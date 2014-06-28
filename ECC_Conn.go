//Use pbkdf2 instead of custom kdf
//Change code to use actual salt/password instead of hardcoded value.
package ECC_Conn

import (
	"github.com/gorilla/websocket"
	"crypto/rand"
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	//"crypto/sha128" //16bit to match the size of a block.
	//Doesn't exist
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"errors"
	"io"
	"encoding/binary"
	"time"
	//"fmt"
)

type ECC_Conn struct {
	auth_key	[]byte
	enc_key		[]byte
	conn		*websocket.Conn
	PacketSize 	int
	BlockSize 	int
	HashBlockSize	int
	PayloadLen	int //(PacketSize-BlockSize*2)-10
			    //IV at begin, HMAC at end,
			    //8byte unique packet counter & 2byte data len
	UsedCounters	[]uint64
	HeaderLen	int
}
//not immune to dropped packets
//hopefully the number range is large enough where it isn't a problem.
func (x *ECC_Conn) header(data []byte,length int) {
	l := make([]byte,2)
	binary.PutUvarint(l,uint64(length))
	copy(data[8:10],l)	//length of data is at beg of chunk

	buf := make([]byte,8)
	found := true
	for found {
		found = false
		rand.Read(data[0:8])
		for i := range x.UsedCounters {
			binary.PutUvarint(buf,uint64(x.UsedCounters[i]))
			if bytes.Equal(data[0:8],buf) {
				found = true
				break
			}
		}
	}
	i,_ := binary.Uvarint(buf[0:8])
	x.UsedCounters = append(x.UsedCounters,i)
}
//Think about not sending key in plain text?
// D x G ->  P;  D x tP -> Q;
//tD x G -> tP; tD x  P -> Q;
func (x *ECC_Conn) Connect(conn *websocket.Conn) {
	//Fix this, poor form.
	x.PacketSize = 1024
	x.BlockSize = aes.BlockSize
	x.HashBlockSize = sha256.BlockSize
	x.HeaderLen = 10
	x.PayloadLen = x.PacketSize-(x.BlockSize+x.HashBlockSize)-x.HeaderLen

	x.auth_key = create_key(conn)
	time.Sleep(2)
	x.enc_key = create_key(conn)
	x.conn = conn
}

//FIX SALT/PASSWORD
func create_key(conn *websocket.Conn) []byte {
	mt := websocket.BinaryMessage
	msg := make([]byte,1000)
	_,err := rand.Read(msg)
	if err != nil {
		panic(err)
	}
	rnd := bytes.NewBuffer(msg)

	c := elliptic.P521()
	D,Px,Py,_ := elliptic.GenerateKey(c,rnd)
	Pmarsh := elliptic.Marshal(c,Px,Py)
	conn.WriteMessage(mt,Pmarsh)

	mt,data,_ := conn.ReadMessage()
	tPx,tPy := elliptic.Unmarshal(c,data)

	Q_x,Q_y := c.ScalarMult(tPx,tPy,D)

	k := elliptic.Marshal(c,Q_x,Q_y)
	salt := make([]byte,64)
	copy(salt,[]byte("Place holder password."))
	return  kdf(k,salt,10000)
}
//2 is hardwired in to describe a Uint16 wrt datalength.
func (x *ECC_Conn) Write(p []byte) (n int, err error) {
	hm := hmac.New(sha256.New,x.auth_key)
	HMACBlock := x.PacketSize - x.BlockSize*2 //why is hmac chksum 16B?
	start := 0
	end := len(p)
	//2 is for size of Uint16 which is prepended to each data
	//stores how many bytes of data are in the block
	if len(p) >= x.PayloadLen{
		end = x.PayloadLen
	} 

	data := make([]byte,x.PacketSize-x.BlockSize)
	for end < len(p) {
		x.header(data,end-start)
		copy(data[x.HeaderLen:],p[start:end])

		cipher := encrypt(x.enc_key,data)
		hm.Write(cipher[:HMACBlock])
		copy(cipher[HMACBlock:],hm.Sum(nil))
		hm.Reset()
		//fmt.Println("Cipher Size:",len(cipher))
		err = x.conn.WriteMessage(websocket.BinaryMessage,cipher)
		if err != nil {
			return start,err
		}
		start = end
		end += x.PayloadLen
	}
	x.header(data,len(p)-start)
	copy(data[x.HeaderLen:],p[start:])

	rem := x.PayloadLen-len(p[start:])
	zeros := make([]byte,rem)
	copy(data[x.HeaderLen+len(p[start:]):],zeros)   //Zeros out rest of the chunk

	cipher := encrypt(x.enc_key,data)
	hm.Write(cipher[:HMACBlock])
	copy(cipher[HMACBlock:],hm.Sum(nil))
	err = x.conn.WriteMessage(websocket.BinaryMessage,cipher)
	if err != nil {
		return start,err
	}
	return len(p),err
}
//Can't assign buffer within the function
//so p needs to have a size of ReadBufferSize or greater
//from websocket upgrader
func (x *ECC_Conn) Read(p []byte) (n int, err error) {
	hm := hmac.New(sha256.New,x.auth_key)
	HMACBlock := x.PacketSize - x.BlockSize*2 //why is hmac chksum 16B?
	_,cipher,err := x.conn.ReadMessage()
	if len(cipher) % x.BlockSize != 0 {
		return 0,errors.New("Incoming cipher is not a multiple of block size.")
	}
	hm.Write(cipher[:HMACBlock])
	if !hmac.Equal(cipher[HMACBlock:],hm.Sum(nil)) {
		return 0,errors.New("Non-Matching HMAC")
	}
	text := decrypt(x.enc_key,cipher[:HMACBlock])
	l,_ := binary.Uvarint(text[8:10])
	copy(p[:l], text[x.HeaderLen:])
	return int(l),err
}
//use pbkdf2 instead.
//Bounds might throw errors, careful.
func kdf(k []byte,salt []byte,c int) []byte {
	pass := make([]byte,len(k)+32)
	copy(pass[:len(k)],k)
	for i := 0; i<c; i++ {
		copy(pass[len(k):],salt)
		temp := sha256.Sum256(pass)
		salt = temp[0:]
	}
	return salt
}
//Variable length CBC with MAC allows for Appending data to the end
//Allows one to extend the message to create a new MAC
//Hence allowing unauthorized data.
//Require text aligned 16 bytes.
//Require key 256-bits, using sha256 for that.
func encrypt(key, text []byte) []byte {
	block,err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	ciphertext := make([]byte, aes.BlockSize + len(text))
	iv := ciphertext[:aes.BlockSize]
	if _,err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	cbc := cipher.NewCBCEncrypter(block, iv)
	//pad text to multiple of 32bytes
	cbc.CryptBlocks(ciphertext[aes.BlockSize:],text)
	return ciphertext
}
func decrypt(key, ciphertext []byte) []byte {
	block,err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	text := make([]byte,len(ciphertext))
	iv := ciphertext[:aes.BlockSize]
//Gives offset so Crypt function index doesn't go out of bounds
	ciphertext = ciphertext[aes.BlockSize:] 
	
	cbc := cipher.NewCBCDecrypter(block,iv)
	cbc.CryptBlocks(text,ciphertext)
	return text
}

package ECC_Conn

import (
	"github.com/gorilla/websocket"
	"crypto/rand"
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"encoding/binary"
//	"fmt"
)

type ECC_Conn struct {
	key	[]byte
	conn	*websocket.Conn
	PacketSize int
	BlockSize int
}
// D x G ->  P;  D x tP -> Q;
//tD x G -> tP; tD x  P -> Q;
func (x *ECC_Conn) Connect(conn *websocket.Conn) {
	//Fix this, poor form.
	x.PacketSize = 1024
	x.BlockSize = aes.BlockSize
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
	x.key = kdf(k,salt,10000)
	x.conn = conn
}
//2 is hardwired in to describe a Uint16 wrt datalength.
func (x *ECC_Conn) Write(p []byte) (n int, err error) {
	start := 0
	end := len(p)
	PayloadLen := x.PacketSize-x.BlockSize-2
	//2 is for size of Uint16 which is prepended to each data
	//stores how many bytes of data are in the block
	if len(p) >= PayloadLen{
		end = PayloadLen
	} 

	data := make([]byte,x.PacketSize-x.BlockSize)
	for end < len(p) {
		l := make([]byte,2)
		binary.PutUvarint(l,uint64(end-start))
		copy(data[0:2],l)	//length of data is at beg of chunk

		copy(data[2:],p[start:end])
		cipher := encrypt(x.key,data)
		//fmt.Println("Cipher Size:",len(cipher))
		err = x.conn.WriteMessage(websocket.BinaryMessage,cipher)
		if err != nil {
			return end,err
		}
		start = end
		end += PayloadLen
	}
	l := make([]byte,2)
	binary.PutUvarint(l,uint64(len(p)-start))
	copy(data[0:2],l)
	copy(data[2:],p[start:])

	rem := PayloadLen-len(p[start:])
	zeros := make([]byte,rem)
	copy(data[2+len(p[start:]):],zeros)   //Zeros out rest of the chunk

	cipher := encrypt(x.key,data)
	err = x.conn.WriteMessage(websocket.BinaryMessage,cipher)
	return len(p),err
}
//Can't assign buffer within the function
//so p needs to have a size of ReadBufferSize or greater
//from websocket upgrader
func (x *ECC_Conn) Read(p []byte) (n int, err error) {
	_,cipher,err := x.conn.ReadMessage()
	if len(cipher) % x.BlockSize != 0 {
		return 0,errors.New("Incoming cipher is not a multiple of block size.")
	}
	text := decrypt(x.key,cipher)
	l,_ := binary.Uvarint(text[0:2])
	copy(p[:l], text[2:])
	return int(l),err
}
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

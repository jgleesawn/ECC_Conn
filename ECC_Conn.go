package ECC_Conn

import (
	"github.com/gorilla/websocket"
	"crypto/rand"
	"bytes"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/aes"
	"crypto/cipher"
	"io"
	"fmt"
)

type ECC_Conn struct {
	key	[]byte
	conn	*websocket.Conn
	BlockSize int
}
// D x G ->  P;  D x tP -> Q;
//tD x G -> tP; tD x  P -> Q;
func (x *ECC_Conn) Connect(conn *websocket.Conn) {
	//Fix this, poor form.
	x.BlockSize = aes.BlockSize
	mt := websocket.BinaryMessage
	msg := make([]byte,1000)
	_,err := rand.Read(msg)
	if err != nil {
		panic(err)
	}
	rnd := bytes.NewBuffer(msg)

	c := elliptic.P224()
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
func (x *ECC_Conn) Write(p []byte) (n int, err error) {
	diff := x.BlockSize-(len(p)%x.BlockSize)
	var data []byte
	if diff != 0 {
		data = make([]byte,len(p)+diff)
		copy(data[:len(p)],p)
	} else {
		data = p
	}
	cipher := encrypt(x.key,data)
	err = x.conn.WriteMessage(websocket.BinaryMessage,cipher)
	return len(p),err
}
//Can't assign buffer within the function
//so p needs to have a size of ReadBufferSize or greater
//from websocket upgrader
func (x *ECC_Conn) Read(p []byte) (n int, err error) {
	//fmt.Println(len(p))
	_,cipher,err := x.conn.ReadMessage()
	//p = make([]byte,len(cipher))
	//fmt.Println(len(p))
	copy(p[:len(cipher)], decrypt(x.key,cipher))
	copy(p[:len(cipher)-aes.BlockSize], p[aes.BlockSize:])
	fmt.Println(string(p))
	return len(p),err
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
	text := make([]byte,len(ciphertext)-aes.BlockSize)
	prev := len(ciphertext)-aes.BlockSize*2
	start := len(ciphertext)-aes.BlockSize
//	end := len(ciphertext)
//Gives offset so Crypt function index doesn't go out of bounds
	ciphertext = ciphertext[aes.BlockSize:] 
	iv := ciphertext[prev:start]
	
	cbc := cipher.NewCBCDecrypter(block,iv)
	cbc.CryptBlocks(text,ciphertext)
	return text
}

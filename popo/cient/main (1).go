package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
)

const (
	key = "my32digitkey12345678901234567890"
)

func main() {
	conn, err := net.Dial("tcp", "localhost:8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	go readMessages(conn)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter your name: ")
	name, _ := reader.ReadString('\n')
	fmt.Fprint(conn, encrypt(name))

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err.Error())
			continue
		}
		enc := encrypt(message)
		_, err = fmt.Fprint(conn, enc)
		if err != nil {
			fmt.Println(err.Error())
		}
	}
}

func readMessages(conn net.Conn) {
	reader := bufio.NewReader(conn)

	for {
		message, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("Disconnected from server")
			os.Exit(0)
		}

		fmt.Print(decrypt(message))
	}
}

func decrypt(secure string) (decoded string) {
	secure = secure[:len(secure)-1]
	// Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)
	// IF DecodeString failed, exit:
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher([]byte(key))
	// IF NewCipher failed, exit:
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	// Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)
	s := string(cipherText)
	return s
}

func encrypt(message string) (encoded string) {
	// Create byte array from the input string
	plainText := []byte(message)

	// Create a new AES cipher using the key
	block, err := aes.NewCipher([]byte(key))
	// IF NewCipher failed, exit:
	if err != nil {
		return
	}

	// Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	// iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	// Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	// Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText) + "\n"
}

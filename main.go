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
	"log"
	"net"
	"strings"
)

/*
1. ENV
2. Architecture
3. UNderstand

*/

type client struct {
	conn net.Conn
	name string
}

var clients []client

const (
	key = "my32digitkey12345678901234567890"
)

func main() {
	// message := "Diyar"
	// encrypted := encrypt(message)
	// fmt.Println(encrypted)
	listener, err := net.Listen("tcp", ":8080")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	name, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		log.Println("error")
	}
	name = strings.TrimSpace(decrypt(name))
	newClient := client{conn: conn, name: name}
	clients = append(clients, newClient)

	fmt.Println(name, "joined the chat")
	// broadcast to clients
	broadcast(encrypt(name+" joined the chat"), &newClient)

	for {
		message, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil {
			break
		}
		message = strings.TrimSpace(decrypt(message))
		fmt.Println(message)
		broadcast(encrypt(message), &newClient)
		fmt.Println(encrypt(message))
	}

	removeClient(&newClient)
	conn.Close()
}

func print(s string) {
	for _, x := range s {
		fmt.Println(x)
	}
}

func broadcast(message string, sender *client) {
	for _, c := range clients {
		if c.conn == sender.conn {
			fmt.Println(c.name, "not send message to client")
			continue
		}

		_, err := fmt.Fprint(c.conn, message)
		if err != nil {
			fmt.Println(err.Error())
		}
		fmt.Println("i have send message to", c.name)
	}
}

func removeClient(clientToRemove *client) {
	for i, c := range clients {
		if c.conn == clientToRemove.conn {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
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

func decrypt(secure string) (decoded string) {
	// Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)
	// IF DecodeString failed, exit:
	if err != nil {
		return
	}

	// Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher([]byte(key))
	// IF NewCipher failed, exit:
	if err != nil {
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
	return s[:len(s)-1]
}

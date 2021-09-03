package aesgsm3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func AES256GSMEncrypt(secretKey, secondKey, plaintext []byte) ([]byte, error) {

	if len(secretKey) != 32 {
		return nil, fmt.Errorf("secret key is not for AES-256: total %d bits", 8*len(secretKey))
	}

	// prepare AES-256-GSM cipher
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err

	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// make random nonce
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// encrypt plaintext with second key
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, secondKey)
	fmt.Println("--\nencryption start")
	fmt.Printf("nonce to use: %x\n", nonce)
	fmt.Printf("ciphertext: %x\n", ciphertext)
	return ciphertext, nil
}

func AES256GSMDecrypt(secretKey []byte, ciphertext []byte, secondKey []byte) ([]byte, error) {

	if len(secretKey) != 32 {
		return nil, fmt.Errorf("secret key is not for AES-256: total %d bits", 8*len(secretKey))
	}

	// prepare AES-256-GSM cipher
	block, err := aes.NewCipher(secretKey)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesgcm.NonceSize()
	nonce, pureCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// decrypt ciphertext with second key
	plaintext, err := aesgcm.Open(nil, nonce, pureCiphertext, secondKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("--\ndecryption start")
	fmt.Printf("ciphertext: %x\n", ciphertext)
	fmt.Printf("nonce: %x\n", nonce)
	fmt.Printf("plaintext: %x\n", plaintext)
	return plaintext, nil
}

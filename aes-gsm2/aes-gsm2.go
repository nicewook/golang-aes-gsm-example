package aesgsm2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

func AES256GSMEncrypt(secretKey []byte, plaintext []byte) ([]byte, error) {

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

	// encrypt plaintext
	ciphertext := aesgcm.Seal(nonce, nonce, plaintext, nil)
	fmt.Println("--\nencryption start")
	fmt.Printf("nonce to use: %x\n", nonce)
	fmt.Printf("ciphertext: %x\n", ciphertext)
	return ciphertext, nil // nonce is included in ciphertext. no need to return
}

func AES256GSMDecrypt(secretKey []byte, ciphertext []byte) ([]byte, error) {

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

	// decrypt ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, pureCiphertext, nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("--\ndecryption start")
	fmt.Printf("ciphertext: %x\n", ciphertext)
	fmt.Printf("nonce: %x\n", nonce)
	fmt.Printf("plaintext: %x\n", plaintext)
	return plaintext, nil
}

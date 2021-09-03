package aesgsm3

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestAES256GSM3(t *testing.T) {

	var (
		passphraseForSecretKey = "this is my secret key passphrase"
		plaintext              = "this should be encrypted"
		secondKey              = "this will be in the code which will not exposed outside"
	)

	// gen 32 byte secret key
	hash := sha256.New()
	_, err := hash.Write([]byte(passphraseForSecretKey))
	if err != nil {
		t.Error(err)
	}
	secretKey := hash.Sum(nil)
	fmt.Printf("secret key generated: %x\n", secretKey)

	// encrypt
	ciphertext, err := AES256GSMEncrypt(secretKey, []byte(secondKey), []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	// decrypt
	plaintextBytes, err := AES256GSMDecrypt(secretKey, ciphertext, []byte(secondKey))
	if err != nil {
		t.Error(err)
	}

	if plaintext != string(plaintextBytes) {
		t.Errorf("plaintext %s is differ from decrypted cipertext %s", plaintext, string(plaintextBytes))
	}
}

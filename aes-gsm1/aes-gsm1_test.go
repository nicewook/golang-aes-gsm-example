package aesgsm1

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestAES256GSM(t *testing.T) {

	var (
		passphraseForSecretKey = "this is my secret key passphrase"
		plaintext              = "this should be encrypted"
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
	ciphertext, nonce, err := AES256GSMEncrypt(secretKey, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	// decrypt
	plaintextBytes, err := AES256GSMDecrypt(secretKey, ciphertext, nonce)
	if err != nil {
		t.Error(err)
	}

	if plaintext != string(plaintextBytes) {
		t.Errorf("plaintext %s is differ from decrypted cipertext %s", plaintext, string(plaintextBytes))
	}
}

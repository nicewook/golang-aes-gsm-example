package aesgsm2

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func TestAES256GSM2(t *testing.T) {

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

	// encrypt - no need to get return nonce
	ciphertext, err := AES256GSMEncrypt(secretKey, []byte(plaintext))
	if err != nil {
		t.Error(err)
	}

	// decrypt - no need to send nonce parameter
	plaintextBytes, err := AES256GSMDecrypt(secretKey, ciphertext)
	if err != nil {
		t.Error(err)
	}

	if plaintext != string(plaintextBytes) {
		t.Errorf("plaintext %s is differ from decrypted ciphertext %s", plaintext, string(plaintextBytes))
	}
}

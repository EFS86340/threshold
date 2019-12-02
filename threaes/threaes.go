// Package threaes a simple wrapper of AES-128-GCM
package threaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"
	"log"
)

// Enc encrypt a plaintext using key
func Enc(plaintext []byte, key []byte) (ciphertext []byte) {
	// check key size
	if len(key) != 16 {
		// 128 = 16*8
		log.Fatal(aes.KeySizeError(len(key)).Error())
	}
	// cipher
	ci, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(ci)
	// err handling

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	ciphertext = gcm.Seal(nonce, nonce, plaintext, nil)
	return
}

// Dec decrypt a ciphertext using key
func Dec(ciphertext []byte, key []byte) (plaintext []byte) {
	//
	ci, err := aes.NewCipher(key)
	// err check
	gcm, err := cipher.NewGCM(ci)
	// err check

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		log.Fatal(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err = gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return
}

package cipherUtil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"io"
)

type AesGcm struct {
	Key  [32]byte
	Aead cipher.AEAD
}

func (ag *AesGcm) Init(key string) error {
	ag.Key = sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(ag.Key[:])
	if err != nil {
		return err
	}
	ag.Aead, err = cipher.NewGCM(block)
	if err != nil {
		return err
	}
	return nil
}

func (ag *AesGcm) Encrypt(data []byte) ([]byte, error) {
	nonce := make([]byte, ag.Aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	cipherData := ag.Aead.Seal(nonce, nonce, data, nil)
	return cipherData, nil
}

func (ag *AesGcm) Decrypt(data []byte) ([]byte, error) {
	nonceSize := ag.Aead.NonceSize()
	nonce, cipherData := data[:nonceSize], data[nonceSize:]
	plainData, err := ag.Aead.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, err
	}
	return plainData, nil
}

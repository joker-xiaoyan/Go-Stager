package AES

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
)

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpadding(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[length-1])
	if padding > length {
		return nil, errors.New("invalid padding")
	}
	return data[:length-padding], nil
}

// Encrypt function encrypts the input data using AES-128-CBC with a fixed key and IV.
func Encrypt(data string) string {
	// Fixed AES key and IV, should not be used in production like this
	key := []byte("1234567890123456") // 16 bytes for AES-128

	block, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	// Add padding
	plaintext := pkcs7Padding([]byte(data), aes.BlockSize)

	iv := []byte("1234567890123456") // 16 bytes IV for CBC mode

	// Create a CBC encrypter
	mode := cipher.NewCBCEncrypter(block, iv)

	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Base64 encode the result to get a string representation
	return base64.StdEncoding.EncodeToString(ciphertext)
}

// Decrypt function decrypts the input data using AES-128-CBC with a fixed key and IV.
func Decrypt(data string) (string, error) {
	// Fixed AES key and IV, should not be used in production like this
	key := []byte("1234567890123456") // 16 bytes for AES-128

	ciphertext, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	iv := []byte("1234567890123456") // 16 bytes IV for CBC mode

	// Create a CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	// Remove padding
	plaintext, err = pkcs7Unpadding(plaintext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

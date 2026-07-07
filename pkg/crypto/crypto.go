package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"runtime"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = 32
	NonceSize = chacha20poly1305.NonceSizeX // 24
)

func Decrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key length: got %d, want %d", len(key), KeySize)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce length: got %d, want %d", len(nonce), NonceSize)
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}

func UnwrapKey(wrapped, nonce, wrappingKey []byte) ([]byte, error) {
	return Decrypt(wrapped, wrappingKey, nonce)
}

func SHA256Sum(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

func DecodeBase64URL(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

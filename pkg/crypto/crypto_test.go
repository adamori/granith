package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The fixture comes from libsodium-wrappers-sumo 0.8.4, the browser client's
// independent implementation, to catch cross-language wire-format regressions.
func TestDecryptLibsodiumFixture(t *testing.T) {
	var fixture struct {
		Key        string `json:"key"`
		Nonce      string `json:"nonce"`
		Plaintext  string `json:"plaintext"`
		Ciphertext string `json:"ciphertext"`
		WrappedKey string `json:"wrappedKey"`
		InnerKey   string `json:"innerKey"`
	}
	data, err := os.ReadFile("testdata/libsodium.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	decode := func(value string) []byte {
		t.Helper()
		decoded, err := hex.DecodeString(value)
		if err != nil {
			t.Fatal(err)
		}
		return decoded
	}
	key, nonce, ciphertext := decode(fixture.Key), decode(fixture.Nonce), decode(fixture.Ciphertext)
	plaintext, err := Decrypt(ciphertext, key, nonce)
	if err != nil || string(plaintext) != fixture.Plaintext {
		t.Fatalf("decrypt: plaintext=%q, err=%v", plaintext, err)
	}
	unwrapped, err := UnwrapKey(decode(fixture.WrappedKey), nonce, key)
	if err != nil || !bytes.Equal(unwrapped, decode(fixture.InnerKey)) {
		t.Fatalf("unwrap: key=%x, err=%v", unwrapped, err)
	}
	for _, tc := range []struct {
		name  string
		ct    []byte
		key   []byte
		nonce []byte
	}{
		{"short key", ciphertext, key[:31], nonce},
		{"long key", ciphertext, append(bytes.Clone(key), 0), nonce},
		{"short nonce", ciphertext, key, nonce[:23]},
		{"long nonce", ciphertext, key, append(bytes.Clone(nonce), 0)},
		{"truncated ciphertext", ciphertext[:8], key, nonce},
		{"wrong key", ciphertext, bytes.Repeat([]byte{0xff}, KeySize), nonce},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(tc.ct, tc.key, tc.nonce); err == nil {
				t.Fatal("invalid input was accepted")
			}
		})
	}
	t.Run("tampered ciphertext", func(t *testing.T) {
		ct := bytes.Clone(ciphertext)
		ct[0] ^= 1
		if _, err := Decrypt(ct, key, nonce); err == nil {
			t.Fatal("tampered ciphertext was accepted")
		}
	})
}

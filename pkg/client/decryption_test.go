package client

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adamori/granith/pkg/bundle"
	"github.com/adamori/granith/pkg/token"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestFetchBundleDecryptsWithLocalKey(t *testing.T) {
	parsed, err := token.Parse(testRawToken)
	if err != nil {
		t.Fatal(err)
	}
	defer parsed.Zero()

	encrypt := func(plaintext, key []byte) (string, string) {
		t.Helper()
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			t.Fatal(err)
		}
		nonce := make([]byte, aead.NonceSize())
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		return base64.StdEncoding.EncodeToString(aead.Seal(nil, nonce, plaintext, nil)), base64.StdEncoding.EncodeToString(nonce)
	}

	pdk := bytes.Repeat([]byte{2}, 32)
	itemKey := bytes.Repeat([]byte{3}, 32)
	wrappedPDK, wrapNonce := encrypt(pdk, parsed.TokenKey)
	projectName, projectNonce := encrypt([]byte("test-project"), pdk)
	wrappedItemKey, wikNonce := encrypt(itemKey, pdk)
	name, nameNonce := encrypt([]byte("TEST_SECRET"), itemKey)
	value, valueNonce := encrypt([]byte("local-decryption-only"), itemKey)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAuthToken {
			t.Errorf("unexpected authorization: %q", got)
		}
		json.NewEncoder(w).Encode(map[string]any{
			"project":     map[string]string{"id": "project", "name_ct": projectName, "name_nonce": projectNonce},
			"wrapped_pdk": wrappedPDK,
			"wrap_nonce":  wrapNonce,
			"secrets": []map[string]any{{
				"id": "secret", "version": 1,
				"wrapped_item_key": wrappedItemKey, "wik_nonce": wikNonce,
				"name_ct": name, "name_nonce": nameNonce,
				"value_ct": value, "value_nonce": valueNonce,
			}},
		})
	}))
	defer srv.Close()

	c := New(srv.URL, testRawToken)
	defer c.Close()
	resp, err := c.FetchBundle()
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := bundle.Decrypt(resp.Body, parsed.TokenKey)
	if err != nil {
		t.Fatal(err)
	}
	if decrypted.ProjectName != "test-project" || len(decrypted.Secrets) != 1 {
		t.Fatalf("unexpected decrypted bundle: %+v", decrypted)
	}
	if decrypted.Secrets[0].Name != "TEST_SECRET" || decrypted.Secrets[0].Value != "local-decryption-only" {
		t.Fatalf("unexpected secret: %+v", decrypted.Secrets[0])
	}
}

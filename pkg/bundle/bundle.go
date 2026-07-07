package bundle

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/adamori/granith/pkg/crypto"
)

type rawBundle struct {
	Project struct {
		ID        string `json:"id"`
		NameCT    string `json:"name_ct"`
		NameNonce string `json:"name_nonce"`
	} `json:"project"`
	WrappedPDK string `json:"wrapped_pdk"`
	WrapNonce  string `json:"wrap_nonce"`
	Secrets    []struct {
		ID             string `json:"id"`
		WrappedItemKey string `json:"wrapped_item_key"`
		WIKNonce       string `json:"wik_nonce"`
		NameCT         string `json:"name_ct"`
		NameNonce      string `json:"name_nonce"`
		ValueCT        string `json:"value_ct"`
		ValueNonce     string `json:"value_nonce"`
		Version        int    `json:"version"`
	} `json:"secrets"`
}

type Secret struct {
	ID      string
	Name    string
	Value   string
	Version int
}

type Bundle struct {
	ProjectID   string
	ProjectName string
	Secrets     []Secret
}

func Decrypt(data []byte, tokenKey []byte) (*Bundle, error) {
	var raw rawBundle
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}

	wrappedPDK, err := b64(raw.WrappedPDK)
	if err != nil {
		return nil, fmt.Errorf("decode wrapped_pdk: %w", err)
	}
	wrapNonce, err := b64(raw.WrapNonce)
	if err != nil {
		return nil, fmt.Errorf("decode wrap_nonce: %w", err)
	}

	pdk, err := crypto.UnwrapKey(wrappedPDK, wrapNonce, tokenKey)
	if err != nil {
		return nil, fmt.Errorf("unwrap PDK: %w", err)
	}
	defer crypto.Zero(pdk)

	projectName, err := decryptField(raw.Project.NameCT, raw.Project.NameNonce, pdk)
	if err != nil {
		return nil, fmt.Errorf("decrypt project name: %w", err)
	}

	secrets := make([]Secret, 0, len(raw.Secrets))
	for i, s := range raw.Secrets {
		wik, err := b64(s.WrappedItemKey)
		if err != nil {
			return nil, fmt.Errorf("secret[%d] decode wrapped_item_key: %w", i, err)
		}
		wikNonce, err := b64(s.WIKNonce)
		if err != nil {
			return nil, fmt.Errorf("secret[%d] decode wik_nonce: %w", i, err)
		}

		itemKey, err := crypto.UnwrapKey(wik, wikNonce, pdk)
		if err != nil {
			return nil, fmt.Errorf("secret[%d] unwrap item_key: %w", i, err)
		}

		name, err := decryptField(s.NameCT, s.NameNonce, itemKey)
		if err != nil {
			crypto.Zero(itemKey)
			return nil, fmt.Errorf("secret[%d] decrypt name: %w", i, err)
		}

		value, err := decryptField(s.ValueCT, s.ValueNonce, itemKey)
		if err != nil {
			crypto.Zero(itemKey)
			return nil, fmt.Errorf("secret[%d] decrypt value: %w", i, err)
		}

		crypto.Zero(itemKey)

		secrets = append(secrets, Secret{
			ID:      s.ID,
			Name:    name,
			Value:   value,
			Version: s.Version,
		})
	}

	return &Bundle{
		ProjectID:   raw.Project.ID,
		ProjectName: projectName,
		Secrets:     secrets,
	}, nil
}

func decryptField(ctB64, nonceB64 string, key []byte) (string, error) {
	ct, err := b64(ctB64)
	if err != nil {
		return "", fmt.Errorf("decode ciphertext: %w", err)
	}
	nonce, err := b64(nonceB64)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	plaintext, err := crypto.Decrypt(ct, key, nonce)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func b64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

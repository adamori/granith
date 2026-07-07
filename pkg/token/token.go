package token

import (
	"fmt"
	"strings"

	"github.com/adamori/granith/pkg/crypto"
)

const Prefix = "grnth_"

type Token struct {
	LookupID []byte
	TokenKey []byte
}

func Parse(raw string) (*Token, error) {
	if !strings.HasPrefix(raw, Prefix) {
		return nil, fmt.Errorf("token must start with %q", Prefix)
	}
	body := raw[len(Prefix):]
	parts := strings.SplitN(body, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("token must contain exactly one dot separator")
	}
	lookupID, err := crypto.DecodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("decode lookup_id: %w", err)
	}
	tokenKey, err := crypto.DecodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("decode token_key: %w", err)
	}
	if len(lookupID) != 32 {
		return nil, fmt.Errorf("lookup_id must be 32 bytes, got %d", len(lookupID))
	}
	if len(tokenKey) != 32 {
		return nil, fmt.Errorf("token_key must be 32 bytes, got %d", len(tokenKey))
	}
	return &Token{LookupID: lookupID, TokenKey: tokenKey}, nil
}

func (t *Token) Zero() {
	crypto.Zero(t.TokenKey)
	crypto.Zero(t.LookupID)
}

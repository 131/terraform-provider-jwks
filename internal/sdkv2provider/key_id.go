package sdkv2provider

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"fmt"
	"strings"
)

func calculateLibtrustKeyID(key interface{}) (string, error) {
	if private, ok := key.(crypto.Signer); ok {
		key = private.Public()
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", fmt.Errorf("encoding public key for libtrust kid: %w", err)
	}
	digest := sha256.Sum256(der)
	encoded := base32.StdEncoding.EncodeToString(digest[:30])
	groups := make([]string, 0, len(encoded)/4)
	for i := 0; i < len(encoded); i += 4 {
		groups = append(groups, encoded[i:i+4])
	}
	return strings.Join(groups, ":"), nil
}

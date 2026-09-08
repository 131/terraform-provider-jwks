package sdkv2provider

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

func dataSourceJwksFromCertificate() *schema.Resource {
	return &schema.Resource{
		ReadContext: dataSourceJwksFromCertificateRead,
		Schema:      dataSourceJwksFromCertificateSchema(),
		Description: `Calculates a JSON Web Key Set from a given certificate.`,
	}
}

func dataSourceJwksFromCertificateSchema() map[string]*schema.Schema {
	return map[string]*schema.Schema{
		"pem": {
			Type:     schema.TypeString,
			Required: true,
			Description: `Requires a PEM-encoded single certificate or correctly ordered certificate chain that starts with an end-entity certificate.
							Each certificate in the chain is the certificate of the CA that issued the previous certificate.`,
		},
		"kid": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to override the kid field of the JWK`,
		},
		"kid_format": {
			Type:         schema.TypeString,
			Optional:     true,
			Default:      "certificate",
			ValidateFunc: validation.StringInSlice([]string{"certificate", "libtrust"}, false),
			Description:  `Format of the generated kid: certificate (default) uses the base64url-encoded SHA-256 certificate fingerprint; libtrust uses the Docker/libtrust public-key ID, compatible with GitLab registry tokens (SHA-256 of DER SubjectPublicKeyInfo, first 30 bytes, uppercase base32 in colon-separated groups of four). An explicit kid takes precedence.`,
		},
		"use": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to populate the use field of the JWK`,
		},
		"alg": {
			Type:        schema.TypeString,
			Optional:    true,
			Description: `Used to populate the alg field of the JWK`,
		},
		"jwks": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: `JSON Web Key Set containing the public JWK in a keys array.`,
		},
		"jwk": {
			Type:        schema.TypeString,
			Computed:    true,
			Description: `Public JSON Web Key with only public key primitives and configured alg, kid and use metadata. Certificate metadata is omitted.`,
		},
	}
}

func dataSourceJwksFromCertificateRead(_ context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	certs, err := decodePem(d.Get("pem").(string))
	if err != nil {
		return diag.FromErr(err)
	}
	certificates, err := parseChain(certs.Certificate)
	if err != nil {
		return diag.FromErr(err)
	}

	leaf := certificates[0]

	var kid string
	if k, ok := d.GetOk("kid"); ok {
		kid = k.(string)
	} else {
		kid, err = calculateCertificateKeyID(leaf, d.Get("kid_format").(string))
		if err != nil {
			return diag.FromErr(err)
		}
	}

	var use string
	if u, ok := d.GetOk("use"); ok {
		use = u.(string)
	}

	var alg string
	if u, ok := d.GetOk("alg"); ok {
		alg = u.(string)
	}

	key, err := calculateKey(leaf, kid, use, alg)
	if err != nil {
		return diag.FromErr(err)
	}

	tb, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(hex.EncodeToString(tb))
	return setPublicKeyOutputs(d, key)
}

func parseChain(chain [][]byte) ([]*x509.Certificate, error) {
	var parsedCertificates []*x509.Certificate
	var prevCert *x509.Certificate
	var certPool = x509.NewCertPool()

	for _, cert := range chain {
		x509Cert, err := x509.ParseCertificate(cert)

		if err != nil {
			return nil, err
		}

		if prevCert != nil {
			if err := prevCert.CheckSignatureFrom(x509Cert); err != nil {
				return nil, errors.New("unable to validate the certificate signature chain")
			}
		}
		parsedCertificates = append(parsedCertificates, x509Cert)
		certPool.AddCert(x509Cert)
		prevCert = x509Cert
	}

	if _, err := prevCert.Verify(x509.VerifyOptions{
		Roots: certPool,
	}); err != nil {
		return nil, err
	}

	return parsedCertificates, nil
}

func calculateCertificateThumbprint(x509Cert *x509.Certificate) string {
	hash := sha256.New()
	hash.Write(x509Cert.Raw)
	return base64.URLEncoding.EncodeToString(hash.Sum(nil))
}

func calculateCertificateKeyID(certificate *x509.Certificate, format string) (string, error) {
	switch format {
	case "certificate":
		return calculateCertificateThumbprint(certificate), nil
	case "libtrust":
		return calculateLibtrustKeyID(certificate.PublicKey)
	default:
		return "", fmt.Errorf("unsupported kid_format %q", format)
	}
}

func calculateKey(x509Cert *x509.Certificate, kid, use, alg string) (jwk.Key, error) {
	key, err := jwk.Import[jwk.Key](x509Cert.PublicKey)
	if err != nil {
		return nil, err
	}

	if err = key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}

	if use != "" {
		if err = key.Set(jwk.KeyUsageKey, use); err != nil {
			return nil, err
		}
	}

	if alg != "" {
		if err = key.Set(jwk.AlgorithmKey, alg); err != nil {
			return nil, err
		}
	}

	return key, nil
}

func decodePem(certInput string) (*tls.Certificate, error) {
	cert := &tls.Certificate{}
	pemData := []byte(strings.TrimSpace(certInput))

	for len(pemData) > 0 {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			return nil, fmt.Errorf("unable to parse pem")
		}

		if block.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, block.Bytes)
		} else {
			return nil, fmt.Errorf("parsed pem is not of correct type, expected: CERTIFICATE, got: %s", block.Type)
		}
	}
	return cert, nil
}

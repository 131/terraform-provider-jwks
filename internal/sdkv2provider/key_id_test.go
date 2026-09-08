package sdkv2provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestKeyIDPublicAndPrivate(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, pemType string
		privateDER    []byte
		public        interface{}
	}{
		{"RSA", "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaKey), &rsaKey.PublicKey},
		{"EC", "EC PRIVATE KEY", ecDER, &ecKey.PublicKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			publicDER, err := x509.MarshalPKIXPublicKey(tc.public)
			if err != nil {
				t.Fatal(err)
			}
			want, err := calculateLibtrustKeyID(tc.public)
			if err != nil {
				t.Fatal(err)
			}
			inputs := []string{
				string(pem.EncodeToMemory(&pem.Block{Type: tc.pemType, Bytes: tc.privateDER})),
				base64.StdEncoding.EncodeToString(tc.privateDER),
				string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
				base64.StdEncoding.EncodeToString(publicDER),
			}
			for _, input := range inputs {
				for _, mode := range []string{"default", "none", "libtrust", "override"} {
					values := map[string]interface{}{"key": input}
					switch mode {
					case "none", "libtrust":
						values["kid_format"] = mode
					case "override":
						values["kid_format"] = "libtrust"
						values["kid"] = "manual"
					}
					d := schema.TestResourceDataRaw(t, dataSourceJwksFromKeySchema(), values)
					if diags := dataSourceJwksFromKeyRead(context.Background(), d, nil); diags.HasError() {
						t.Fatal(diags)
					}
					var key map[string]interface{}
					if err := json.Unmarshal([]byte(d.Get("jwks").(string)), &key); err != nil {
						t.Fatal(err)
					}
					var expected interface{}
					if mode == "libtrust" {
						expected = want
					}
					if mode == "override" {
						expected = "manual"
					}
					if key["kid"] != expected {
						t.Fatalf("%s: kid = %v, want %v", mode, key["kid"], expected)
					}
				}
			}
		})
	}
	if _, err := calculateLibtrustKeyID(struct{}{}); err == nil {
		t.Fatal("unsupported key accepted")
	}
}

func TestAccKeyIDFormats(t *testing.T) {
	block, _ := pem.Decode([]byte(SingleCertificatePem))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	config := func(format string) string {
		return fmt.Sprintf("data \"jwks_from_key\" \"test\" {\nkey = %q\nkid_format = %q\n}", base64.StdEncoding.EncodeToString(der), format)
	}
	check := resource.TestCheckResourceAttrWith("data.jwks_from_key.test", "jwks", func(value string) error {
		var key map[string]interface{}
		if err := json.Unmarshal([]byte(value), &key); err != nil {
			return err
		}
		if key["kid"] != libtrustFixtureKid {
			return fmt.Errorf("kid = %v, want %s", key["kid"], libtrustFixtureKid)
		}
		return nil
	})
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{Config: config("libtrust"), Check: check},
			{Config: config("typo"), ExpectError: regexp.MustCompile("expected kid_format to be one of")},
			{Config: config("libtrust"), Check: check},
		},
	})
}

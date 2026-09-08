package sdkv2provider

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Independently calculated with OpenSSL SubjectPublicKeyInfo DER, SHA-256
// truncated to 30 bytes, and Python's base64.b32encode.
const libtrustFixtureKid = "VCJA:LVJ3:DGBD:2346:4CEY:4ADY:GSZN:IVYG:4XEY:Z2OA:DUYU:425W"

func TestAccCertificateKeyIDFormats(t *testing.T) {
	config := func(attributes string) string {
		return fmt.Sprintf("data \"jwks_from_certificate\" \"test\" {\n pem = %q\n%s\n}", SingleCertificatePem, attributes)
	}
	checkKid := func(want string) resource.TestCheckFunc {
		return resource.TestCheckResourceAttrWith("data.jwks_from_certificate.test", "jwk", func(value string) error {
			var key map[string]interface{}
			if err := json.Unmarshal([]byte(value), &key); err != nil {
				return err
			}
			if key["kid"] != want {
				return fmt.Errorf("kid = %v, want %q", key["kid"], want)
			}
			return nil
		})
	}
	resource.Test(t, resource.TestCase{
		ProtoV5ProviderFactories: testAccProviders,
		Steps: []resource.TestStep{
			{Config: config(`kid_format = "libtrust"`), Check: checkKid(libtrustFixtureKid)},
			{Config: config("kid_format = \"libtrust\"\nkid = \"manual\""), Check: checkKid("manual")},
			{Config: config(""), Check: checkKid("IZbkJobc7ZEyBG8Gc98ImVqsyIrycTgBgi0NCRNIxxc=")},
			{Config: config(`kid_format = "typo"`), ExpectError: regexp.MustCompile("expected kid_format to be one of")},
			{Config: config(`kid_format = "libtrust"`), Check: checkKid(libtrustFixtureKid)},
		},
	})
}

func TestCertificateKeyID(t *testing.T) {
	block, _ := pem.Decode([]byte(SingleCertificatePem))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ format, want string }{
		{"certificate", "IZbkJobc7ZEyBG8Gc98ImVqsyIrycTgBgi0NCRNIxxc="},
		{"libtrust", libtrustFixtureKid},
	} {
		t.Run(tc.format, func(t *testing.T) {
			got, err := calculateCertificateKeyID(cert, tc.format)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	// Certificate renewal must not change a public-key-based ID.
	cert.Raw = []byte("renewed certificate with the same public key")
	if got, err := calculateCertificateKeyID(cert, "libtrust"); err != nil || got != libtrustFixtureKid {
		t.Fatalf("renewal changed kid: %q, %v", got, err)
	}
	if _, err := calculateCertificateKeyID(cert, "typo"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, errs := dataSourceJwksFromCertificateSchema()["kid_format"].ValidateFunc("typo", "kid_format"); len(errs) == 0 {
		t.Fatal("schema accepted unknown format")
	}
}

func TestCertificateKeyIDRead(t *testing.T) {
	// Generated certificates avoid tying datasource tests to fixture expiry.
	pemCert, cert := generateEcCert(t)
	for _, tc := range []struct {
		name   string
		values map[string]interface{}
		want   string
	}{
		{"default", map[string]interface{}{}, calculateCertificateThumbprint(cert)},
		{"libtrust", map[string]interface{}{"kid_format": "libtrust"}, ""},
		{"override", map[string]interface{}{"kid_format": "libtrust", "kid": "explicit"}, "explicit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.values["pem"] = pemCert
			d := schema.TestResourceDataRaw(t, dataSourceJwksFromCertificateSchema(), tc.values)
			if diags := dataSourceJwksFromCertificateRead(context.Background(), d, nil); diags.HasError() {
				t.Fatal(diags)
			}
			var key map[string]interface{}
			if err := json.Unmarshal([]byte(d.Get("jwk").(string)), &key); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				tc.want, _ = calculateCertificateKeyID(cert, "libtrust")
			}
			if key["kid"] != tc.want {
				t.Fatalf("kid = %v, want %q", key["kid"], tc.want)
			}
			if _, ok := key["x5t#S256"]; ok {
				t.Fatal("certificate metadata leaked")
			}
			assertPublicOutputs(t, d)
		})
	}
}

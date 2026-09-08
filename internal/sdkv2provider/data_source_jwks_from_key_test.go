package sdkv2provider

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"filippo.io/mldsa"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

const (
	PrivateKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAgUElV5mwqkloIrM8ZNZ72gSCcnSJt7+/Usa5G+D15YQUAdf9
c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZYVg5ZErNCa/hzn+x10xzcepeS3KPV
Xcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2Gle3hTxjlWFb3F5qLgR+4Mf4ruhER
1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr+sTSxfh7
r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV7Gwl/5gHXonCUKURaV++dBNLrHIZ
pqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+7QIDAQABAoIBAC1rK+kFW3vrAYm3
+8/fQnQQw5nec4o6+crng6JVQXLeH32qXShNf8kLLG/Jj0vaYcTPPDZw9JCKkTMQ
0mKj9XR/5DLbBMsV6eNXXuvJJ3x4iKW5eD9WkLD4FKlNarBRyO7j8sfPTqXW7uat
NxWdFH7YsSRvNh/9pyQHLWA5OituidMrYbc3EUx8B1GPNyJ9W8Q8znNYLfwYOjU4
Wv1SLE6qGQQH9Q0WzA2WUf8jklCYyMYTIywAjGb8kbAJlKhmj2t2Igjmqtwt1PYc
pGlqbtQBDUiWXt5S4YX/1maIQ/49yeNUajjpbJiH3DbhJbHwFTzP3pZ9P9GHOzlG
kYR+wSECgYEAw/Xida8kSv8n86V3qSY/I+fYQ5V+jDtXIE+JhRnS8xzbOzz3v0WS
Oo5H+o4nJx5eL3Ghb3Gcm0Jn46dHrxinHbm+3RjXv/X6tlbxIYjRSQfHOTSMCTvd
qcliF5vC6RCLXuc7R+IWR1Ky6eDEZGtrvt3DyeYABsp9fRUFR/6NluUCgYEAqNsw
1aSl7WJa27F0DoJdlU9LWerpXcazlJcIdOz/S9QDmSK3RDQTdqfTxRmrxiYI9LEs
mkOkvzlnnOBMpnZ3ZOU5qIRfprecRIi37KDAOHWGnlC0EWGgl46YLb7/jXiWf0AG
Y+DfJJNd9i6TbIDWu8254/erAS6bKMhW/3q7f2kCgYAZ7Id/BiKJAWRpqTRBXlvw
BhXoKvjI2HjYP21z/EyZ+PFPzur/lNaZhIUlMnUfibbwE9pFggQzzf8scM7c7Sf+
mLoVSdoQ/Rujz7CqvQzi2nKSsM7t0curUIb3lJWee5/UeEaxZcmIufoNUrzohAWH
BJOIPDM4ssUTLRq7wYM9uQKBgHCBau5OP8gE6mjKuXsZXWUoahpFLKwwwmJUp2vQ
pOFPJ/6WZOlqkTVT6QPAcPUbTohKrF80hsZqZyDdSfT3peFx4ZLocBrS56m6NmHR
UYHMvJ8rQm76T1fryHVidz85g3zRmfBeWg8yqT5oFg4LYgfLsPm1gRjOhs8LfPvI
OLlRAoGBAIZ5Uv4Z3s8O7WKXXUe/lq6j7vfiVkR1NW/Z/WLKXZpnmvJ7FgxN4e56
RXT7GwNQHIY8eDjDnsHxzrxd+raOxOZeKcMHj3XyjCX3NHfTscnsBPAGYpY/Wxzh
T8UYnFu6RzkixElTf2rseEav7rkdKkI3LAeIZy7B0HulKKsmqVQ7
-----END RSA PRIVATE KEY-----
`

	PublicKey = `
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgUElV5mwqkloIrM8ZNZ7
2gSCcnSJt7+/Usa5G+D15YQUAdf9c1zEekTfHgDP+04nw/uFNFaE5v1RbHaPxhZY
Vg5ZErNCa/hzn+x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL/c3H/B+2G
le3hTxjlWFb3F5qLgR+4Mf4ruhER1v6eHQa/nchi03MBpT4UeJ7MrL92hTJYLdpS
yCqmr8yjxkKJDVC2uRrr+sTSxfh7r6v24u/vp/QTmBIAlNPgadVAZw17iNNb7vjV
7Gwl/5gHXonCUKURaV++dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV+
7QIDAQAB
-----END PUBLIC KEY-----
`
	ECPrivateKey = `
-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDBYv+Kxcvmf1THbJ3amFFEwf9o8JnBV+CFQSERT0XQvQQqiLswPShGK
uWypa5iw3B2gBwYFK4EEACKhZANiAARCdKoVsoZ0SLP+DQKhkVcEC+wwxswGqqdn
eMn/OsvG4FKENOauxGhTswI4Atu3Th8WhEjwfTppLVarVewBsyIwtSqmXmOg5Z5Q
KHHI9vS/7sHzogT3b31QcGlsB9ye2F0=
-----END EC PRIVATE KEY-----`

	ECPublicKey = `
-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQnSqFbKGdEiz/g0CoZFXBAvsMMbMBqqn
Z3jJ/zrLxuBShDTmrsRoU7MCOALbt04fFoRI8H06aS1Wq1XsAbMiMLUqpl5joOWe
UChxyPb0v+7B86IE9299UHBpbAfcnthd
-----END PUBLIC KEY-----`
)

func TestAccJwksFromKeyDataSource(t *testing.T) {
	resourceName := "data.jwks_from_key.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProviders,
		CheckDestroy:             testAccCheckJwksFromKeyDataSourceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJwksFromKeyDataSourceConfig(PrivateKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(PublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ECPrivateKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ECPublicKey),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},

			{
				Config: testAccJwksFromKeyDataSourceConfig(privateKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(publicKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ecPrivateKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyDataSourceConfig(ecPublicKeyDer()),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithKidDataSourceConfig(ecPrivateKeyDer(), "123"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kid":"123","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithKidDataSourceConfig(ecPublicKeyDer(), "123"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"crv":"P-384","kid":"123","kty":"EC","x":"QnSqFbKGdEiz_g0CoZFXBAvsMMbMBqqnZ3jJ_zrLxuBShDTmrsRoU7MCOALbt04f","y":"FoRI8H06aS1Wq1XsAbMiMLUqpl5joOWeUChxyPb0v-7B86IE9299UHBpbAfcnthd"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithUseDataSourceConfig(PublicKey, "sig"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q","use":"sig"}`),
				),
			},
			{
				Config: testAccJwksFromKeyWithAlgDataSourceConfig(PublicKey, "RS256"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(resourceName, "jwk", `{"alg":"RS256","e":"AQAB","kty":"RSA","n":"gUElV5mwqkloIrM8ZNZ72gSCcnSJt7-_Usa5G-D15YQUAdf9c1zEekTfHgDP-04nw_uFNFaE5v1RbHaPxhZYVg5ZErNCa_hzn-x10xzcepeS3KPVXcxae4MR0BEegvqZqJzN9loXsNL_c3H_B-2Gle3hTxjlWFb3F5qLgR-4Mf4ruhER1v6eHQa_nchi03MBpT4UeJ7MrL92hTJYLdpSyCqmr8yjxkKJDVC2uRrr-sTSxfh7r6v24u_vp_QTmBIAlNPgadVAZw17iNNb7vjV7Gwl_5gHXonCUKURaV--dBNLrHIZpqcAM8wHRph8mD1EfL9hsz77pHewxolBATV-7Q"}`),
				),
			},
		},
	})
}

func TestAccJwksFromKeyMLDSADataSource(t *testing.T) {
	resourceName := "data.jwks_from_key.test"

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV5ProviderFactories: testAccProviders,
		CheckDestroy:             testAccCheckJwksFromKeyDataSourceDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA44())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-44", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA65())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-65", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPublicConfig(mlDSAKeyBase64(mldsa.MLDSA87())),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-87", false),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-44"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-44", true),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-65"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-65", true),
			},
			{
				Config: testAccJwksFromKeyMLDSAPrivateConfig(mlDSASeedBase64(), "ML-DSA-87"),
				Check:  checkMLDSAJWK(resourceName, "ML-DSA-87", true),
			},
		},
	})
}

func testAccCheckJwksFromKeyDataSourceDestroy(s *terraform.State) error {
	return nil
}

func testAccJwksFromKeyDataSourceConfig(data string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = <<EOF
%s
EOF
}
	`, data)
}

func testAccJwksFromKeyWithKidDataSourceConfig(data, kid string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		kid = %s
	}
	`, data, kid)
}

func testAccJwksFromKeyWithUseDataSourceConfig(data, use string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		use = "%s"
	}
	`, data, use)
}

func testAccJwksFromKeyWithAlgDataSourceConfig(data, alg string) string {
	return fmt.Sprintf(`
	data "jwks_from_key" "test" {
		key = <<EOF
%s
EOF
		alg = "%s"
	}
	`, data, alg)
}

func privateKeyDer() string {
	block, _ := pem.Decode([]byte(PrivateKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func publicKeyDer() string {
	block, _ := pem.Decode([]byte(PublicKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func ecPrivateKeyDer() string {
	block, _ := pem.Decode([]byte(ECPrivateKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

func ecPublicKeyDer() string {
	block, _ := pem.Decode([]byte(ECPublicKey))
	return base64.StdEncoding.EncodeToString(block.Bytes)
}

// mlDSAKeyBase64 returns a base64 std-encoded ML-DSA public key for the given
// parameter set, derived from a fixed all-zeros seed for test determinism.
func mlDSAKeyBase64(params *mldsa.Parameters) string {
	seed := make([]byte, 32)
	sk, err := mldsa.NewPrivateKey(params, seed)
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(sk.PublicKey().Bytes())
}

// mlDSASeedBase64 returns the base64 std-encoding of a fixed all-zeros 32-byte
// seed, usable as ML-DSA private key input.
func mlDSASeedBase64() string {
	return base64.StdEncoding.EncodeToString(make([]byte, 32))
}

// checkMLDSAJWK returns a TestCheckFunc that parses the jwks attribute as JSON
// and asserts public AKP fields are present and private fields are absent.
func checkMLDSAJWK(resourceName, wantAlg string, _ bool) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return fmt.Errorf("resource %s not found", resourceName)
		}
		raw := rs.Primary.Attributes["jwk"]
		var m map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			return fmt.Errorf("jwks is not valid JSON: %w", err)
		}
		if m["kty"] != "AKP" {
			return fmt.Errorf("expected kty=AKP, got %v", m["kty"])
		}
		if m["alg"] != wantAlg {
			return fmt.Errorf("expected alg=%s, got %v", wantAlg, m["alg"])
		}
		if _, ok := m["pub"]; !ok {
			return fmt.Errorf("expected pub field to be present")
		}
		if _, ok := m["priv"]; ok {
			return fmt.Errorf("private key leaked into public JWK")
		}
		return nil
	}
}

func testAccJwksFromKeyMLDSAPublicConfig(keyBase64 string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = "%s"
}
`, keyBase64)
}

func testAccJwksFromKeyMLDSAPrivateConfig(seedBase64, alg string) string {
	return fmt.Sprintf(`
data "jwks_from_key" "test" {
  key = "%s"
  alg = "%s"
}
`, seedBase64, alg)
}

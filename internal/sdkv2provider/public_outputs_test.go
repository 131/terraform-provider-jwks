package sdkv2provider

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func assertPublicOutputs(t *testing.T, d *schema.ResourceData) {
	t.Helper()
	var key map[string]interface{}
	if err := json.Unmarshal([]byte(d.Get("jwk").(string)), &key); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"kty": true, "alg": true, "kid": true, "use": true}
	switch key["kty"] {
	case "RSA":
		allowed["n"], allowed["e"] = true, true
	case "EC":
		allowed["crv"], allowed["x"], allowed["y"] = true, true, true
	case "OKP":
		allowed["crv"], allowed["x"] = true, true
	case "AKP":
		allowed["pub"] = true
	default:
		t.Fatalf("unexpected key type %v", key["kty"])
	}
	for name := range key {
		if !allowed[name] {
			t.Fatalf("unexpected output field %s", name)
		}
	}
	var set map[string][]map[string]interface{}
	if err := json.Unmarshal([]byte(d.Get("jwks").(string)), &set); err != nil {
		t.Fatal(err)
	}
	if len(set) != 1 || len(set["keys"]) != 1 || !reflect.DeepEqual(set["keys"][0], key) {
		t.Fatal("jwks must contain exactly the public jwk in a keys array")
	}
}

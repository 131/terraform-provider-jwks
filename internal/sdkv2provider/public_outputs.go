package sdkv2provider

import (
	"encoding/json"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/lestrrat-go/jwx/v4/jwk"
)

// Export the public key first, then retain only public JWK primitives and
// explicitly supported metadata. Never serialize private parameters to outputs.
func setPublicKeyOutputs(d *schema.ResourceData, key jwk.Key) diag.Diagnostics {
	public, err := key.PublicKey()
	if err != nil {
		return diag.FromErr(err)
	}
	b, err := json.Marshal(public)
	if err != nil {
		return diag.FromErr(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return diag.FromErr(err)
	}
	clean := make(map[string]json.RawMessage)
	for _, name := range []string{"kty", "n", "e", "crv", "x", "y", "pub", "alg", "kid", "use"} {
		if value, ok := fields[name]; ok {
			clean[name] = value
		}
	}
	b, err = json.Marshal(clean)
	if err != nil {
		return diag.FromErr(err)
	}
	set, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{b}})
	if err != nil {
		return diag.FromErr(err)
	}
	if err := d.Set("jwk", string(b)); err != nil {
		return diag.FromErr(err)
	}
	return diag.FromErr(d.Set("jwks", string(set)))
}

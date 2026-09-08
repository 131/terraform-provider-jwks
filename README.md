# terraform-provider-jwks

A Terraform provider for generating [JSON Web Key Sets (JWKS)](https://datatracker.ietf.org/doc/html/rfc7517) from keys and certificates.

Fork of [iwarapter/terraform-provider-jwks](https://github.com/iwarapter/terraform-provider-jwks), prepared for the `131/jwks` namespace.

## Data Sources

### `jwks_from_key`

Generates a JWKS from a PEM-encoded or base64 DER-encoded public or private key.

```hcl
data "jwks_from_key" "example" {
  key = file("${path.module}/public.pem")
  kid = "my-key-id"
  use = "sig"
  alg = "RS256"
}

output "jwks" {
  value = data.jwks_from_key.example.jwks
}
```

Accepts keys from AWS KMS, local PEM files, or any base64 DER source:

```hcl
data "jwks_from_key" "kms" {
  key = data.aws_kms_public_key.example.public_key
}
```

### `jwks_from_certificate`

Generates a JWKS from a PEM-encoded certificate or certificate chain. The chain must be ordered with the end-entity certificate first.

```hcl
data "jwks_from_certificate" "example" {
  pem = file("${path.module}/certificate.pem")
  kid = "my-cert-id"
  use = "sig"
  alg = "RS256"
}
```

## Docker/libtrust key IDs

For Docker Distribution / GitLab container registry authentication:

```hcl
terraform {
  required_providers {
    jwks = {
      source = "131/jwks"
    }
  }
}

data "jwks_from_certificate" "gitlab_registry" {
  pem        = file("${path.module}/certificate.pem")
  kid_format = "libtrust"
  use        = "sig"
  alg        = "RS256"
}
```

`kid_format` defaults to `"certificate"`, preserving the original certificate
fingerprint. `"libtrust"` hashes the DER SubjectPublicKeyInfo with SHA-256,
encodes the first 30 bytes in uppercase base32 and separates groups of four
characters with colons. This is the [Docker/libtrust key ID](https://github.com/docker/libtrust/blob/master/key.go)
used by [GitLab registry tokens](https://github.com/gitlabhq/gitlabhq/blob/master/lib/json_web_token/rsa_token.rb).
It stays stable when a certificate is renewed with the same public key. An
explicit `kid` takes precedence over `kid_format`. Certificate metadata (`x5c`
and `x5t#S256`) is unchanged.

## Development

To use a local build before publishing:

```sh
GOEXPERIMENT=jsonv2 go build -o "$PWD/bin/terraform-provider-jwks" .
```

In the `provider_installation.dev_overrides` block of your Terraform CLI
configuration, map the provider source address used by your configuration to
the absolute path of the local `bin` directory.
Development overrides let `terraform plan` use the local binary without a
published registry version. Do not run `terraform init` to install an unpublished
provider. Remove the override after publishing and pin the released version in
the consumer before running `terraform init`.

```sh
make test    # run tests
make checks  # fmt, vet, staticcheck, gosec
```

## CI and releases

GitHub Actions runs acceptance tests, `go vet`, and a build on pushes and pull
requests. The build workflow can also be started manually.

Pushing a `v*` tag runs GoReleaser, which builds the provider archives,
signs SHA-256 checksums, and publishes the GitHub release directly.
Tests run in the separate build workflow. Configure the repository secrets
`GPG_PRIVATE_KEY` and `PASSPHRASE`. `GITHUB_TOKEN` is supplied automatically by
GitHub Actions. Register the signing public key in the publisher's Terraform
Registry namespace.

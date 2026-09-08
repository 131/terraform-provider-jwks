# JWKS Provider

The JWKS provider is used to help working with public and private keys to generate JSON Web Key Sets.

## Example Usage
Terraform 0.13 and later:
```hcl
# Configure the JWKS Provider
terraform {
  required_providers {
    jwks = {
      source = "131/jwks"
    }
  }
}

provider "jwks" {}
```
Terraform 0.12 and earlier:
```hcl
# Configure the JWKS Provider
provider "jwks" {}
```

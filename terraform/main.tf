terraform {
  required_providers {
    pkcs11 = {
      source = "blechschmidt/pkcs11"
    }
  }
}

provider "pkcs11" {
  module_path = var.pkcs11_module_path
  token_label = var.token_label
  pin         = var.pkcs11_pin
}

# YubiHSM Ed25519 root CA key.
#
# The key was generated on the YubiHSM via yubihsm-shell and imported into
# Terraform state with:
#   terraform import pkcs11_key_pair.root_ca_ed25519[0] 'ssh-pki-root-ca/50dd'
#
# CKM_EC_EDWARDS_KEY_PAIR_GEN = 0x1055 = 4181
resource "pkcs11_key_pair" "root_ca_ed25519" {
  count     = var.use_yubihsm ? 1 : 0
  mechanism = "4181" # CKM_EC_EDWARDS_KEY_PAIR_GEN

  public_key = {
    label = var.ca_label
    class = "CKO_PUBLIC_KEY"
  }

  private_key = {
    label = var.ca_label
    class = "CKO_PRIVATE_KEY"
  }

  lifecycle {
    # The key already exists on the HSM — never recreate or modify it
    prevent_destroy = true
    ignore_changes  = all
  }
}

# Test signing with the Ed25519 key to verify it works
# CKM_EDDSA = 0x1057 = 4183
data "pkcs11_signature" "test_sign" {
  count = var.use_yubihsm ? 1 : 0

  mechanism = "4183" # CKM_EDDSA
  key_label = var.ca_label
  key_class = "CKO_PRIVATE_KEY"
  data      = base64encode("test-signing-verification")
}

# ECDSA P-384 key pair on SoftHSM (fallback for environments without Ed25519)
resource "pkcs11_key_pair" "root_ca_ecdsa" {
  count     = var.use_yubihsm ? 0 : 1
  mechanism = "CKM_EC_KEY_PAIR_GEN"

  public_key = {
    label     = "${var.ca_label}-pub"
    class     = "CKO_PUBLIC_KEY"
    key_type  = "CKK_EC"
    ec_params = "BgUrgQQAIg==" # OID 1.3.132.0.34 (P-384) DER-encoded
    token     = true
    verify    = true
  }

  private_key = {
    label     = "${var.ca_label}-priv"
    class     = "CKO_PRIVATE_KEY"
    key_type  = "CKK_EC"
    token     = true
    sign      = true
    sensitive = true
  }
}

data "pkcs11_slots" "all" {}

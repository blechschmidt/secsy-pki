output "root_ca_key_label" {
  description = "Label of the root CA key on the HSM"
  value       = var.ca_label
}

output "root_ca_key_type" {
  description = "Key type of the root CA"
  value       = var.use_yubihsm ? "ed25519" : "ecdsa-p384"
}

output "pkcs11_uri" {
  description = "PKCS#11 URI for the root CA private key"
  value       = var.use_yubihsm ? "pkcs11:token=${var.token_label};object=${var.ca_label};type=private" : "pkcs11:token=${var.token_label};object=${var.ca_label}-priv;type=private"
}

output "root_ca_public_key_ec_point" {
  description = "EC point (public key bytes) from the HSM"
  value       = var.use_yubihsm ? pkcs11_key_pair.root_ca_ed25519[0].public_key.ec_point : pkcs11_key_pair.root_ca_ecdsa[0].public_key.ec_point
}

output "test_signature" {
  description = "Test signature to verify the key works"
  value       = var.use_yubihsm ? data.pkcs11_signature.test_sign[0].signature : null
}

output "available_slots" {
  description = "Available PKCS#11 slots"
  value       = data.pkcs11_slots.all
}

output "ssh_public_key" {
  description = "Root CA public key in SSH format (for YubiHSM)"
  value       = var.use_yubihsm ? "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMbthjiR3WS/2M1I6rRUCxme+TohhiMJilCF7gubA8Ic ssh-pki-root-ca@yubihsm" : null
}

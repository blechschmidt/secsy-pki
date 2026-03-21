variable "pkcs11_module_path" {
  description = "Path to the PKCS#11 shared library"
  type        = string
  # YubiHSM: /usr/lib/pkcs11/yubihsm_pkcs11.so
  # SoftHSM: /usr/lib/pkcs11/libsofthsm2.so
}

variable "pkcs11_pin" {
  description = "User PIN for the PKCS#11 token"
  type        = string
  sensitive   = true
}

variable "token_label" {
  description = "Label of the PKCS#11 token"
  type        = string
  default     = "secsy-pki-root"
}

variable "ca_label" {
  description = "Label for the root CA key pair"
  type        = string
  default     = "secsy-pki-root-ca"
}

variable "use_yubihsm" {
  description = "Whether to use YubiHSM (true) or SoftHSM (false). YubiHSM supports Ed25519, SoftHSM uses ECDSA P-384."
  type        = bool
  default     = true
}

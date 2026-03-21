package models

import "time"

type Permission string

const (
	PermSignCertificate   Permission = "SIGN_CERTIFICATE"
	PermManagePermissions Permission = "MANAGE_PERMISSIONS"
)

var AllPermissions = []Permission{
	PermSignCertificate,
	PermManagePermissions,
}

type CA struct {
	ID         string    `json:"id" db:"id"`
	ParentID   *string   `json:"parent_id,omitempty" db:"parent_id"`
	Label      string    `json:"label" db:"label"`
	PKCS11URI  string    `json:"pkcs11_uri" db:"pkcs11_uri"`
	KeyType    string    `json:"key_type" db:"key_type"`
	PublicKey  string    `json:"public_key" db:"public_key"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

type Group struct {
	ID   string `json:"id" db:"id"`
	Name string `json:"name" db:"name"`
}

type GroupMember struct {
	GroupID  string `json:"group_id" db:"group_id"`
	UserSub string `json:"user_sub" db:"user_sub"`
}

type PermissionEntry struct {
	ID         string     `json:"id" db:"id"`
	CAID       string     `json:"ca_id" db:"ca_id"`
	EntityType string     `json:"entity_type" db:"entity_type"` // "user" or "group"
	EntityID   string     `json:"entity_id" db:"entity_id"`
	Permission Permission `json:"permission" db:"permission"`
}

type SignRequest struct {
	CAID       string   `json:"ca_id"`
	PublicKey  string   `json:"public_key"`
	Principals []string `json:"principals"`
	CertType   string   `json:"cert_type"` // "user" or "host"
	KeyID      string   `json:"key_id"`
	ValidAfter string   `json:"valid_after,omitempty"`
	ValidBefore string  `json:"valid_before,omitempty"`
	Extensions map[string]string `json:"extensions,omitempty"`
	CriticalOptions map[string]string `json:"critical_options,omitempty"`
}

type SignResponse struct {
	Certificate string `json:"certificate"`
	KeyID       string `json:"key_id"`
}

type KeyGenRequest struct {
	KeyType    string            `json:"key_type"`    // rsa, ecdsa, ed25519, dsa
	Bits       int               `json:"bits"`        // key size for rsa/ecdsa
	Comment    string            `json:"comment"`
	Options    map[string]string `json:"options"`     // additional ssh-keygen options
}

type KeyGenResponse struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type PermissionGrant struct {
	CAID       string     `json:"ca_id"`
	EntityType string     `json:"entity_type"` // "user" or "group"
	EntityID   string     `json:"entity_id"`
	Permission Permission `json:"permission"`
}

type UserInfo struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
	IsRoot  bool   `json:"is_root"`
}

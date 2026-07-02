module github.com/blechschmidt/secsy-pki/server

go 1.25.7

require (
	github.com/coreos/go-oidc/v3 v3.17.0
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/uuid v1.6.0
	github.com/lib/pq v1.12.0
	github.com/mattn/go-sqlite3 v1.14.37
	github.com/miekg/pkcs11 v1.1.2
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.45.0
	gopkg.in/yaml.v3 v3.0.1
)

require golang.org/x/oauth2 v0.36.0 // indirect

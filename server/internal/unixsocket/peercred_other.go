//go:build !linux

package unixsocket

import "errors"

// peerCredential has no portable spelling: the BSDs expose LOCAL_PEERCRED and
// Windows exposes nothing comparable. Callers treat the error as "credentials
// unavailable" and fall back to an anonymous address, so the listener still
// works — it simply cannot attribute a connection to a local user.
func peerCredential(uintptr) (credential, error) {
	return credential{}, errors.ErrUnsupported
}

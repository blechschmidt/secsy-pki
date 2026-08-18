//go:build linux

package unixsocket

import "syscall"

// peerCredential reads the connected peer's user, group, and process ID with
// SO_PEERCRED. The kernel fills these in at connect(2) time from the peer's own
// credentials, so a client cannot claim to be someone else the way it could with
// an application-level header.
func peerCredential(fd uintptr) (credential, error) {
	ucred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	if err != nil {
		return credential{}, err
	}
	return credential{uid: ucred.Uid, gid: ucred.Gid, pid: ucred.Pid}, nil
}

//go:build windows

package unixsocket

// withRestrictiveUmask has no Windows equivalent: there is no umask, and the
// AF_UNIX sockets Windows does support carry ACLs inherited from their directory
// rather than mode bits. The subsequent chmod is likewise a no-op there, so a
// Windows deployment must protect the socket with the containing directory's
// ACL.
func withRestrictiveUmask(fn func() error) error { return fn() }

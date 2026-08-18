//go:build !windows

package unixsocket

import (
	"sync"
	"syscall"
)

// umaskMu serializes the process-wide umask change around bind. The listeners
// are created once, sequentially, during server startup — before any request is
// served and before the background jobs that write files are started — so the
// window is not observable in practice; the mutex makes that guarantee hold even
// if a future caller binds sockets concurrently.
var umaskMu sync.Mutex

// withRestrictiveUmask runs fn with every permission bit masked off, so a file
// (here: a socket) created inside it lands with mode 0000 and is opened up
// afterwards by an explicit chmod. There is no per-socket mode argument to
// bind(2), so this is the only way to avoid publishing a socket that is briefly
// more permissive than configured.
func withRestrictiveUmask(fn func() error) error {
	umaskMu.Lock()
	defer umaskMu.Unlock()
	prev := syscall.Umask(0o777)
	defer syscall.Umask(prev)
	return fn()
}

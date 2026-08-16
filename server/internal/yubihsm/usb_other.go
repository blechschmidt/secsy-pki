//go:build !linux

package yubihsm

import (
	"context"
	"fmt"
	"runtime"
)

// The direct USB transport is implemented against Linux usbfs. On other
// platforms the device is reached through a yubihsm-connector instead, which is
// a supported deployment rather than a degraded one — the SCP03 channel is
// end-to-end either way.
func openUSB(context.Context, string) (Transport, error) {
	return nil, fmt.Errorf("direct YubiHSM USB access is implemented for Linux only (this is %s); "+
		"run yubihsm-connector and use an http:// connector URL instead", runtime.GOOS)
}

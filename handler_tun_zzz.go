//go:build !darwin

package main

import (
	"golang.zx2c4.com/wireguard/tun"
)

// tunNewBatchDevice returns the device unchanged; batched tun io is a
// darwin-only workaround for the BatchSize()==1 utun device. On linux the
// wireguard device already batches via vnethdr, on windows wintun uses a
// shared-memory ring.
func tunNewBatchDevice(device tun.Device) tun.Device {
	return device
}

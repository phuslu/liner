//go:build notuntap

package main

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/phuslu/log"
)

type TunHandler struct {
	Config      TunConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
	DnsResolver *DnsResolver
	LocalDialer *LocalDialer
	Functions   *Functions
	Dialers     map[string]Dialer

	name string
	mtu  atomic.Int64
}

func (h *TunHandler) Load(ctx context.Context) error {
	return errors.ErrUnsupported
}

func (h *TunHandler) Unload() error {
	return errors.ErrUnsupported
}

func (h *TunHandler) Serve(ctx context.Context) {
	panic(errors.ErrUnsupported)
}

package main

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/libp2p/go-yamux/v5"
	"github.com/puzpuzpuz/xsync/v4"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type DialerContextKey struct {
	name string
}

var (
	DialerHTTPHeaderContextKey      any = &DialerContextKey{"dailer-http-header"}
	DialerDisableIPv6ContextKey     any = &DialerContextKey{"dailer-disable-ipv6"}
	DialerPreferIPv6ContextKey      any = &DialerContextKey{"dailer-prefer-ipv6"}
	DialerMemoryDialersContextKey   any = &DialerContextKey{"dailer-memory-dialers"}
	DialerMemoryListenersContextKey any = &DialerContextKey{"dailer-memory-listeners"}
)

// IsMemoryAddress check ip address is in 240.0.0.0/8
func IsMemoryAddress[Addr string | netip.Addr](ip Addr) bool {
	switch v := any(ip).(type) {
	case string:
		return strings.HasPrefix(v, "240.")
	case netip.Addr:
		return v.Is4() && v.As4()[0] == 240
	}
	return false
}

var _ Dialer = (*MemoryDialer)(nil)

type MemoryDialer struct {
	Address   string
	Session   *yamux.Session
	CreatedAt int64
}

func (d *MemoryDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		break
	default:
		return nil, net.InvalidAddrError("memory dialer network mismatched: " + network)
	}

	if address != d.Address {
		return nil, net.InvalidAddrError("memory dialer network mismatched: " + address + " != " + d.Address)
	}

	return d.Session.OpenStream(ctx)
}

type MemoryDialers struct {
	*xsync.Map[string, *MemoryDialer]
}

func MemoryDialersWith(ctx context.Context, mds *MemoryDialers) context.Context {
	if mds != nil {
		ctx = context.WithValue(ctx, DialerMemoryDialersContextKey, mds)
	}
	return ctx
}

func MemoryDialerOf(ctx context.Context, network, address string) *MemoryDialer {
	if mds, ok := ctx.Value(DialerMemoryDialersContextKey).(*MemoryDialers); ok && mds != nil {
		if md, ok := mds.Load(address); ok && md != nil {
			return md
		}
	}
	return nil
}

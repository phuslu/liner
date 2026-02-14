package main

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"time"

	"github.com/libp2p/go-yamux/v5"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/xtaci/smux"
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

var MemoryDialerIPPrefix = netip.MustParsePrefix("240.0.0.0/8")

var _ Dialer = (*MemoryDialer)(nil)

type MemoryDialer struct {
	Address   string
	Session   *MuxSession
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

	return d.Session.OpenConn(ctx)
}

type MemoryDialers struct {
	*xsync.Map[string, *MemoryDialer]
}

func MemoryDialerOf(ctx context.Context, network, address string) *MemoryDialer {
	if mds, ok := ctx.Value(DialerMemoryDialersContextKey).(*MemoryDialers); ok && mds != nil {
		if md, ok := mds.Load(address); ok && md != nil {
			return md
		}
	}
	return nil
}

type MuxSession struct {
	YamuxSession *yamux.Session
	SmuxSession  *smux.Session
}

func (s *MuxSession) OpenConn(ctx context.Context) (net.Conn, error) {
	switch {
	case s.YamuxSession != nil:
		return s.YamuxSession.Open(ctx)
	case s.SmuxSession != nil:
		return s.SmuxSession.OpenStream()
	}
	return nil, errors.ErrUnsupported
}

func (s *MuxSession) Ping(_ context.Context) (time.Duration, error) {
	switch {
	case s.YamuxSession != nil:
		return s.YamuxSession.Ping()
	case s.SmuxSession != nil:
		start := time.Now()
		stream, err := s.SmuxSession.OpenStream()
		if err != nil {
			return 0, err
		}
		defer stream.Close()
		return time.Since(start) / 2, nil
	}
	return 0, errors.ErrUnsupported
}

func (s *MuxSession) Close() error {
	switch {
	case s.YamuxSession != nil:
		return s.YamuxSession.Close()
	case s.SmuxSession != nil:
		return s.SmuxSession.Close()
	}
	return errors.ErrUnsupported
}

func (s *MuxSession) LocalAddr() net.Addr {
	switch {
	case s.YamuxSession != nil:
		return s.YamuxSession.LocalAddr()
	case s.SmuxSession != nil:
		return s.SmuxSession.LocalAddr()
	}
	return nil
}

func (s *MuxSession) RemoteAddr() net.Addr {
	switch {
	case s.YamuxSession != nil:
		return s.YamuxSession.RemoteAddr()
	case s.SmuxSession != nil:
		return s.SmuxSession.RemoteAddr()
	}
	return nil
}

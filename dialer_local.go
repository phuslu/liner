package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/puzpuzpuz/xsync/v4"
)

var _ Dialer = (*LocalDialer)(nil)

type LocalDialer struct {
	Logger      *slog.Logger
	DnsResolver *DnsResolver

	Interface       string
	DisableIPv6     bool
	PerferIPv6      bool
	ForbidLocalAddr bool
	Concurrency     int

	DialTimeout   time.Duration
	TCPKeepAlive  time.Duration
	ReadBuffSize  int
	WriteBuffSize int
	TLSConfig     *tls.Config
}

func (d *LocalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialContext(ctx, network, address, nil)
}

func (d *LocalDialer) DialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.TLSConfig == nil {
		return nil, errors.New("localdialer: empty tls config")
	}
	return d.dialContext(ctx, network, address, d.TLSConfig)
}

func (d *LocalDialer) dialContext(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
		break
	default:
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	if md := MemoryDialerOf(ctx, network, address); md != nil {
		if d.Logger != nil {
			d.Logger.Info("local dialer dialing to memory dialer", "memory_dialer_address", md.Address)
		}
		return md.DialContext(ctx, network, address)
	}

	if m, ok := ctx.Value(DialerMemoryListenersContextKey).(*xsync.Map[string, *MemoryListener]); ok && m != nil {
		if ml, ok := m.Load(address); ok && ml != nil {
			if d.Logger != nil {
				d.Logger.Info("local dialer dialing memory listener", "memory_listener_address", ml.Address)
			}
			return ml.OpenConn(), nil
		}
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := d.DnsResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, net.InvalidAddrError("empty dns record: " + host)
	}

	var perfers = ips
	var fallbacks []netip.Addr
	switch {
	case d.DisableIPv6 || ctx.Value(DialerDisableIPv6ContextKey) != nil:
		if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is6() }); i > 0 {
			perfers, fallbacks = ips[:i], nil
		}
	case d.PerferIPv6 || ctx.Value(DialerPreferIPv6ContextKey) != nil:
		if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is6() }); i > 0 {
			perfers, fallbacks = ips[i:], ips[:i]
		}
	}

	port, _ := strconv.Atoi(portStr)

	if d.DialTimeout > 0 {
		deadline := timeNow().Add(d.DialTimeout)
		if d, ok := ctx.Deadline(); ok && deadline.After(d) {
			deadline = d
		}

		subCtx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		ctx = subCtx
	}

	concurrency := max(d.Concurrency, 1)
	dial := d.dialParallel
	if concurrency <= 1 || len(perfers) == 1 {
		dial = d.dialSerial
	}

	conn, err := dial(ctx, network, host, perfers, uint16(port), tlsConfig)
	if err != nil && fallbacks != nil {
		if errmsg := err.Error(); strings.Contains(errmsg, "connect: network is unreachable") || (strings.HasPrefix(errmsg, "dial tcp ") && strings.HasSuffix(errmsg, ": i/o timeout")) {
			if d.Logger != nil {
				d.Logger.Warn("retrying dial to fallbacks ip4", "network", network, "host", host, "perfers", perfers, "fallbacks", fallbacks)
			}
			conn, err = dial(ctx, network, host, fallbacks, uint16(port), tlsConfig)
		}
	}
	return conn, err
}

func (d *LocalDialer) dialSerial(ctx context.Context, network, hostname string, ips []netip.Addr, port uint16, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if DailerReservedIPPrefix.Contains(ip) {
			return nil, net.InvalidAddrError("reserved address is unreachable: " + ip.String())
		}

		if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		dailer := &net.Dialer{}
		if d.Interface != "" {
			dailer.Control = (&DailerController{Interface: d.Interface}).Control
		}

		conn, err := dailer.DialTCP(ctx, network, netip.AddrPort{}, netip.AddrPortFrom(ip, port))
		if err != nil {
			if i < len(ips)-1 {
				continue
			} else {
				return nil, err
			}
		}

		if d.TCPKeepAlive > 0 {
			conn.SetKeepAliveConfig(net.KeepAliveConfig{
				Enable:   true,
				Idle:     d.TCPKeepAlive,
				Interval: d.TCPKeepAlive,
			})
		}

		if d.ReadBuffSize > 0 {
			conn.SetReadBuffer(d.ReadBuffSize)
		}

		if d.WriteBuffSize > 0 {
			conn.SetWriteBuffer(d.WriteBuffSize)
		}

		if tlsConfig == nil {
			return conn, nil
		}

		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			if i < len(ips)-1 {
				continue
			} else {
				return nil, err
			}
		}

		return tlsConn, nil
	}
	return nil, err
}

func (d *LocalDialer) dialParallel(ctx context.Context, network, hostname string, ips []netip.Addr, port uint16, tlsConfig *tls.Config) (net.Conn, error) {
	type dialResult struct {
		Conn net.Conn
		Err  error
	}

	level := len(ips)
	if level > d.Concurrency {
		level = d.Concurrency
		ips = ips[:level]
	}

	lane := make(chan dialResult, level)
	for i := 0; i < level; i++ {
		go func(ip netip.Addr, port uint16, tlsConfig *tls.Config) {
			if DailerReservedIPPrefix.Contains(ip) {
				lane <- dialResult{nil, net.InvalidAddrError("reserved address is unreachable: " + ip.String())}
				return
			}
			if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
				lane <- dialResult{nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())}
				return
			}
			dailer := &net.Dialer{}
			if d.Interface != "" {
				dailer.Control = (&DailerController{Interface: d.Interface}).Control
			}
			conn, err := dailer.DialTCP(ctx, network, netip.AddrPort{}, netip.AddrPortFrom(ip, port))
			if err != nil {
				lane <- dialResult{nil, err}
				return
			}

			if d.TCPKeepAlive > 0 {
				conn.SetKeepAliveConfig(net.KeepAliveConfig{
					Enable:   true,
					Idle:     d.TCPKeepAlive,
					Interval: d.TCPKeepAlive,
				})
			}

			if d.ReadBuffSize > 0 {
				conn.SetReadBuffer(d.ReadBuffSize)
			}

			if d.WriteBuffSize > 0 {
				conn.SetWriteBuffer(d.WriteBuffSize)
			}

			if tlsConfig == nil {
				lane <- dialResult{conn, nil}
				return
			}

			tlsConn := tls.Client(conn, tlsConfig)
			err = tlsConn.HandshakeContext(ctx)

			if err != nil {
				lane <- dialResult{nil, err}
				return
			}

			lane <- dialResult{tlsConn, nil}
		}(ips[i], port, tlsConfig)
	}

	var r dialResult
	for j := 0; j < level; j++ {
		r = <-lane
		if r.Err == nil {
			go func(count int) {
				var r1 dialResult
				for ; count > 0; count-- {
					r1 = <-lane
					if r1.Conn != nil {
						r1.Conn.Close()
					}
				}
			}(level - 1 - j)
			return r.Conn, nil
		}
	}

	return nil, r.Err
}

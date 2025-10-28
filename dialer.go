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
	"sync"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type DialerContextKey struct {
	name string
}

var (
	DialerHTTPHeaderContextKey    any = &DialerContextKey{"dailer-http-header"}
	DialerPreferIPv6ContextKey    any = &DialerContextKey{"dailer-prefer-ipv6"}
	DialerMemoryDialersContextKey any = &DialerContextKey{"dailer-memory-dialers"}
)

var _ Dialer = (*LocalDialer)(nil)

type LocalDialer struct {
	Logger   *slog.Logger
	Resolver *Resolver

	Interface       string
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

	if m, ok := ctx.Value(DialerMemoryDialersContextKey).(*sync.Map); ok && m != nil {
		if v, ok := m.Load(address); ok && d != nil {
			if md, ok := v.(*MemoryDialer); ok && md != nil {
				if d.Logger != nil {
					d.Logger.Info("http dialer switch to memory dialer", "memory_dialer_address", md.Address)
				}
				return md.DialContext(ctx, network, address)
			}
		}
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, net.InvalidAddrError("empty dns record: " + host)
	}

	var ip4 []netip.Addr
	if d.PerferIPv6 || ctx.Value(DialerPreferIPv6ContextKey) != nil {
		if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is6() }); i > 0 {
			ips, ip4 = ips[i:], ips[:i]
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
	if concurrency <= 1 || len(ips) == 1 {
		dial = d.dialSerial
	}

	conn, err := dial(ctx, network, host, ips, uint16(port), tlsConfig)
	if err != nil && ip4 != nil {
		if errmsg := err.Error(); strings.Contains(errmsg, "connect: network is unreachable") || (strings.HasPrefix(errmsg, "dial tcp ") && strings.HasSuffix(errmsg, ": i/o timeout")) {
			if d.Logger != nil {
				d.Logger.Warn("retrying dial to ip4", "network", network, "host", host, "ips", ips, "ip4", ip4)
			}
			conn, err = dial(ctx, network, host, ip4, uint16(port), tlsConfig)
		}
	}
	return conn, err
}

func (d *LocalDialer) dialSerial(ctx context.Context, network, hostname string, ips []netip.Addr, port uint16, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		dailer := &net.Dialer{}
		if d.Interface != "" {
			dailer.Control = (&DailerController{Interface: d.Interface}).Control
		}
		conn, err = dailer.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
		if err != nil {
			if i < len(ips)-1 {
				continue
			} else {
				return nil, err
			}
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
			if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
				lane <- dialResult{nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())}
				return
			}
			dailer := &net.Dialer{}
			if d.Interface != "" {
				dailer.Control = (&DailerController{Interface: d.Interface}).Control
			}
			conn, err := dailer.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
			if err != nil {
				lane <- dialResult{nil, err}
				return
			}

			if d.TCPKeepAlive > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(d.TCPKeepAlive)
				}
			}

			if d.ReadBuffSize > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetReadBuffer(d.ReadBuffSize)
				}
			}

			if d.WriteBuffSize > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetReadBuffer(d.WriteBuffSize)
				}
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

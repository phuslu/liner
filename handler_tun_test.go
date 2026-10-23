package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/quic-go/quic-go"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
)

func tunTestTCPPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	a, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := ln.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { b.Close() })
	for _, c := range []*net.TCPConn{a, b} {
		if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	return a, b
}

func TestTunRelayTCPHalfClose(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(map[bool]string{false: "client", true: "server"}[reverse], func(t *testing.T) {
			client, local := tunTestTCPPair(t)
			remote, server := tunTestTCPPair(t)
			done := make(chan struct{})
			go func() {
				defer close(done)
				tunRelayTCP(&ConnWithData{Conn: local}, remote, func() {})
			}()
			if reverse {
				client, server = server, client
			}
			request := bytes.Repeat([]byte("request"), 20000)
			go func() {
				client.Write(request)
				client.CloseWrite()
			}()
			got, err := io.ReadAll(server)
			if err != nil || !bytes.Equal(got, request) {
				t.Fatalf("request after half-close: bytes=%d err=%v", len(got), err)
			}
			if _, err := server.Write([]byte("response after EOF")); err != nil {
				t.Fatal(err)
			}
			server.CloseWrite()
			got, err = io.ReadAll(client)
			if err != nil || string(got) != "response after EOF" {
				t.Fatalf("response after half-close: %q, %v", got, err)
			}
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("relay did not join both copy directions")
			}
		})
	}
}

type tunTestErrorConn struct {
	net.Conn
}

func (c tunTestErrorConn) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestTunRelayTCPReadError(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		local, client := net.Pipe()
		remote, server := net.Pipe()
		defer client.Close()
		defer server.Close()
		var a, b net.Conn = tunTestErrorConn{local}, remote
		if reverse {
			a, b = b, a
		}
		done := make(chan struct{})
		go func() {
			tunRelayTCP(a, b, func() {})
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			local.Close()
			remote.Close()
			t.Fatal("read error left the reverse copy blocked without an idle timer")
		}
	}
}

type tunTestCloseConn struct {
	net.Conn
	closed atomic.Bool
}

func (c *tunTestCloseConn) Close() error { c.closed.Store(true); return nil }

func TestTunIdleTimer(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		conn := new(tunTestCloseConn)
		touch, stop := tunStartIdleTimer(100*time.Millisecond, conn)
		defer stop()
		time.Sleep(80 * time.Millisecond)
		touch()
		time.Sleep(10 * time.Millisecond)
		touch()
		time.Sleep(95 * time.Millisecond)
		synctest.Wait()
		if conn.closed.Load() {
			t.Fatal("timer closed before a full idle interval since the last activity")
		}
		time.Sleep(5 * time.Millisecond)
		synctest.Wait()
		if !conn.closed.Load() {
			t.Fatal("idle connection did not close")
		}
	})
	synctest.Test(t, func(t *testing.T) {
		conn := new(tunTestCloseConn)
		touch, stop := tunStartIdleTimer(time.Second, conn)
		stop()
		touch()
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if conn.closed.Load() {
			t.Fatal("stopped timer closed the connection")
		}
	})
}

type tunTestDevice struct {
	tun.Device
	events      chan tun.Event
	closed      chan struct{}
	readEntered chan struct{}
	readRelease chan struct{}
	once        sync.Once
	mtu         atomic.Int64
}

func (d *tunTestDevice) BatchSize() int           { return 1 }
func (d *tunTestDevice) Events() <-chan tun.Event { return d.events }
func (d *tunTestDevice) MTU() (int, error)        { return int(d.mtu.Load()), nil }
func (d *tunTestDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if d.readEntered != nil {
		close(d.readEntered)
		<-d.closed
		<-d.readRelease
		return 0, os.ErrClosed
	}
	select {
	case <-d.closed:
		return 0, os.ErrClosed
	default:
		return 0, nil
	}
}
func (d *tunTestDevice) Close() error {
	d.once.Do(func() { close(d.closed) })
	return nil
}

func TestTunServeWaitsForIO(t *testing.T) {
	d := &tunTestDevice{
		events: make(chan tun.Event), closed: make(chan struct{}),
		readEntered: make(chan struct{}), readRelease: make(chan struct{}),
	}
	h := &TunHandler{device: d, endpoint: channel.New(1, 1500, "")}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.Serve(ctx); close(done) }()
	<-d.readEntered
	cancel()
	<-d.closed
	select {
	case <-done:
		t.Error("Serve returned before its read goroutine released buffers")
	default:
	}
	close(d.readRelease)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
	if !errors.Is(h.ctx.Err(), context.Canceled) {
		t.Fatal("handler lifetime was not canceled")
	}
}

func TestTunMTUUpdate(t *testing.T) {
	d := &tunTestDevice{events: make(chan tun.Event), closed: make(chan struct{})}
	h := &TunHandler{device: d, endpoint: channel.New(1, 1500, "")}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { h.Serve(ctx); close(done) }()
	for i := range 100 {
		d.mtu.Store(int64(1500 + i))
		d.events <- tun.EventMTUUpdate
	}
	cancel()
	<-done
}

func TestTunDialContextLifetime(t *testing.T) {
	h := new(TunHandler)
	h.ctx, h.cancel = context.WithCancel(context.Background())
	h.Config.Forward.DialTimeout = 1
	ctx, _, _, ok := h.prepareDial(&TunRequest{ServerAddr: netip.MustParseAddrPort("1.1.1.1:443")})
	if !ok {
		t.Fatal("prepareDial failed")
	}
	setup, cancel := h.forwardDialContext(ctx)
	cancel()
	if setup.Err() == nil || ctx.Err() != nil {
		t.Fatal("setup cancellation affected stream lifetime")
	}
	h.Unload()
	if ctx.Err() == nil {
		t.Fatal("Unload did not cancel pending forwarding work")
	}
}

type tunTestDialer func(context.Context, string, string) (net.Conn, error)

func (d tunTestDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return d(ctx, network, addr)
}

func TestTunUDPUnload(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "forwarding", true: "dialing"}[pending], func(t *testing.T) {
			local, client := net.Pipe()
			remote, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			defer remote.Close()
			h := new(TunHandler)
			h.ctx, h.cancel = context.WithCancel(context.Background())
			defer h.Unload()
			h.Config.Forward.UdpTimeout = -1
			started := make(chan struct{})
			h.static.Dialer = tunTestDialer(func(ctx context.Context, _, _ string) (net.Conn, error) {
				close(started)
				if pending {
					<-ctx.Done()
					return nil, ctx.Err()
				}
				return remote, nil
			})
			done := make(chan struct{})
			go func() {
				h.serveUDP(TunRequest{Network: "udp", ServerAddr: netip.MustParseAddrPort("1.1.1.1:123")}, local)
				close(done)
			}()
			<-started
			h.Unload()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("Unload left UDP forwarding or dialing blocked")
			}
			if !pending {
				server.SetReadDeadline(time.Now().Add(time.Second))
				if _, err := server.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
					t.Fatalf("upstream connection was not closed: %v", err)
				}
			}
		})
	}
}

func TestTunUnloadCleanupBeforeDeviceClose(t *testing.T) {
	d := &tunTestDevice{closed: make(chan struct{})}
	h := &TunHandler{device: d}
	h.ctx, h.cancel = context.WithCancel(context.Background())
	var calls atomic.Int32
	h.cleanup = func() {
		calls.Add(1)
		if h.ctx.Err() != context.Canceled {
			t.Error("cleanup ran before forwarding was canceled")
		}
		select {
		case <-d.closed:
			t.Error("device closed before route cleanup")
		default:
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { h.Unload() })
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls.Load())
	}
	select {
	case <-d.closed:
	default:
		t.Fatal("device was not closed")
	}
}

func TestTunLoadCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := new(TunHandler)
	if err := h.Load(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Load with canceled context: %v", err)
	}
	if h.device != nil || h.cleanup != nil {
		t.Fatal("canceled setup created TUN resources")
	}
}

func tunTestQUICInitials(t *testing.T, serverName string) [][]byte {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{ServerName: serverName, NextProtos: []string{"h3"}}, nil)
	var datagrams [][]byte
	for {
		buf := make([]byte, 2048)
		_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			break
		}
		datagrams = append(datagrams, buf[:n])
	}
	if len(datagrams) == 0 {
		t.Fatal("no quic initial captured")
	}
	return datagrams
}

func TestTunSniffQUICClientHello(t *testing.T) {
	initials := tunTestQUICInitials(t, "www.Example.com")
	t.Logf("captured %d initial datagrams, first %d bytes", len(initials), len(initials[0]))
	for _, reverse := range []bool{false, true} {
		datagrams := slices.Clone(initials)
		if reverse {
			slices.Reverse(datagrams)
		}
		// trailing datagram padding outside the packet length
		datagrams[0] = append(slices.Clone(datagrams[0]), 0, 0, 0, 0)
		lconn, rconn := net.Pipe()
		go func() {
			for _, b := range datagrams {
				if _, err := rconn.Write(b); err != nil {
					return
				}
			}
		}()
		h := new(TunHandler)
		hello, sniffed := h.sniffQUICClientHello(lconn, make([]byte, tunCopyBufferSize))
		lconn.Close()
		rconn.Close()
		if hello == nil || hello.ServerName != "www.Example.com" {
			t.Fatalf("reverse=%v datagrams=%d: unexpected hello %+v", reverse, len(datagrams), hello)
		}
		for i, b := range sniffed {
			if !bytes.Equal(b, datagrams[i]) {
				t.Fatalf("reverse=%v: sniffed datagram %d was modified", reverse, i)
			}
		}
	}
}

func TestTunSniffQUICClientHelloNotQUIC(t *testing.T) {
	lconn, rconn := net.Pipe()
	defer lconn.Close()
	defer rconn.Close()
	go rconn.Write([]byte("not a quic packet"))
	hello, sniffed := new(TunHandler).sniffQUICClientHello(lconn, make([]byte, tunCopyBufferSize))
	if hello != nil || len(sniffed) != 1 || string(sniffed[0]) != "not a quic packet" {
		t.Fatalf("unexpected sniff result %+v %q", hello, sniffed)
	}
}

func TestTunDomainDialer(t *testing.T) {
	proxy := tunTestDialer(func(context.Context, string, string) (net.Conn, error) { return nil, errors.ErrUnsupported })
	h := &TunHandler{Dialers: map[string]Dialer{"proxy1": proxy}}
	h.Config.Forward.DomainDialer = append(h.Config.Forward.DomainDialer, struct {
		Domain string `json:"domain" yaml:"domain"`
		Dialer string `json:"dialer" yaml:"dialer"`
	}{Domain: `(^|\.)example\.com$`, Dialer: "dialer=proxy1&prefer_ipv6=true"})
	h.dialer = nil
	for i, config := range h.Config.Forward.DomainDialer {
		var dd tunDomainDialer
		var err error
		if dd.dialer, dd.dialerName, dd.disableIPv6, dd.preferIPv6, err = h.parseForwardDialer(config.Dialer); err != nil {
			t.Fatal(i, err)
		}
		dd.domain = regexp.MustCompile(config.Domain)
		h.domainDialers = append(h.domainDialers, dd)
	}
	for _, c := range []struct {
		serverName string
		dialerName string
	}{
		{"www.EXAMPLE.com", "proxy1"},
		{"example.com", "proxy1"},
		{"notexample.com", ""},
		{"", ""},
	} {
		calls := 0
		req := &TunRequest{
			ServerAddr: netip.MustParseAddrPort("1.1.1.1:443"),
			TLSClientHello: func() (*tls.ClientHelloInfo, error) {
				calls++
				return &tls.ClientHelloInfo{ServerName: c.serverName}, nil
			},
		}
		ctx, _, dialerName, ok := h.prepareDial(req)
		if !ok || dialerName != c.dialerName || calls != 1 || req.ServerName != c.serverName {
			t.Fatalf("%q: ok=%v dialer=%q calls=%d server_name=%q", c.serverName, ok, dialerName, calls, req.ServerName)
		}
		if (ctx.Value(DialerPreferIPv6ContextKey) != nil) != (c.dialerName == "proxy1") {
			t.Fatalf("%q: prefer_ipv6 not applied", c.serverName)
		}
	}
}

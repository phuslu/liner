package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

type testSocksUDPDialer struct {
	network chan string
	address chan string
}

func (d *testSocksUDPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.network <- network
	d.address <- addr
	return (&net.Dialer{}).DialContext(ctx, network, addr)
}

func TestSocksUDPAssociate(t *testing.T) {
	echo, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(netip.MustParseAddrPort("127.0.0.1:0")))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()

	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := echo.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			msg := append([]byte("echo:"), buf[:n]...)
			_, _ = echo.WriteToUDPAddrPort(msg, addr)
		}
	}()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	dialer := &testSocksUDPDialer{
		network: make(chan string, 1),
		address: make(chan string, 1),
	}
	h := &SocksHandler{
		Dialers: map[string]Dialer{"udp": dialer},
	}
	h.Config.Forward.Dialer = "udp"
	h.Config.Forward.UdpTimeout = 2

	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			h.ServeConn(context.Background(), conn)
		}
		close(done)
	}()

	ctrl, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer ctrl.Close()
	if err := ctrl.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	if _, err = ctrl.Write([]byte{byte(VersionSocks5), 1, Socks5AuthMethodNone}); err != nil {
		t.Fatal(err)
	}
	var auth [2]byte
	if _, err = io.ReadFull(ctrl, auth[:]); err != nil {
		t.Fatal(err)
	}
	if auth != [2]byte{byte(VersionSocks5), Socks5AuthMethodNone} {
		t.Fatalf("unexpected auth response: %#v", auth)
	}

	if _, err = ctrl.Write([]byte{byte(VersionSocks5), byte(SocksCommandConnectUDP), 0, byte(Socks5IPv4Address), 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	var reply [22]byte
	if _, err = io.ReadFull(ctrl, reply[:4]); err != nil {
		t.Fatal(err)
	}
	if reply[0] != byte(VersionSocks5) || reply[1] != byte(Socks5StatusRequestGranted) || reply[2] != 0 {
		t.Fatalf("unexpected udp associate response header: %#v", reply[:4])
	}

	var relay netip.AddrPort
	switch Socks5AddressType(reply[3]) {
	case Socks5IPv4Address:
		if _, err = io.ReadFull(ctrl, reply[4:10]); err != nil {
			t.Fatal(err)
		}
		relay = netip.AddrPortFrom(netip.AddrFrom4(*(*[4]byte)(reply[4:8])), uint16(reply[8])<<8|uint16(reply[9]))
	case Socks5IPv6Address:
		if _, err = io.ReadFull(ctrl, reply[4:22]); err != nil {
			t.Fatal(err)
		}
		relay = netip.AddrPortFrom(netip.AddrFrom16(*(*[16]byte)(reply[4:20])), uint16(reply[20])<<8|uint16(reply[21]))
	default:
		t.Fatalf("unexpected udp associate address type: %d", reply[3])
	}

	udp, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}

	echoAddr := AddrPortFromNetAddr(echo.LocalAddr())
	echoIP := echoAddr.Addr().As4()
	payload := []byte("ping")
	packet := []byte{0, 0, 0, byte(Socks5IPv4Address), echoIP[0], echoIP[1], echoIP[2], echoIP[3], byte(echoAddr.Port() >> 8), byte(echoAddr.Port())}
	packet = append(packet, payload...)
	if _, err = udp.Write(packet); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1024)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("short udp response: %d", n)
	}
	if got := string(buf[10:n]); got != "echo:ping" {
		t.Fatalf("unexpected udp payload: %q", got)
	}

	select {
	case network := <-dialer.network:
		if network != "udp" {
			t.Fatalf("unexpected dial network: %q", network)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for udp dial network")
	}

	wantAddr := net.JoinHostPort(echoAddr.Addr().String(), strconv.Itoa(int(echoAddr.Port())))
	select {
	case addr := <-dialer.address:
		if addr != wantAddr {
			t.Fatalf("unexpected dial address: got %q want %q", addr, wantAddr)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for udp dial address")
	}

	ctrl.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("socks handler did not exit after control connection closed")
	}
}

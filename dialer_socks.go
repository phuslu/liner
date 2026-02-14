package main

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"
)

var _ Dialer = (*SocksDialer)(nil)

type SocksDialer struct {
	Username    string
	Password    string
	Host        string
	Port        string
	PSK         string
	Socks4      bool
	Socks4A     bool
	Socks5      bool
	Socks5H     bool
	Logger      *slog.Logger
	DnsResolver *DnsResolver
	Dialer      Dialer
}

func (d *SocksDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch {
	case d.Socks4, d.Socks4A:
		return d.dialsocks4(ctx, network, addr)
	case d.Socks5, d.Socks5H:
		return d.dialsocks5(ctx, network, addr)
	}
	return nil, errors.New("invaild socks dialer")
}

func (d *SocksDialer) dialsocks4(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("socksdialer: no support for SOCKS4 proxy connections of type " + network)
	}

	dialer := d.Dialer
	if md := MemoryDialerOf(ctx, network, addr); md != nil {
		if d.Logger != nil {
			d.Logger.Info("socks4 dialer switch to memory dialer", "memory_dialer_address", md.Address)
		}
		if addrport, err := netip.ParseAddrPort(addr); err == nil {
			if MemoryDialerIPPrefix.Contains(addrport.Addr()) {
				// Target is a memory address, skip SOCKS CONNECT
				return md.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
			}
		}
		dialer = md
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	if d.PSK != "" {
		sha1sum := sha1.Sum(s2b(d.PSK))
		nonce := binary.LittleEndian.Uint64(sha1sum[:8])
		conn = &Chacha20NetConn{
			Conn:   conn,
			Writer: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
			Reader: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
		}
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("socksdialer: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return nil, errors.New("socksdialer: port number out of range: " + portStr)
	}

	if d.DnsResolver != nil {
		if ips, err := d.DnsResolver.LookupNetIP(ctx, "ip", host); err == nil && len(ips) > 0 {
			host = ips[0].String()
		}
	}

	buf := make([]byte, 0, 1024)

	switch network {
	case "tcp", "tcp6", "tcp4":
		buf = append(buf, VersionSocks4, SocksCommandConnectTCP)
	case "udp", "udp6", "udp4":
		buf = append(buf, VersionSocks4, SocksCommandConnectUDP)
	default:
		return nil, errors.New("socksdialer: no support for SOCKS5 proxy connections of type " + network)
	}

	buf = append(buf, byte(port>>8), byte(port))
	if d.Socks4A {
		buf = append(buf, 0, 0, 0, 1, 0)
		buf = append(buf, []byte(host+"\x00")...)
	} else {
		ips, err := d.DnsResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("socksdialer: resolve %s return empty ip list", host)
		}
		if !ips[0].Is4() {
			return nil, errors.New("socksdialer: resolve ip address out of range: " + ips[0].String())
		}
		ip4 := ips[0].As4()
		buf = append(buf, ip4[0], ip4[1], ip4[2], ip4[3], 0)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	var resp [8]byte
	_, err = conn.Read(resp[:])
	if err != nil && err != io.EOF {
		return nil, err
	}

	if status := Socks4Status(resp[1]); status > 0 {
		return nil, errors.New("socksdialer: SOCKS4 proxy at " + d.Host + " failed to connect: " + status.String())
	}

	closeConn = nil
	return conn, nil
}

func (d *SocksDialer) dialsocks5(ctx context.Context, network, addr string) (net.Conn, error) {
	dialer := d.Dialer
	if md := MemoryDialerOf(ctx, network, addr); md != nil {
		if d.Logger != nil {
			d.Logger.Info("socks5 dialer switch to memory dialer", "memory_dialer_address", md.Address)
		}
		if addrport, err := netip.ParseAddrPort(addr); err == nil {
			if MemoryDialerIPPrefix.Contains(addrport.Addr()) {
				// Target is a memory address, skip SOCKS CONNECT
				return md.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
			}
		}
		dialer = md
	}

	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	if d.PSK != "" {
		sha1sum := sha1.Sum(s2b(d.PSK))
		nonce := binary.LittleEndian.Uint64(sha1sum[:8])
		conn = &Chacha20NetConn{
			Conn:   conn,
			Writer: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
			Reader: must(Chacha20NewStreamCipher([]byte(d.PSK), nonce)),
		}
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("socksdialer: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return nil, errors.New("socksdialer: port number out of range: " + portStr)
	}

	if !d.Socks5H && d.DnsResolver != nil {
		ips, err := d.DnsResolver.LookupNetIP(ctx, "ip", host)
		if err == nil && len(ips) > 0 {
			host = ips[0].String()
		}
	}

	// the size here is just an estimate
	buf := make([]byte, 0, 6+len(host))

	buf = append(buf, VersionSocks5)
	if len(d.Username) > 0 && len(d.Username) < 256 && len(d.Password) < 256 {
		buf = append(buf, 2 /* num auth methods */, Socks5AuthMethodNone, Socks5AuthMethodPassword)
	} else {
		buf = append(buf, 1 /* num auth methods */, Socks5AuthMethodNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("socksdialer: failed to write greeting to SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, errors.New("socksdialer: failed to read greeting from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}
	if buf[0] != 5 {
		return nil, errors.New("socksdialer: SOCKS5 proxy at " + d.Host + " has unexpected version " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] == 0xff {
		return nil, errors.New("socksdialer: SOCKS5 proxy at " + d.Host + " requires authentication")
	}

	if buf[1] == byte(Socks5AuthMethodPassword) {
		buf = buf[:0]
		buf = append(buf, 1 /* password protocol version */)
		buf = append(buf, uint8(len(d.Username)))
		buf = append(buf, d.Username...)
		buf = append(buf, uint8(len(d.Password)))
		buf = append(buf, d.Password...)

		if _, err := conn.Write(buf); err != nil {
			return nil, errors.New("socksdialer: failed to write authentication request to SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return nil, errors.New("socksdialer: failed to read authentication reply from SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}

		if buf[1] != 0 {
			return nil, errors.New("socksdialer: SOCKS5 proxy at " + d.Host + " rejected username/password")
		}
	}

	buf = buf[:0]
	switch network {
	case "tcp", "tcp6", "tcp4":
		buf = append(buf, VersionSocks5, SocksCommandConnectTCP, 0 /* reserved */)
	case "udp", "udp6", "udp4":
		buf = append(buf, VersionSocks5, SocksCommandConnectUDP, 0 /* reserved */)
	default:
		return nil, errors.New("socksdialer: no support for SOCKS5 proxy connections of type " + network)
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			buf = append(buf, Socks5IPv4Address)
		} else {
			buf = append(buf, Socks5IPv6Address)
		}
		buf = append(buf, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("socksdialer: destination hostname too long: " + host)
		}
		buf = append(buf, Socks5DomainName)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("socksdialer: failed to write connect request to SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return nil, errors.New("socksdialer: failed to read connect reply from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if status := Socks5Status(buf[1]); status > 0 {
		return nil, errors.New("socksdialer: SOCKS5 proxy at " + d.Host + " failed to connect: " + status.String())
	}

	bytesToDiscard := 0
	switch buf[3] {
	case Socks5IPv4Address:
		bytesToDiscard = net.IPv4len
	case Socks5IPv6Address:
		bytesToDiscard = net.IPv6len
	case Socks5DomainName:
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return nil, errors.New("socksdialer: failed to read domain length from SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}
		bytesToDiscard = int(buf[0])
	default:
		return nil, errors.New("socksdialer: got unknown address type " + strconv.Itoa(int(buf[3])) + " from SOCKS5 proxy at " + d.Host)
	}

	if cap(buf) < bytesToDiscard {
		buf = make([]byte, bytesToDiscard)
	} else {
		buf = buf[:bytesToDiscard]
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, errors.New("socksdialer: failed to read address from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	// Also need to discard the port number
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, errors.New("socksdialer: failed to read port from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	closeConn = nil
	return conn, nil
}

type SocksVersion byte

const (
	_             SocksVersion = iota
	VersionSocks4              = 4
	VersionSocks5              = 5
)

type SocksCommand byte

const (
	_                      SocksCommand = iota
	SocksCommandConnectTCP              = 1
	SocksCommandConnectUDP              = 3
)

type Socks4Status byte

const (
	_                               Socks4Status = iota
	Socks4StatusRequestGranted                   = 0x5a
	Socks4StatusConnectionForbidden              = 0x5b
	Socks4StatusIdentdRequired                   = 0x5c
	Socks4StatusIdentdFailed                     = 0x5d
)

func (s Socks4Status) String() string {
	switch s {
	case Socks4StatusRequestGranted:
		return "request granted"
	case Socks4StatusConnectionForbidden:
		return "connection forbidden"
	case Socks4StatusIdentdRequired:
		return "identd required"
	case Socks4StatusIdentdFailed:
		return "identd failed"
	}
	return "socks4 status: errno 0x" + strconv.FormatInt(int64(s), 16)
}

type Socks5AddressType byte

const (
	_                 Socks5AddressType = iota
	Socks5IPv4Address                   = 1
	Socks5DomainName                    = 3
	Socks5IPv6Address                   = 4
)

const (
	Socks5AuthMethodNone     byte = 0
	Socks5AuthMethodGSSAPI   byte = 1
	Socks5AuthMethodPassword byte = 2
)

type Socks5Status byte

const (
	Socks5StatusRequestGranted Socks5Status = iota
	Socks5StatusGeneralFailure
	Socks5StatusConnectionNotAllowedByRuleset
	Socks5StatusNetworkUnreachable
	Socks5StatusHostUnreachable
	Socks5StatusConnectionRefusedByDestinationHost
	Socks5StatusTTLExpired
	Socks5StatusCommandNotSupported
	Socks5StatusAddressTypeNotSupported
)

func (s Socks5Status) String() string {
	switch s {
	case Socks5StatusRequestGranted:
		return "request granted"
	case Socks5StatusGeneralFailure:
		return "general failure"
	case Socks5StatusConnectionNotAllowedByRuleset:
		return "connection not allowed by ruleset"
	case Socks5StatusNetworkUnreachable:
		return "network unreachable"
	case Socks5StatusHostUnreachable:
		return "host unreachable"
	case Socks5StatusConnectionRefusedByDestinationHost:
		return "connection refused by destination host"
	case Socks5StatusTTLExpired:
		return "TTL expired"
	case Socks5StatusCommandNotSupported:
		return "command not supported"
	case Socks5StatusAddressTypeNotSupported:
		return "address type not supported"
	}
	return "socks5 status: errno 0x" + strconv.FormatInt(int64(s), 16)
}

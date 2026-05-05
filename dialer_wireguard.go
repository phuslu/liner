package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

var _ Dialer = (*WireGuardDialer)(nil)

var wireguardLogger = &device.Logger{
	Errorf:   device.DiscardLogf,
	Verbosef: device.DiscardLogf,
}

type WireGuardDialer struct {
	URL         string
	DnsResolver *DnsResolver

	mu     sync.Mutex
	tnet   atomic.Pointer[netstack.Net]
	device *device.Device
	config wireguardDialerConfig
}

type wireguardDialerConfig struct {
	Addresses []netip.Addr
	DNS       []netip.Addr
	MTU       int
	UAPI      string
}

func (d *WireGuardDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if ctx == nil {
		panic("nil context")
	}

	if d.tnet.Load() == nil {
		if err := d.init(ctx); err != nil {
			return nil, err
		}
	}

	tnet := d.tnet.Load()
	if tnet == nil {
		return nil, errors.New("wireguard dialer is not initialized")
	}

	if ctx.Value(DialerDisableIPv6ContextKey) != nil {
		switch network {
		case "tcp":
			network = "tcp4"
		case "udp":
			network = "udp4"
		}
	}

	host, port, ok := wireguardSplitHostPort(network, addr)
	if !ok {
		return tnet.DialContext(ctx, network, addr)
	}

	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return wireguardDialAddrPort(ctx, tnet, network, netip.AddrPortFrom(ip, port))
	}

	if len(d.config.DNS) > 0 {
		return tnet.DialContext(ctx, network, addr)
	}

	if d.DnsResolver == nil {
		return nil, errors.New("wireguard dialer requires dns resolver for hostnames when dns is unset")
	}

	lookupNetwork := "ip"
	switch network {
	case "tcp4", "udp4":
		lookupNetwork = "ip4"
	case "tcp6", "udp6":
		lookupNetwork = "ip6"
	}
	ips, err := d.DnsResolver.LookupNetIP(ctx, lookupNetwork, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, net.InvalidAddrError("empty dns record: " + host)
	}
	if ctx.Value(DialerPreferIPv6ContextKey) != nil {
		if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is6() }); i > 0 {
			ips = append(append([]netip.Addr{}, ips[i:]...), ips[:i]...)
		}
	}
	for i, ip := range ips {
		if !wireguardNetworkAcceptsAddr(network, ip) {
			continue
		}
		conn, err := wireguardDialAddrPort(ctx, tnet, network, netip.AddrPortFrom(ip, port))
		if err == nil || i == len(ips)-1 {
			return conn, err
		}
	}
	return nil, net.InvalidAddrError("no suitable address found: " + host)
}

func (d *WireGuardDialer) init(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.tnet.Load() != nil {
		return nil
	}

	cfg, err := wireguardDialerConfigFromURL(ctx, d.URL, d.DnsResolver)
	if err != nil {
		return err
	}

	tdev, tnet, err := netstack.CreateNetTUN(cfg.Addresses, cfg.DNS, cfg.MTU)
	if err != nil {
		return fmt.Errorf("create wireguard netstack: %w", err)
	}

	dev := device.NewDevice(tdev, conn.NewDefaultBind(), wireguardLogger)
	loaded := false
	defer func() {
		if !loaded {
			dev.Close()
		}
	}()

	if err := dev.IpcSet(cfg.UAPI); err != nil {
		return fmt.Errorf("wireguard ipc set: %w", err)
	}
	if err := dev.Up(); err != nil {
		return fmt.Errorf("wireguard up: %w", err)
	}

	d.device = dev
	d.config = cfg
	d.tnet.Store(tnet)
	loaded = true
	return nil
}

func wireguardDialerConfigFromURL(ctx context.Context, rawURL string, resolver *DnsResolver) (wireguardDialerConfig, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return wireguardDialerConfig{}, err
	}
	if u.Host != "" || u.Path == "" {
		return wireguardDialerConfig{}, fmt.Errorf("wireguard dialer expects wg-quick config URL like wg:///etc/wireguard/wg0.conf")
	}

	data, err := os.ReadFile(u.Path)
	if err != nil {
		return wireguardDialerConfig{}, err
	}

	type peerConfig struct {
		publicKey           string
		presharedKey        string
		endpoint            string
		persistentKeepalive string
		allowedIPs          []string
	}

	var (
		privateKey string
		listenPort string
		fwmark     string
		peers      []peerConfig
		peer       *peerConfig
		section    string
		cfg        = wireguardDialerConfig{MTU: 1420}
	)

	for line := range strings.Lines(b2s(data)) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				peers = append(peers, peerConfig{})
				peer = &peers[len(peers)-1]
			}
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return cfg, fmt.Errorf("invalid wireguard config line: %q", line)
		}
		key = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(key), " ", ""))
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				privateKey = value
			case "listenport":
				listenPort = value
			case "fwmark":
				fwmark = value
			case "address":
				cfg.Addresses = cfg.Addresses[:0]
				for _, item := range wireguardSplitList(value) {
					addr, err := wireguardParseAddr(item)
					if err != nil {
						return cfg, fmt.Errorf("parse wireguard address: %w", err)
					}
					cfg.Addresses = append(cfg.Addresses, addr)
				}
			case "dns":
				cfg.DNS = cfg.DNS[:0]
				for _, item := range wireguardSplitList(value) {
					addr, err := wireguardParseAddr(item)
					if err != nil {
						continue
					}
					cfg.DNS = append(cfg.DNS, addr)
				}
			case "mtu":
				mtu, err := strconv.Atoi(value)
				if err != nil {
					return cfg, fmt.Errorf("parse wireguard mtu: %w", err)
				}
				cfg.MTU = mtu
			}
		case "peer":
			if peer == nil {
				peers = append(peers, peerConfig{})
				peer = &peers[len(peers)-1]
			}
			switch key {
			case "publickey":
				peer.publicKey = value
			case "presharedkey":
				peer.presharedKey = value
			case "endpoint":
				peer.endpoint = value
			case "allowedips":
				peer.allowedIPs = wireguardSplitList(value)
			case "persistentkeepalive":
				peer.persistentKeepalive = value
			}
		}
	}

	if len(cfg.Addresses) == 0 {
		return cfg, errors.New("wireguard address is required")
	}
	if privateKey, err = wireguardKeyToHex(privateKey); err != nil {
		return cfg, fmt.Errorf("invalid wireguard private_key: %w", err)
	}
	if len(peers) == 0 {
		return cfg, errors.New("wireguard peer is required")
	}

	has4, has6 := false, false
	for _, addr := range cfg.Addresses {
		has4 = has4 || addr.Is4()
		has6 = has6 || addr.Is6()
	}

	var uapi strings.Builder
	uapi.Grow(512 + 256*len(peers))
	uapi.WriteString("private_key=")
	uapi.WriteString(privateKey)
	uapi.WriteByte('\n')
	if listenPort != "" {
		if _, err := strconv.ParseUint(listenPort, 10, 16); err != nil {
			return cfg, fmt.Errorf("parse wireguard listen_port: %w", err)
		}
		uapi.WriteString("listen_port=")
		uapi.WriteString(listenPort)
		uapi.WriteByte('\n')
	}
	if fwmark != "" && !strings.EqualFold(fwmark, "off") {
		if _, err := strconv.ParseUint(fwmark, 10, 32); err != nil {
			return cfg, fmt.Errorf("parse wireguard fwmark: %w", err)
		}
		uapi.WriteString("fwmark=")
		uapi.WriteString(fwmark)
		uapi.WriteByte('\n')
	}
	uapi.WriteString("replace_peers=true\n")

	for i := range peers {
		peer := &peers[i]
		publicKey, err := wireguardKeyToHex(peer.publicKey)
		if err != nil {
			return cfg, fmt.Errorf("invalid wireguard peer public_key: %w", err)
		}

		uapi.WriteString("public_key=")
		uapi.WriteString(publicKey)
		uapi.WriteByte('\n')

		if peer.presharedKey != "" {
			presharedKey, err := wireguardKeyToHex(peer.presharedKey)
			if err != nil {
				return cfg, fmt.Errorf("invalid wireguard peer preshared_key: %w", err)
			}
			uapi.WriteString("preshared_key=")
			uapi.WriteString(presharedKey)
			uapi.WriteByte('\n')
		}

		if peer.endpoint != "" {
			host, portStr, err := net.SplitHostPort(peer.endpoint)
			if err != nil {
				if strings.Count(peer.endpoint, ":") == 0 {
					host, portStr = peer.endpoint, "51820"
				} else {
					return cfg, fmt.Errorf("parse wireguard endpoint: %w", err)
				}
			}
			port, err := strconv.ParseUint(portStr, 10, 16)
			if err != nil {
				return cfg, fmt.Errorf("parse wireguard endpoint port: %w", err)
			}
			host = strings.Trim(host, "[]")
			ip, err := netip.ParseAddr(host)
			if err != nil {
				if resolver == nil {
					return cfg, errors.New("dns resolver unavailable")
				}
				ips, err := resolver.LookupNetIP(ctx, "ip", host)
				if err != nil {
					return cfg, fmt.Errorf("resolve wireguard endpoint: %w", err)
				}
				if len(ips) == 0 {
					return cfg, net.InvalidAddrError("empty dns record: " + host)
				}
				ip = ips[0]
			}
			uapi.WriteString("endpoint=")
			uapi.WriteString(netip.AddrPortFrom(ip, uint16(port)).String())
			uapi.WriteByte('\n')
		}

		if peer.persistentKeepalive != "" && !strings.EqualFold(peer.persistentKeepalive, "off") {
			if _, err := strconv.ParseUint(peer.persistentKeepalive, 10, 16); err != nil {
				return cfg, fmt.Errorf("parse wireguard persistent_keepalive: %w", err)
			}
			uapi.WriteString("persistent_keepalive_interval=")
			uapi.WriteString(peer.persistentKeepalive)
			uapi.WriteByte('\n')
		}

		if len(peer.allowedIPs) == 0 {
			if has4 {
				peer.allowedIPs = append(peer.allowedIPs, "0.0.0.0/0")
			}
			if has6 {
				peer.allowedIPs = append(peer.allowedIPs, "::/0")
			}
		}
		uapi.WriteString("replace_allowed_ips=true\n")
		for _, allowedIP := range peer.allowedIPs {
			if _, err := netip.ParsePrefix(allowedIP); err != nil {
				return cfg, fmt.Errorf("parse wireguard allowed_ip: %w", err)
			}
			uapi.WriteString("allowed_ip=")
			uapi.WriteString(allowedIP)
			uapi.WriteByte('\n')
		}
	}

	cfg.UAPI = uapi.String()
	return cfg, nil
}

func wireguardDialAddrPort(ctx context.Context, tnet *netstack.Net, network string, addr netip.AddrPort) (net.Conn, error) {
	if !wireguardNetworkAcceptsAddr(network, addr.Addr()) {
		return nil, net.InvalidAddrError("address family mismatched: " + addr.String())
	}
	switch network {
	case "tcp", "tcp4", "tcp6":
		return tnet.DialContextTCPAddrPort(ctx, addr)
	case "udp", "udp4", "udp6":
		return tnet.DialUDPAddrPort(netip.AddrPort{}, addr)
	default:
		return tnet.DialContext(ctx, network, addr.String())
	}
}

func wireguardSplitHostPort(network, addr string) (string, uint16, bool) {
	switch network {
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6":
	default:
		return "", 0, false
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return "", 0, false
	}
	return host, uint16(port), true
}

func wireguardNetworkAcceptsAddr(network string, ip netip.Addr) bool {
	switch network {
	case "tcp4", "udp4":
		return ip.Is4()
	case "tcp6", "udp6":
		return ip.Is6()
	default:
		return true
	}
}

func wireguardParseAddr(value string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), nil
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	value = strings.Trim(value, "[]")
	return netip.ParseAddr(value)
}

func wireguardKeyToHex(value string) (string, error) {
	value = strings.TrimSpace(strings.ReplaceAll(value, " ", "+"))
	if value == "" {
		return "", errors.New("empty key")
	}
	if len(value) == 64 {
		if _, err := hex.DecodeString(value); err == nil {
			return strings.ToLower(value), nil
		}
	}
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(key) != 32 {
		return "", fmt.Errorf("invalid key length %d", len(key))
	}
	return hex.EncodeToString(key), nil
}

func wireguardSplitList(value string) []string {
	var values []string
	for item := range strings.SplitSeq(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			values = append(values, item)
		}
	}
	return values
}

func (d *WireGuardDialer) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if dev := d.device; dev != nil {
		dev.Close()
	}
	d.tnet.Store(nil)
	d.device = nil
}

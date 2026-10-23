package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go/quicvarint"
	"github.com/valyala/bytebufferpool"
	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

type TunRequest struct {
	TunName        string
	Network        string
	RemoteAddr     netip.AddrPort
	ServerAddr     netip.AddrPort
	Host           string
	Port           uint16
	TraceID        log.XID
	ServerName     string
	TLSClientHello func() (*tls.ClientHelloInfo, error)
	ProcessInfo    func() (*ConnProcessInfo, error)
}

type TunHandler struct {
	Config      TunConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
	DnsResolver *DnsResolver
	LocalDialer *LocalDialer
	Functions   *Functions
	Dialers     map[string]Dialer

	device   tun.Device
	endpoint *channel.Endpoint
	stack    *stack.Stack
	name     string
	mtu      atomic.Int64
	cleanup  func()
	once     sync.Once
	address  netip.Prefix
	ctx      context.Context
	cancel   context.CancelFunc

	dialer         *template.Template
	processDialers []tunProcessDialer
	domainDialers  []tunDomainDialer
	static         struct {
		Dialer      Dialer
		DialerName  string
		DisableIPv6 bool
		PreferIPv6  bool
	}
}

var tunEnvRegexp = regexp.MustCompile(`\$\{env:([^}]+)\}`)

type tunProcessDialer struct {
	path        *regexp.Regexp
	name        *regexp.Regexp
	dialer      Dialer
	dialerName  string
	disableIPv6 bool
	preferIPv6  bool
}

type tunDomainDialer struct {
	domain      *regexp.Regexp
	dialer      Dialer
	dialerName  string
	disableIPv6 bool
	preferIPv6  bool
}

func (h *TunHandler) Load(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var loaded bool
	var err error

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = h.Functions.ParseTemplate("tun_dialer", s); err != nil {
			return err
		}
	}
	if h.dialer == nil {
		if h.static.Dialer, h.static.DialerName, h.static.DisableIPv6, h.static.PreferIPv6, err = h.parseForwardDialer(h.Config.Forward.Dialer); err != nil {
			return err
		}
	} else {
		h.static.DisableIPv6 = h.Config.Forward.DisableIpv6
		h.static.PreferIPv6 = h.Config.Forward.PreferIpv6
	}
	for i, config := range h.Config.Forward.ProcessDialer {
		var err error
		var pd tunProcessDialer
		pd.dialer, pd.dialerName, pd.disableIPv6, pd.preferIPv6, err = h.parseForwardDialer(config.Dialer)
		if err != nil {
			return fmt.Errorf("parse tun process_dialer[%d].dialer: %w", i, err)
		}
		switch {
		case config.Path != "":
			// expand vscode-style ${env:NAME}, values are quoted as regex literals
			var missing string
			path := tunEnvRegexp.ReplaceAllStringFunc(config.Path, func(s string) string {
				name := s[len("${env:") : len(s)-1]
				value, ok := os.LookupEnv(name)
				if !ok {
					missing = cmp.Or(missing, name)
				}
				return regexp.QuoteMeta(value)
			})
			if missing != "" {
				return fmt.Errorf("parse tun process_dialer[%d].path: env %q not set", i, missing)
			}
			if pd.path, err = regexp.Compile(path); err != nil {
				return fmt.Errorf("parse tun process_dialer[%d].path: %w", i, err)
			}
		case config.Name != "":
			if pd.name, err = regexp.Compile(config.Name); err != nil {
				return fmt.Errorf("parse tun process_dialer[%d].name: %w", i, err)
			}
		}
		if pd.path != nil || pd.name != nil {
			h.processDialers = append(h.processDialers, pd)
		}
	}
	for i, config := range h.Config.Forward.DomainDialer {
		var err error
		var dd tunDomainDialer
		dd.dialer, dd.dialerName, dd.disableIPv6, dd.preferIPv6, err = h.parseForwardDialer(config.Dialer)
		if err != nil {
			return fmt.Errorf("parse tun domain_dialer[%d].dialer: %w", i, err)
		}
		if config.Domain == "" {
			continue
		}
		if dd.domain, err = regexp.Compile(config.Domain); err != nil {
			return fmt.Errorf("parse tun domain_dialer[%d].domain: %w", i, err)
		}
		h.domainDialers = append(h.domainDialers, dd)
	}
	if h.DnsResolver == nil && h.LocalDialer != nil {
		h.DnsResolver = h.LocalDialer.DnsResolver
	}

	h.mtu.Store(int64(cmp.Or(h.Config.MTU, map[bool]int{false: 9000, true: 4064}[runtime.GOOS == "darwin"])))
	h.device, err = tun.CreateTUN(cmp.Or(h.Config.Name, "tun%d"), int(h.mtu.Load()))
	if err != nil {
		return err
	}
	h.device = tunNewBatchDevice(h.device)
	if h.name, err = h.device.Name(); err != nil {
		h.name = cmp.Or(h.Config.Name, "tun")
	}
	if mtu, err := h.device.MTU(); err == nil && mtu > 0 {
		h.mtu.Store(int64(mtu))
	}

	defer func() {
		if !loaded {
			h.device.Close()
		}
	}()

	addressPrefix, err := netip.ParsePrefix(cmp.Or(strings.TrimSpace(h.Config.Address), "198.18.0.1/15"))
	if err != nil {
		return fmt.Errorf("parse tun address: %w", err)
	}
	h.address = addressPrefix

	routePrefixes := make([]netip.Prefix, 0)
	bypassPrefixes := make([]netip.Prefix, 0)
	addRoutePrefix := func(prefix netip.Prefix) {
		prefix = prefix.Masked()
		if slices.Contains(routePrefixes, prefix) {
			return
		}
		routePrefixes = append(routePrefixes, prefix)
	}

	addBypassPrefix := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		if u, err := url.Parse(value); err == nil && u.Host != "" {
			value = u.Host
		}
		if host, _, err := net.SplitHostPort(value); err == nil {
			value = host
		}
		value = strings.Trim(value, "[]")

		var prefixes []netip.Prefix
		switch {
		case strings.Contains(value, "/"):
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return err
			}
			prefixes = append(prefixes, prefix)
		default:
			if ip, err := netip.ParseAddr(value); err == nil {
				prefixes = append(prefixes, netip.PrefixFrom(ip, 32))
				break
			}
			resolver := h.DnsResolver
			if resolver == nil && h.LocalDialer != nil {
				resolver = h.LocalDialer.DnsResolver
			}
			if resolver == nil || resolver.Client == nil {
				return errors.New("dns resolver unavailable")
			}
			// A captive portal can black-hole DoH until authorized. No tun route
			// is installed yet, so retry while its page remains reachable; the
			// overall deadline bounds Load.
			var ips []netip.Addr
			deadline := time.Now().Add(5 * time.Minute)
			for attempt := 1; ; attempt++ {
				lookupCtx, cancel := context.WithTimeout(ctx, cmp.Or(resolver.Client.Timeout, 5*time.Second))
				ips, err = resolver.LookupNetIP(lookupCtx, "ip4", value)
				cancel()
				if err == nil {
					break
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if time.Now().After(deadline) {
					return err
				}
				e := log.Warn()
				if attempt > 1 {
					e = log.Debug()
				}
				e.Err(err).Str("tun_name", h.name).Str("tun_host", value).Str("dns_server", resolver.Client.Addr).Msg("tun bypass host lookup failed")
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
				}
			}
			for _, ip := range ips {
				prefixes = append(prefixes, netip.PrefixFrom(ip, 32))
			}
		}
		for _, prefix := range prefixes {
			if !prefix.Addr().Is4() {
				return errors.ErrUnsupported
			}
			prefix = prefix.Masked()
			if slices.Contains(bypassPrefixes, prefix) {
				continue
			}
			// log.Info().Str("tun_name", h.name).NetIPPrefix("tun_bypass_prefix", prefix).Msg("add bypass prefix")
			bypassPrefixes = append(bypassPrefixes, prefix)
		}
		return nil
	}

	routes := h.Config.Routes[:]
	if slices.ContainsFunc(routes, func(route string) bool { return strings.TrimSpace(route) == "0.0.0.0/0" }) {
		routes = make([]string, 0, len(h.Config.Routes)+1)
		for _, route := range h.Config.Routes {
			if strings.TrimSpace(route) == "0.0.0.0/0" {
				routes = append(routes, "0.0.0.0/1", "128.0.0.0/1")
			} else {
				routes = append(routes, route)
			}
		}
	}
	for _, route := range routes {
		route = strings.TrimSpace(route)
		if strings.HasPrefix(route, "-") {
			route = strings.TrimSpace(route[1:])
			if err := addBypassPrefix(route); err != nil {
				return fmt.Errorf("parse tun bypass route %q: %w", route, err)
			}
			continue
		}
		prefix, err := netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("parse tun route %q: %w", route, err)
		}
		addRoutePrefix(prefix)
	}
	if runtime.GOOS == "windows" && len(h.Config.Routes) == 0 {
		// Windows still needs a destination route for sockets bound only to the
		// TUN source address. Keep it as a high-metric /0 so normal routing wins.
		addRoutePrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))
	}
	// has default route
	if slices.ContainsFunc(h.Config.Routes, func(route string) bool { return strings.TrimSpace(route) == "0.0.0.0/0" }) {
		if h.Config.DisableIpv6 {
			for _, prefix := range []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")} {
				addRoutePrefix(prefix)
			}
		}
		for _, dialer := range h.Dialers {
			for dialer != nil {
				v := reflect.ValueOf(dialer)
				if v.Kind() != reflect.Pointer || v.IsNil() {
					break
				}
				if v = v.Elem(); v.Kind() != reflect.Struct {
					break
				}
				for _, key := range []string{"Resolve", "Host"} {
					if f := v.FieldByName(key); f.Kind() == reflect.String {
						if host := f.String(); host != "" {
							if err := addBypassPrefix(host); err != nil {
								return fmt.Errorf("parse tun bypass route %q: %w", host, err)
							}
							break
						}
					}
				}
				if f := v.FieldByName("Dialer"); f.IsValid() && f.CanInterface() {
					if next, ok := f.Interface().(Dialer); ok {
						dialer = next
						continue
					}
				}
				dialer = nil
			}
		}
		resolvers := []*DnsResolver{h.DnsResolver}
		if h.LocalDialer != nil {
			resolvers = append(resolvers, h.LocalDialer.DnsResolver)
		}
		for _, resolver := range resolvers {
			if resolver != nil && resolver.Client != nil {
				if err := addBypassPrefix(resolver.Client.Addr); err != nil {
					return fmt.Errorf("parse tun bypass route %q: %w", resolver.Client.Addr, err)
				}
			}
		}
	}
	cleanup, err := ConfigureTunInterface(h.name, addressPrefix, routePrefixes, cmp.Or(h.Config.RouteMetric, 32767), bypassPrefixes)
	if err != nil {
		return fmt.Errorf("configure tun interface: %w", err)
	}
	defer func() {
		if !loaded && cleanup != nil {
			cleanup()
		}
	}()

	log.Info().Str("tun_name", h.name).Str("tun_address", addressPrefix.String()).Msg("wait tun address update")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		addr := addressPrefix.Addr().Unmap()
		ready := false
		ifis, err := net.Interfaces()
		if err != nil {
			return fmt.Errorf("wait tun address ready: %w", err)
		}
		for _, ifi := range ifis {
			if !strings.EqualFold(ifi.Name, h.name) {
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				return fmt.Errorf("wait tun address ready: %w", err)
			}
			for _, a := range addrs {
				ipNet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip := ipNet.IP
				if ip4 := ip.To4(); ip4 != nil {
					ip = ip4
				}
				ipaddr, ok := netip.AddrFromSlice(ip)
				if ok && ipaddr.Unmap() == addr {
					ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IP(addr.AsSlice())})
					if err != nil {
						break
					}
					ln.Close()
					ready = true
					break
				}
			}
			break
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("wait tun address %s ready timeout: interface=%s", addressPrefix, h.name)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	log.Info().Str("tun_name", h.name).Str("tun_address", addressPrefix.String()).Msg("tun address updated")
	log.Info().Str("tun_name", h.name).Msg("tun link up")
	for _, prefix := range bypassPrefixes {
		log.Info().Str("tun_name", h.name).Str("tun_route", prefix.String()).Msg("tun bypass route updated")
	}
	for _, prefix := range routePrefixes {
		log.Info().Str("tun_name", h.name).Str("tun_route", prefix.String()).Msg("tun route updated")
	}
	if len(routePrefixes) == 0 {
		log.Info().Str("tun_name", h.name).Str("tun_route", "none").Msg("tun route updated")
	}

	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	var ep *channel.Endpoint
	defer func() {
		if !loaded {
			if ep != nil {
				ep.Close()
			}
			s.Close()
			s.Wait()
		}
	}()

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		return fmt.Errorf("enable tcp sack: %s", err)
	}
	// gvisor defaults to reno; cubic recovers faster from drops on the
	// stack-to-tun path (channel queue or tun ring overflow).
	congestionControlOpt := tcpip.CongestionControlOption("cubic")
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &congestionControlOpt); err != nil {
		return fmt.Errorf("set tcp congestion control: %s", err)
	}
	tcpBufferSize := max(cmp.Or(h.Config.Forward.TcpBufferSize, tcp.MaxBufferSize), tcp.MinBufferSize)
	tcpBufferSizeOpt := tcpip.TCPSendBufferSizeRangeOption{
		Min:     tcp.MinBufferSize,
		Default: tcpBufferSize,
		Max:     max(tcpBufferSize, tcp.MaxBufferSize),
	}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpBufferSizeOpt); err != nil {
		return fmt.Errorf("set tcp send buffer size: %s", err)
	}
	tcpReceiveBufferSizeOpt := tcpip.TCPReceiveBufferSizeRangeOption(tcpBufferSizeOpt)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &tcpReceiveBufferSizeOpt); err != nil {
		return fmt.Errorf("set tcp receive buffer size: %s", err)
	}

	ep = channel.New(cmp.Or(h.Config.StackQueueSize, 4096), uint32(h.mtu.Load()), "")
	ep.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
	// With gVisor GSO the tcp sender builds super-segments up to the
	// endpoint GSOMaxSize (32KB) and splits them into MSS-sized packets
	// only at write time, amortizing the per-segment send-loop, route and
	// packet-delivery costs. Packets reaching the tun write loop are still
	// at most MSS bytes, so the device-level GRO/GSO offload is unaffected.
	ep.SupportedGSOKind = stack.GVisorGSOSupported
	if err := s.CreateNIC(1, ep); err != nil {
		return fmt.Errorf("create tun stack nic: %s", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol: header.IPv4ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addressPrefix.Addr().AsSlice()),
			PrefixLen: addressPrefix.Bits(),
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("add tun stack address: %s", err)
	}
	if err := s.SetPromiscuousMode(1, true); err != nil {
		return fmt.Errorf("enable tun promiscuous mode: %s", err)
	}
	if err := s.SetSpoofing(1, true); err != nil {
		return fmt.Errorf("enable tun spoofing mode: %s", err)
	}

	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: 1})
	s.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: 1})

	tcpForwarder := tcp.NewForwarder(s, tcpBufferSize, cmp.Or(h.Config.Forward.TcpMaxInFlight, 1024), h.forwardTCP)
	udpForwarder := udp.NewForwarder(s, h.forwardUDP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

	h.stack = s
	h.endpoint = ep
	h.cleanup = cleanup
	// Load's context bounds setup; returned streams live until Unload.
	h.ctx, h.cancel = context.WithCancel(context.Background())
	loaded = true
	return nil
}

func (h *TunHandler) Unload() error {
	h.once.Do(func() {
		if h.cancel != nil {
			h.cancel()
		}
		if h.cleanup != nil {
			h.cleanup()
		}
		if h.device != nil {
			h.device.Close()
		}
		if h.endpoint != nil {
			h.endpoint.Close()
		}
		if h.stack != nil {
			h.stack.Close()
		}
	})
	return nil
}

var tunPacketOffset = func() int {
	switch runtime.GOOS {
	case "windows":
		return 0
	case "darwin":
		return 4
	default:
		return 16
	}
}()

func (h *TunHandler) Serve(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Go(func() {
		batchSize := cmp.Or(h.device.BatchSize(), 1)
		bufs := make([][]byte, batchSize)
		sizes := make([]int, batchSize)
		views := make([]*buffer.View, batchSize)
		releaseViews := func() {
			for i, view := range views {
				if view != nil {
					view.Release()
					views[i] = nil
				}
			}
		}
		defer releaseViews()

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			default:
			}

			size := tunPacketOffset + cmp.Or(int(h.mtu.Load()), 1500)
			for i := range views {
				view := views[i]
				if view == nil {
					view = buffer.NewViewSize(size)
					views[i] = view
				} else if view.Capacity() < size {
					view.Release()
					view = buffer.NewViewSize(size)
					views[i] = view
				} else {
					view.Reset()
					view.Grow(size)
				}
				bufs[i] = view.AsSlice()
				sizes[i] = 0
			}

			n, err := h.device.Read(bufs, sizes, tunPacketOffset)
			if errors.Is(err, tun.ErrTooManySegments) {
				log.Warn().Err(err).Str("tun_name", h.name).Msg("tun read too many segments")
				continue
			}
			if err != nil {
				errc <- err
				return
			}

			for i := range n {
				view := views[i]
				views[i] = nil
				if sizes[i] == 0 {
					view.Release()
					continue
				}
				if tunPacketOffset+sizes[i] > view.Size() {
					log.Debug().Str("tun_name", h.name).Int("packet_size", sizes[i]).Int("buffer_size", view.Size()-tunPacketOffset).Msg("tun drop oversized packet")
					view.Release()
					continue
				}
				packet := view.AsSlice()[tunPacketOffset : tunPacketOffset+sizes[i]]
				var network tcpip.NetworkProtocolNumber
				switch packet[0] >> 4 {
				case 4:
					network = header.IPv4ProtocolNumber
				case 6:
					network = header.IPv6ProtocolNumber
				default:
					log.Debug().Str("tun_name", h.name).Int("packet_size", len(packet)).Msg("tun drop unknown ip packet")
					view.Release()
					continue
				}
				view.CapLength(tunPacketOffset + sizes[i])
				view.TrimFront(tunPacketOffset)
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithView(view),
				})
				pkt.NetworkProtocolNumber = network
				pkt.RXChecksumValidated = true
				h.endpoint.InjectInbound(network, pkt)
				pkt.DecRef()
			}
		}
	})
	wg.Go(func() {
		batchSize := cmp.Or(h.device.BatchSize(), 1)
		pkts := make([]*stack.PacketBuffer, 0, batchSize)
		bufs := make([][]byte, 0, batchSize)
		copyBufs := make([][]byte, 0, batchSize)
		writePkts := make([]*stack.PacketBuffer, 0, batchSize)
		for {
			pkt := h.endpoint.ReadContext(ctx)
			if pkt == nil {
				errc <- ctx.Err()
				return
			}

			pkts = append(pkts[:0], pkt)
			for len(pkts) < batchSize {
				pkt = h.endpoint.Read()
				if pkt == nil {
					break
				}
				pkts = append(pkts, pkt)
			}

			bufs = bufs[:0]
			copyBufs = copyBufs[:0]
			writePkts = writePkts[:0]
			for _, pkt := range pkts {
				pktSize := pkt.Size()
				if pktSize == 0 {
					pkt.DecRef()
					continue
				}
				if buf, ok := tunPacketHeadroomSlice(pkt, pktSize); ok {
					bufs = append(bufs, buf)
				} else {
					buf := tunGetCopyBuffer(tunPacketOffset + pktSize)
					n := tunPacketOffset + tunCopyPacket(buf[tunPacketOffset:tunPacketOffset+pktSize], pkt)
					bufs = append(bufs, buf[:n])
					copyBufs = append(copyBufs, buf)
				}
				writePkts = append(writePkts, pkt)
			}
			if len(bufs) == 0 {
				continue
			}
			_, err := h.device.Write(bufs, tunPacketOffset)
			for _, pkt := range writePkts {
				pkt.DecRef()
			}
			for _, buf := range copyBufs {
				tunPutCopyBuffer(buf)
			}
			if err != nil {
				errc <- err
				return
			}
		}
	})
	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-h.device.Events():
				if !ok {
					return
				}
				if event&tun.EventUp != 0 {
					log.Info().Str("tun_name", h.name).Msg("tun device up")
				}
				if event&tun.EventDown != 0 {
					log.Info().Str("tun_name", h.name).Msg("tun device down")
				}
				if event&tun.EventMTUUpdate != 0 {
					mtu, err := h.device.MTU()
					if err != nil {
						log.Error().Err(err).Str("tun_name", h.name).Msg("tun mtu update error")
						continue
					}
					if mtu > 0 {
						h.mtu.Store(int64(mtu))
						h.endpoint.SetMTU(uint32(mtu))
					}
					log.Info().Str("tun_name", h.name).Int("tun_mtu", mtu).Msg("tun mtu updated")
				}
			}
		}
	})

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, context.Canceled) {
			log.Error().Err(err).Str("tun_name", h.name).Msg("tun handler stopped")
		}
	}

	cancel()
	h.Unload()
	wg.Wait()
	if h.stack != nil {
		h.stack.Wait()
	}
}

func (h *TunHandler) forwardTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	serverIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	var tcpTimeout time.Duration
	if timeout := cmp.Or(h.Config.Forward.TcpTimeout, 600); timeout > 0 {
		tcpTimeout = time.Duration(timeout) * time.Second
	}
	req := TunRequest{
		TunName:    h.name,
		Network:    "tcp",
		RemoteAddr: netip.AddrPortFrom(remoteIP, id.RemotePort),
		ServerAddr: netip.AddrPortFrom(serverIP, id.LocalPort),
		Host:       serverIP.String(),
		Port:       id.LocalPort,
		TraceID:    log.NewXID(),
	}
	var (
		wq           waiter.Queue
		lconn        net.Conn
		completed    bool
		localConnErr error
		stopLocal    func() bool
	)
	defer func() {
		if stopLocal != nil {
			stopLocal()
		}
		if lconn != nil {
			lconn.Close()
		}
	}()

	ensureLocalConn := func() (net.Conn, error) {
		if lconn != nil {
			return lconn, nil
		}
		if completed {
			if localConnErr != nil {
				return nil, localConnErr
			}
			return nil, errors.New("tun tcp forwarder request already completed")
		}
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("error", tcpipErr.String()).Msg("tun tcp create endpoint error")
			r.Complete(true)
			completed = true
			localConnErr = fmt.Errorf("create tun tcp endpoint: %s", tcpipErr.String())
			return nil, localConnErr
		}
		r.Complete(false)
		completed = true
		conn := gonet.NewTCPConn(&wq, ep)
		lconn = conn
		stopLocal = context.AfterFunc(cmp.Or(h.ctx, context.Background()), func() { conn.Close() })
		if tcpTimeout > 0 {
			_ = lconn.SetDeadline(time.Now().Add(tcpTimeout))
		}
		return lconn, nil
	}

	addr := req.ServerAddr.Addr()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4() && addr.As4() == [4]byte{255, 255, 255, 255} {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun local request")
		r.Complete(true)
		return
	}
	if req.Port == 53 && h.DnsResolver != nil && h.DnsResolver.Client != nil {
		if _, err := ensureLocalConn(); err != nil {
			return
		}
		h.serveTCPDNS(req, lconn)
		return
	}

	if h.Config.DisableIpv6 && req.ServerAddr.Addr().Is6() {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun ipv6 request")
		r.Complete(true)
		return
	}
	if h.address.Contains(addr) {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun local request")
		r.Complete(true)
		return
	}

	var (
		clientHelloOnce sync.Once
		clientHello     *tls.ClientHelloInfo
		clientHelloErr  error
	)
	req.TLSClientHello = func() (*tls.ClientHelloInfo, error) {
		clientHelloOnce.Do(func() {
			c, err := ensureLocalConn()
			if err != nil {
				clientHelloErr = err
				return
			}
			// server-first protocols (smtp, ftp, mysql) never send, so bound the peek
			_ = c.SetReadDeadline(time.Now().Add(time.Second))
			data := make([]byte, 0, 2048)
			for {
				n, err := c.Read(data[len(data):cap(data)])
				data = data[:len(data)+n]
				if err != nil {
					if !errors.Is(err, io.EOF) && !errors.Is(err, os.ErrDeadlineExceeded) {
						log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Msg("failed to peek data from tun tcp connection")
						clientHelloErr = err
					}
					break
				}
				// read the whole tls record, post-quantum client hellos often exceed one segment
				if len(data) < 5 || data[0] != 0x16 || data[1] != 0x03 {
					break
				}
				size := 5 + (int(data[3])<<8 | int(data[4]))
				if len(data) >= size || size > 5+16384 {
					break
				}
				if cap(data) < size {
					data = slices.Grow(data, size-len(data))
				}
			}
			if tcpTimeout > 0 {
				_ = c.SetReadDeadline(time.Now().Add(tcpTimeout))
			} else {
				_ = c.SetReadDeadline(time.Time{})
			}
			if len(data) > 0 {
				lconn = &ConnWithData{Conn: c, Data: data}
			}
			if clientHelloErr == nil && len(data) > 40 && data[0] == 0x16 && data[1] == 0x03 {
				clientHello = tunParseClientHello(data)
				if clientHello == nil {
					log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Msg("parse tls client hello failed")
				}
			}
		})
		return clientHello, clientHelloErr
	}

	var (
		processInfoOnce sync.Once
		processInfo     *ConnProcessInfo
	)
	req.ProcessInfo = func() (*ConnProcessInfo, error) {
		processInfoOnce.Do(func() {
			c, err := ensureLocalConn()
			if err != nil {
				return
			}
			info, err := GetTCPConnProcessInfo(c)
			if err == nil {
				processInfo = &info
			}
		})
		return processInfo, nil
	}

	ctx, dialer, dialerName, ok := h.prepareDial(&req)
	if !ok {
		if !completed {
			r.Complete(true)
		}
		return
	}
	if localConnErr != nil {
		return
	}

	dialCtx, dialCancel := h.forwardDialContext(ctx)
	rconn, err := dialer.DialContext(dialCtx, "tcp", req.ServerAddr.String())
	dialCancel()
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", dialerName).Msg("tun tcp dial error")
		if !completed {
			r.Complete(true)
		}
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()
	stopRemote := context.AfterFunc(ctx, func() { rconn.Close() })
	defer stopRemote()

	if _, err = ensureLocalConn(); err != nil {
		return
	}
	if tcpTimeout > 0 {
		_ = lconn.SetDeadline(time.Time{})
	}

	h.logForward(req, dialerName)

	touch, stop := tunStartIdleTimer(tcpTimeout, lconn, rconn)
	defer stop()

	tunRelayTCP(lconn, rconn, touch)

	h.logData(context.Background(), req, dialerName)
}

func (h *TunHandler) forwardUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	serverIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	req := TunRequest{
		TunName:    h.name,
		Network:    "udp",
		RemoteAddr: netip.AddrPortFrom(remoteIP, id.RemotePort),
		ServerAddr: netip.AddrPortFrom(serverIP, id.LocalPort),
		Host:       serverIP.String(),
		Port:       id.LocalPort,
		TraceID:    log.NewXID(),
	}
	addr := req.ServerAddr.Addr()
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsMulticast() || addr.Is4() && addr.As4() == [4]byte{255, 255, 255, 255} {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun local request")
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		} else {
			ep.Close()
		}
		return false
	}
	if req.Port == 53 && h.DnsResolver != nil && h.DnsResolver.Client != nil {
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
			return false
		}
		lconn := gonet.NewUDPConn(&wq, ep)
		go h.serveUDP(req, lconn)
		return true
	}
	if h.Config.DisableUdp {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun udp request")
		return false
	}
	if h.Config.DisableIpv6 && req.ServerAddr.Addr().Is6() {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun ipv6 request")
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		} else {
			ep.Close()
		}
		return false
	}
	if h.address.Contains(addr) {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun local request")
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		} else {
			ep.Close()
		}
		return false
	}

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		return false
	}
	lconn := gonet.NewUDPConn(&wq, ep)

	go h.serveUDP(req, lconn)
	return true
}

func (h *TunHandler) serveUDP(req TunRequest, lconn net.Conn) {
	defer lconn.Close()
	stopLocal := context.AfterFunc(cmp.Or(h.ctx, context.Background()), func() { lconn.Close() })
	defer stopLocal()

	var (
		processInfoOnce sync.Once
		processInfo     *ConnProcessInfo
	)
	req.ProcessInfo = func() (*ConnProcessInfo, error) {
		processInfoOnce.Do(func() {
			info, err := GetUDPConnProcessInfo(lconn)
			if err == nil {
				processInfo = &info
			}
		})
		return processInfo, nil
	}

	if req.Port == 53 && h.DnsResolver != nil && h.DnsResolver.Client != nil {
		client := h.DnsResolver.Client
		h.logForward(req, client.Addr)
		defer h.logData(context.Background(), req, client.Addr)

		buf := tunGetCopyBuffer(tunCopyBufferSize)
		defer tunPutCopyBuffer(buf)
		timeout := time.Duration(cmp.Or(h.Config.Forward.UdpTimeout, 120)) * time.Second
		for {
			if timeout > 0 {
				_ = lconn.SetReadDeadline(time.Now().Add(timeout))
			}
			n, err := lconn.Read(buf)
			if err != nil {
				return
			}
			n, err = h.exchangeTunDNS(req, buf[:n], buf)
			if err != nil {
				return
			}
			if _, err = lconn.Write(buf[:n]); err != nil {
				return
			}
		}
	}

	var (
		clientHelloOnce sync.Once
		clientHello     *tls.ClientHelloInfo
		sniffBuf        []byte
		sniffed         [][]byte
	)
	defer func() {
		if sniffBuf != nil {
			tunPutCopyBuffer(sniffBuf)
		}
	}()
	req.TLSClientHello = func() (*tls.ClientHelloInfo, error) {
		clientHelloOnce.Do(func() {
			sniffBuf = tunGetCopyBuffer(tunCopyBufferSize)
			clientHello, sniffed = h.sniffQUICClientHello(lconn, sniffBuf)
		})
		return clientHello, nil
	}

	ctx, dialer, dialerName, ok := h.prepareDial(&req)
	if !ok {
		return
	}

	dialCtx, dialCancel := h.forwardDialContext(ctx)
	rconn, err := dialer.DialContext(dialCtx, "udp", req.ServerAddr.String())
	dialCancel()
	if err != nil {
		if !errors.Is(err, errors.ErrUnsupported) {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", dialerName).Msg("tun udp dial error")
		}
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	for _, b := range sniffed {
		if _, err = rconn.Write(b); err != nil {
			return
		}
	}

	h.logForward(req, dialerName)

	timeout := time.Duration(cmp.Or(h.Config.Forward.UdpTimeout, 120)) * time.Second
	done := make(chan struct{}, 2)
	touch, stop := tunStartIdleTimer(timeout, lconn, rconn)
	defer stop()

	copyPacket := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := tunGetCopyBuffer(cmp.Or(int(h.mtu.Load()), 1500))
		defer tunPutCopyBuffer(buf)
		for {
			n, err := src.Read(buf)
			if err != nil {
				return
			}
			if n == 0 {
				continue
			}
			if _, err = dst.Write(buf[:n]); err != nil {
				return
			}
			touch()
		}
	}

	go copyPacket(rconn, lconn)
	go copyPacket(lconn, rconn)
	<-done
	lconn.Close()
	rconn.Close()
	<-done

	h.logData(context.Background(), req, dialerName)
}

func (h *TunHandler) serveTCPDNS(req TunRequest, lconn net.Conn) {
	client := h.DnsResolver.Client
	h.logForward(req, client.Addr)
	defer h.logData(context.Background(), req, client.Addr)

	buf := tunGetCopyBuffer(tunCopyBufferSize)
	defer tunPutCopyBuffer(buf)
	resp := tunGetCopyBuffer(tunCopyBufferSize)
	defer tunPutCopyBuffer(resp)
	var header [2]byte
	timeout := time.Duration(cmp.Or(h.Config.Forward.UdpTimeout, 120)) * time.Second
	for {
		if timeout > 0 {
			_ = lconn.SetReadDeadline(time.Now().Add(timeout))
		}
		if _, err := io.ReadFull(lconn, header[:]); err != nil {
			return
		}
		n := int(header[0])<<8 | int(header[1])
		if n == 0 {
			continue
		}
		if n > len(buf) {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Int("dns_query_size", n).Msg("tun dns query too large")
			return
		}
		if _, err := io.ReadFull(lconn, buf[:n]); err != nil {
			return
		}
		n, err := h.exchangeTunDNS(req, buf[:n], resp)
		if err != nil {
			return
		}
		header[0], header[1] = byte(n>>8), byte(n)
		if _, err = lconn.Write(header[:]); err != nil {
			return
		}
		if _, err = lconn.Write(resp[:n]); err != nil {
			return
		}
	}
}

func (h *TunHandler) exchangeTunDNS(req TunRequest, query, response []byte) (int, error) {
	if h.Config.DisableIpv6 {
		var msg fastdns.Message
		msg.Raw = query
		if err := fastdns.ParseMessage(&msg, query, false); err == nil && msg.Question.Type == fastdns.TypeAAAA {
			msg.SetResponseHeader(fastdns.RcodeNoError, 0)
			return copy(response, msg.Raw), nil
		}
	}

	client := h.DnsResolver.Client
	ctx := context.Background()
	cancel := func() {}
	if h.Config.Forward.DialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.Forward.DialTimeout)*time.Second)
	}
	defer cancel()

	var (
		rconn net.Conn
		err   error
	)
	if client.Dialer != nil {
		rconn, err = client.Dialer.DialContext(ctx, "udp", client.Addr)
	} else {
		rconn, err = (&net.Dialer{}).DialContext(ctx, "udp", client.Addr)
	}
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns dial error")
		return 0, err
	}
	put := func() {
		_ = rconn.SetDeadline(time.Time{})
		if d, _ := client.Dialer.(interface{ Put(net.Conn) }); d != nil {
			d.Put(rconn)
		} else {
			rconn.Close()
		}
	}
	if client.Timeout > 0 {
		_ = rconn.SetDeadline(time.Now().Add(client.Timeout))
	}
	if _, err = rconn.Write(query); err != nil {
		put()
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns write error")
		return 0, err
	}
	n, err := rconn.Read(response)
	put()
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns read error")
		return 0, err
	}
	return n, nil
}

const tunCopyBufferSize = 64 * 1024

var tunCopyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, tunCopyBufferSize)
		return &b
	},
}

func tunGetCopyBuffer(size int) []byte {
	if size <= 0 {
		size = tunCopyBufferSize
	}
	p := tunCopyBufferPool.Get().(*[]byte)
	b := *p
	if cap(b) < size {
		tunCopyBufferPool.Put(p)
		return make([]byte, size)
	}
	return b[:size]
}

func tunRelayTCP(lconn, rconn net.Conn, touch func()) {
	copyConn := func(dst, src net.Conn) {
		if err := tunCopyConnWithActivity(dst, src, touch); errors.Is(err, io.EOF) {
			if c, ok := dst.(interface{ CloseWrite() error }); ok && c.CloseWrite() == nil {
				return
			}
		}
		lconn.Close()
		rconn.Close()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		copyConn(rconn, lconn)
	}()
	copyConn(lconn, rconn)
	<-done
}

func tunCopyConnWithActivity(dst, src net.Conn, touch func()) error {
	buf := tunGetCopyBuffer(tunCopyBufferSize)
	defer tunPutCopyBuffer(buf)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			touch()
			if nw, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			} else if nw != n {
				return io.ErrShortWrite
			}
			touch()
		}
		if err != nil {
			return err
		}
	}
}

func tunStartIdleTimer(timeout time.Duration, conns ...net.Conn) (func(), func()) {
	if timeout <= 0 {
		return func() {}, func() {}
	}
	var mu sync.Mutex
	var stopped bool
	var lastTouch atomic.Int64
	start := time.Now()
	var timer *time.Timer
	mu.Lock()
	timer = time.AfterFunc(timeout, func() {
		mu.Lock()
		defer mu.Unlock()
		if stopped {
			return
		}
		if remaining := timeout - (time.Since(start) - time.Duration(lastTouch.Load())); remaining > 0 {
			timer.Reset(remaining)
			return
		}
		stopped = true
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	mu.Unlock()
	touch := func() {
		now := time.Since(start).Nanoseconds()
		for last := lastTouch.Load(); now > last; last = lastTouch.Load() {
			if lastTouch.CompareAndSwap(last, now) {
				break
			}
		}
	}
	stop := func() {
		mu.Lock()
		stopped = true
		timer.Stop()
		mu.Unlock()
	}
	return touch, stop
}

func tunPacketHeadroomSlice(pkt *stack.PacketBuffer, pktSize int) ([]byte, bool) {
	views, offset := pkt.AsViewList()
	for v := views.Front(); v != nil; v = v.Next() {
		s := v.AsSlice()
		if offset >= len(s) {
			offset -= len(s)
			continue
		}
		if offset < tunPacketOffset || len(s)-offset < pktSize {
			return nil, false
		}
		return s[offset-tunPacketOffset : offset+pktSize], true
	}
	return nil, false
}

func tunCopyPacket(dst []byte, pkt *stack.PacketBuffer) int {
	views, offset := pkt.AsViewList()
	n := 0
	for v := views.Front(); v != nil; v = v.Next() {
		s := v.AsSlice()
		if offset >= len(s) {
			offset -= len(s)
			continue
		}
		if offset > 0 {
			s = s[offset:]
			offset = 0
		}
		n += copy(dst[n:], s)
	}
	return n
}

func tunPutCopyBuffer(b []byte) {
	if cap(b) > 1024*1024 {
		return
	}
	b = b[:cap(b)]
	tunCopyBufferPool.Put(&b)
}

func (h *TunHandler) parseForwardDialer(dialerValue string) (Dialer, string, bool, bool, error) {
	dialerName := dialerValue
	// disableIPv6 := cmp.Or(h.Config.Forward.DisableIpv6, h.Config.DisableIpv6)
	disableIPv6 := h.Config.Forward.DisableIpv6
	preferIPv6 := h.Config.Forward.PreferIpv6
	switch {
	case strings.HasPrefix(dialerValue, "{\""):
		var v struct {
			Dialer      string `json:"dialer"`
			DisableIPv6 bool   `json:"disable_ipv6"`
			PreferIPv6  bool   `json:"prefer_ipv6"`
		}
		err := json.Unmarshal([]byte(dialerValue), &v)
		if err != nil {
			return nil, dialerName, disableIPv6, preferIPv6, fmt.Errorf("parse tun_dialer json: %w", err)
		}
		dialerName = v.Dialer
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			return nil, dialerName, disableIPv6, preferIPv6, fmt.Errorf("parse tun_dialer query: %w", err)
		}
		dialerName = u.Get("dialer")
		if s := u.Get("disable_ipv6"); s != "" {
			disableIPv6, _ = strconv.ParseBool(s)
		}
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}
	var dialer Dialer
	switch dialerName {
	case "", "direct", "local":
		dialer = h.LocalDialer
	default:
		dialer = h.Dialers[dialerName]
		if dialer == nil {
			return nil, dialerName, disableIPv6, preferIPv6, fmt.Errorf("dialer %q not exists", dialerName)
		}
	}
	return dialer, dialerName, disableIPv6, preferIPv6, nil
}

func (h *TunHandler) prepareDial(req *TunRequest) (context.Context, Dialer, string, bool) {
	if addr := req.ServerAddr.Addr(); IsReservedIP(addr) && !IsMemoryAddress(addr) {
		ctx := cmp.Or(h.ctx, context.Background())
		switch {
		case h.static.DisableIPv6:
			ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, struct{}{})
		case h.static.PreferIPv6:
			ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
		}
		return ctx, h.LocalDialer, "direct", true
	}

	dialer := h.static.Dialer
	dialerName := h.static.DialerName
	disableIPv6 := h.static.DisableIPv6
	preferIPv6 := h.static.PreferIPv6

	if req.TLSClientHello == nil {
		req.TLSClientHello = func() (*tls.ClientHelloInfo, error) { return nil, nil }
	}
	if req.ProcessInfo == nil {
		req.ProcessInfo = func() (*ConnProcessInfo, error) { return nil, nil }
	}
	matched := false
	if len(h.processDialers) > 0 {
		if info, err := req.ProcessInfo(); err == nil && info != nil && info.Path != "" {
			for _, pd := range h.processDialers {
				if (pd.path != nil && pd.path.MatchString(info.Path)) || (pd.name != nil && pd.name.MatchString(info.Name)) {
					dialer = pd.dialer
					dialerName = pd.dialerName
					disableIPv6 = pd.disableIPv6
					preferIPv6 = pd.preferIPv6
					matched = true
					break
				}
			}
		}
	}
	if !matched && len(h.domainDialers) > 0 {
		if hello, err := req.TLSClientHello(); err == nil && hello != nil && hello.ServerName != "" {
			req.ServerName = hello.ServerName
			serverName := strings.ToLower(hello.ServerName)
			for _, dd := range h.domainDialers {
				if dd.domain.MatchString(serverName) {
					dialer = dd.dialer
					dialerName = dd.dialerName
					disableIPv6 = dd.disableIPv6
					preferIPv6 = dd.preferIPv6
					matched = true
					break
				}
			}
		}
	}
	if !matched && h.dialer != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = h.dialer.Execute(bb, map[string]any{
				"Request":        *req,
				"ServerAddr":     req.ServerAddr,
				"TLSClientHello": req.TLSClientHello,
				"ProcessInfo":    req.ProcessInfo,
			})
		} else {
			err = h.dialer.Execute(bb, struct {
				Request        TunRequest
				ServerAddr     netip.AddrPort
				TLSClientHello func() (*tls.ClientHelloInfo, error)
				ProcessInfo    func() (*ConnProcessInfo, error)
			}{
				Request:        *req,
				ServerAddr:     req.ServerAddr,
				TLSClientHello: req.TLSClientHello,
				ProcessInfo:    req.ProcessInfo,
			})
		}
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute tun_dialer error")
			return nil, nil, "", false
		}
		var parseErr error
		dialer, dialerName, disableIPv6, preferIPv6, parseErr = h.parseForwardDialer(strings.TrimSpace(bb.String()))
		if parseErr != nil {
			log.Error().Err(parseErr).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tun_dialer error")
			return nil, nil, "", false
		}
	}

	ctx := cmp.Or(h.ctx, context.Background())
	switch {
	case disableIPv6:
		ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
	}
	// ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
	// 	"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	// })

	return ctx, dialer, dialerName, true
}

func (h *TunHandler) forwardDialContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if h.Config.Forward.DialTimeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, time.Duration(h.Config.Forward.DialTimeout)*time.Second)
}

func (h *TunHandler) logForward(req TunRequest, dialerName string) {
	e := log.Debug()
	if h.Config.Forward.Log {
		e = log.Info()
	}
	e.Xid("trace_id", req.TraceID).
		Str("tun_name", h.name).
		Str("tun_network", req.Network).
		NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
		NetIPAddrPort("req_hostport", req.ServerAddr).
		Str("tun_host", req.Host).
		Uint16("tun_port", req.Port).
		Str("tun_server_name", req.ServerName).
		Str("forward_dialer_name", dialerName).
		Msg("forward tun request")
}

func (h *TunHandler) logData(ctx context.Context, req TunRequest, dialerName string) {
	if !h.Config.Forward.Log {
		return
	}

	var info GeoIPInfo
	if h.GeoResolver != nil && h.GeoResolver.CityReader != nil {
		info = h.GeoResolver.GetGeoIPInfo(ctx, req.RemoteAddr.Addr())
	}
	h.DataLogger.Log().
		Str("logger", "tun").
		Xid("trace_id", req.TraceID).
		Str("tun_name", h.name).
		Str("tun_network", req.Network).
		NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
		Str("remote_country", info.Country).
		Str("remote_city", info.City).
		Str("remote_isp", info.ISP).
		Str("remote_connection_type", info.ConnectionType).
		Str("tun_host", req.Host).
		Uint16("tun_port", req.Port).
		Str("tun_server_name", req.ServerName).
		Str("forward_dialer_name", dialerName).
		Msg("")
}

func tunParseClientHello(record []byte) (hello *tls.ClientHelloInfo) {
	_ = tls.Server(&ConnWithData{Data: record}, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			hello = chi
			return nil, nil
		},
	}).HandshakeContext(context.Background())
	return
}

// QUIC v1 initial salt, see RFC 9001 section 5.2
var tunQUICInitialSalt = []byte{0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a}

func tunHKDFExpandLabel(secret []byte, label string, length int) []byte {
	info := make([]byte, 0, 4+len("tls13 ")+len(label))
	info = append(info, byte(length>>8), byte(length), byte(len("tls13 ")+len(label)))
	info = append(info, "tls13 "...)
	info = append(info, label...)
	info = append(info, 0)
	return must(hkdf.Expand(sha256.New, secret, b2s(info), length))
}

// sniffQUICClientHello decrypts QUIC v1 Initial packets (RFC 9001 section 5) until the
// CRYPTO stream holds a whole ClientHello. Read datagrams are returned for replay.
// Post-quantum client hellos span 2+ Initial packets and chrome shuffles CRYPTO frames.
func (h *TunHandler) sniffQUICClientHello(conn net.Conn, buf []byte) (*tls.ClientHelloInfo, [][]byte) {
	defer conn.SetReadDeadline(time.Time{})

	var (
		datagrams [][]byte
		dcid      []byte
		aead      cipher.AEAD
		iv        []byte
		hp        cipher.Block
		pkt       []byte
		crypto    []byte
		ranges    [][2]int
		off       int
	)
	mtu := cmp.Or(int(h.mtu.Load()), 1500)
	for range 4 {
		if len(buf)-off < mtu {
			break
		}
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(buf[off:])
		if err != nil {
			break
		}
		p := buf[off : off+n]
		off += n
		datagrams = append(datagrams, p)

		// coalesced packets
		for len(p) > 0 {
			// long header, fixed bit, Initial type, version 1
			if len(p) < 7 || p[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(p[1:5]) != 1 {
				if aead == nil {
					return nil, datagrams
				}
				break // coalesced 0-RTT or trailing padding
			}
			i := 6 + int(p[5])
			if p[5] > 20 || i >= len(p) {
				return nil, datagrams
			}
			if aead == nil {
				dcid = p[6:i]
				secret := tunHKDFExpandLabel(must(hkdf.Extract(sha256.New, dcid, tunQUICInitialSalt)), "client in", sha256.Size)
				aead = must(cipher.NewGCM(must(aes.NewCipher(tunHKDFExpandLabel(secret, "quic key", 16)))))
				iv = tunHKDFExpandLabel(secret, "quic iv", 12)
				hp = must(aes.NewCipher(tunHKDFExpandLabel(secret, "quic hp", 16)))
			} else if !bytes.Equal(dcid, p[6:i]) {
				return nil, datagrams
			}
			i += 1 + int(p[i])
			if i >= len(p) {
				return nil, datagrams
			}
			token, n, err := quicvarint.Parse(p[i:])
			if err != nil || token > uint64(len(p)) {
				return nil, datagrams
			}
			i += n + int(token)
			if i >= len(p) {
				return nil, datagrams
			}
			length, n, err := quicvarint.Parse(p[i:])
			if err != nil || length > uint64(len(p)-i-n) || length < 20 {
				return nil, datagrams
			}
			i += n
			// work on a copy, the datagram is replayed untouched
			pkt = append(pkt[:0], p[:i+int(length)]...)
			p = p[i+int(length):]

			var mask [aes.BlockSize]byte
			hp.Encrypt(mask[:], pkt[i+4:i+4+aes.BlockSize])
			pkt[0] ^= mask[0] & 0x0f
			pnlen := int(pkt[0]&0x03) + 1
			var nonce [12]byte
			copy(nonce[:], iv)
			// the first Initial packet numbers are small, so the truncated number is the full one
			for j := range pnlen {
				pkt[i+j] ^= mask[1+j]
				nonce[12-pnlen+j] ^= pkt[i+j]
			}
			i += pnlen
			payload, err := aead.Open(pkt[i:i], nonce[:], pkt[i:], pkt[:i])
			if err != nil {
				return nil, datagrams
			}

		frames:
			for len(payload) > 0 {
				switch payload[0] {
				case 0x00, 0x01: // PADDING, PING
					payload = payload[1:]
				case 0x06: // CRYPTO
					offset, n1, err1 := quicvarint.Parse(payload[1:])
					if err1 != nil {
						return nil, datagrams
					}
					size, n2, err2 := quicvarint.Parse(payload[1+n1:])
					if err2 != nil || size > uint64(len(payload)-1-n1-n2) || offset+size > 4+16384 {
						return nil, datagrams
					}
					payload = payload[1+n1+n2:]
					if end := int(offset + size); end > len(crypto) {
						crypto = append(crypto, make([]byte, end-len(crypto))...)
					}
					copy(crypto[offset:], payload[:size])
					ranges = append(ranges, [2]int{int(offset), int(offset + size)})
					payload = payload[size:]
				default:
					break frames
				}
			}
		}

		slices.SortFunc(ranges, func(a, b [2]int) int { return a[0] - b[0] })
		end := 0
		for _, r := range ranges {
			if r[0] > end {
				break
			}
			end = max(end, r[1])
		}
		if end < 4 {
			continue
		}
		if crypto[0] != 0x01 { // ClientHello
			return nil, datagrams
		}
		size := 4 + (int(crypto[1])<<16 | int(crypto[2])<<8 | int(crypto[3]))
		if size > 16384 {
			return nil, datagrams
		}
		if end < size {
			continue
		}
		record := make([]byte, 5+size)
		record[0], record[1], record[2], record[3], record[4] = 0x16, 0x03, 0x01, byte(size>>8), byte(size)
		copy(record[5:], crypto[:size])
		return tunParseClientHello(record), datagrams
	}
	return nil, datagrams
}

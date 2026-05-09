package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
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
	TLSClientHello func() (*tls.ClientHelloInfo, error)
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
	mtu      int
	cleanup  func()
	once     sync.Once

	dialer *template.Template
	static struct {
		Dialer      Dialer
		DialerName  string
		DisableIPv6 bool
		PreferIPv6  bool
	}
}

func (h *TunHandler) Load(ctx context.Context) error {
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
	}
	if h.DnsResolver == nil && h.LocalDialer != nil {
		h.DnsResolver = h.LocalDialer.DnsResolver
	}

	h.mtu = cmp.Or(h.Config.MTU, map[bool]int{false: 9000, true: 4064}[runtime.GOOS == "darwin"])
	h.device, err = tun.CreateTUN(cmp.Or(h.Config.Name, "tun%d"), h.mtu)
	if err != nil {
		return err
	}
	if h.name, err = h.device.Name(); err != nil {
		h.name = cmp.Or(h.Config.Name, "tun")
	}
	if mtu, err := h.device.MTU(); err == nil && mtu > 0 {
		h.mtu = mtu
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

	routePrefixes := make([]netip.Prefix, 0)
	bypassPrefixes := make([]netip.Prefix, 0)

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
			ips, err := resolver.LookupNetIP(ctx, "ip4", value)
			if err != nil {
				return err
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
		routePrefixes = append(routePrefixes, prefix.Masked())
	}
	if runtime.GOOS == "windows" && len(h.Config.Routes) == 0 {
		// Windows still needs a destination route for sockets bound only to the
		// TUN source address. Keep it as a high-metric /0 so normal routing wins.
		routePrefixes = append(routePrefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{}), 0))
	}
	// has default route
	if slices.ContainsFunc(h.Config.Routes, func(route string) bool { return strings.TrimSpace(route) == "0.0.0.0/0" }) {
		if h.Config.DisableIpv6 {
			for _, prefix := range []netip.Prefix{netip.MustParsePrefix("::/1"), netip.MustParsePrefix("8000::/1")} {
				if !slices.Contains(routePrefixes, prefix) {
					routePrefixes = append(routePrefixes, prefix)
				}
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
		}
	}()

	sackEnabledOpt := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sackEnabledOpt); err != nil {
		return fmt.Errorf("enable tcp sack: %s", err)
	}
	tcpBufferSize := cmp.Or(h.Config.Forward.TcpBufferSize, tcp.MaxBufferSize)
	if tcpBufferSize < tcp.MinBufferSize {
		tcpBufferSize = tcp.MinBufferSize
	}
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

	ep = channel.New(cmp.Or(h.Config.StackQueueSize, 1024), uint32(h.mtu), "")
	ep.LinkEPCapabilities = stack.CapabilityRXChecksumOffload
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
	loaded = true
	return nil
}

func (h *TunHandler) Unload() error {
	h.once.Do(func() {
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

const tunPacketOffset = 16

func (h *TunHandler) Serve(ctx context.Context) {
	errc := make(chan error, 2)
	go func() {
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

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			default:
			}

			size := tunPacketOffset + cmp.Or(h.mtu, 1500)
			for i := range views {
				view := buffer.NewViewSize(size)
				views[i] = view
				bufs[i] = view.AsSlice()
				sizes[i] = 0
			}

			n, err := h.device.Read(bufs, sizes, tunPacketOffset)
			if errors.Is(err, tun.ErrTooManySegments) {
				releaseViews()
				log.Warn().Err(err).Str("tun_name", h.name).Msg("tun read too many segments")
				continue
			}
			if err != nil {
				releaseViews()
				errc <- err
				return
			}

			for i := 0; i < n; i++ {
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
			releaseViews()
		}
	}()
	go func() {
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
	}()
	go func() {
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
						h.mtu = mtu
						h.endpoint.SetMTU(uint32(mtu))
					}
					log.Info().Str("tun_name", h.name).Int("tun_mtu", mtu).Msg("tun mtu updated")
				}
			}
		}
	}()

	select {
	case <-ctx.Done():
	case err := <-errc:
		if err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, context.Canceled) {
			log.Error().Err(err).Str("tun_name", h.name).Msg("tun handler stopped")
		}
	}

	h.Unload()
}

func (h *TunHandler) forwardTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	serverIP, _ := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	remoteIP, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	req := TunRequest{
		TunName:    h.name,
		Network:    "tcp",
		RemoteAddr: netip.AddrPortFrom(remoteIP, id.RemotePort),
		ServerAddr: netip.AddrPortFrom(serverIP, id.LocalPort),
		Host:       serverIP.String(),
		Port:       id.LocalPort,
		TraceID:    log.NewXID(),
	}
	if h.Config.DisableIpv6 && req.ServerAddr.Addr().Is6() {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun ipv6 request")
		r.Complete(true)
		return
	}

	var (
		wq        waiter.Queue
		lconn     net.Conn
		completed bool
	)
	defer func() {
		if lconn != nil {
			lconn.Close()
		}
	}()

	ensureLocalConn := func() (net.Conn, error) {
		if lconn != nil {
			return lconn, nil
		}
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("error", tcpipErr.String()).Msg("tun tcp create endpoint error")
			r.Complete(true)
			completed = true
			return nil, fmt.Errorf("create tun tcp endpoint: %s", tcpipErr.String())
		}
		r.Complete(false)
		completed = true
		lconn = gonet.NewTCPConn(&wq, ep)
		return lconn, nil
	}

	req.TLSClientHello = func() (*tls.ClientHelloInfo, error) {
		c, err := ensureLocalConn()
		if err != nil {
			return nil, err
		}
		data := make([]byte, 2048)
		n, err := c.Read(data)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debug().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Msg("failed to peek data from tun tcp connection")
				return nil, nil
			}
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Msg("failed to peek data from tun tcp connection")
			return nil, err
		}
		data = data[:n]
		lconn = &ConnWithData{Conn: c, Data: data}

		if n > 40 && data[0] == 0x16 && data[1] == 0x03 {
			var clienthello *tls.ClientHelloInfo
			err = tls.Server(&ConnWithData{Data: data}, &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					clienthello = hello
					return nil, nil
				},
			}).HandshakeContext(context.Background())
			if clienthello != nil {
				return clienthello, nil
			}
			if err != nil {
				log.Debug().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Msg("parse tls client hello failed")
			}
		}
		return nil, nil
	}

	if req.Port == 53 && h.DnsResolver != nil && h.DnsResolver.Client != nil {
		if _, err := ensureLocalConn(); err != nil {
			return
		}
		h.serveTCPDNS(req, lconn)
		return
	}

	ctx, dialer, dialerName, ok := h.prepareDial(req)
	if !ok {
		if !completed {
			r.Complete(true)
		}
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

	if _, err = ensureLocalConn(); err != nil {
		return
	}

	h.logForward(req, dialerName)

	go io.Copy(rconn, lconn)
	_, _ = io.Copy(lconn, rconn)

	h.logData(context.Background(), req, dialerName)
}

func (h *TunHandler) forwardUDP(r *udp.ForwarderRequest) {
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
	if h.Config.DisableIpv6 && req.ServerAddr.Addr().Is6() {
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Msg("reject tun ipv6 request")
		var wq waiter.Queue
		ep, tcpipErr := r.CreateEndpoint(&wq)
		if tcpipErr != nil {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		} else {
			ep.Close()
		}
		return
	}

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		return
	}
	lconn := gonet.NewUDPConn(&wq, ep)

	go h.serveUDP(req, lconn)
}

func (h *TunHandler) serveUDP(req TunRequest, lconn net.Conn) {
	defer lconn.Close()

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

	ctx, dialer, dialerName, ok := h.prepareDial(req)
	if !ok {
		return
	}

	dialCtx, dialCancel := h.forwardDialContext(ctx)
	rconn, err := dialer.DialContext(dialCtx, "udp", req.ServerAddr.String())
	dialCancel()
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", dialerName).Msg("tun udp dial error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	h.logForward(req, dialerName)

	timeout := time.Duration(cmp.Or(h.Config.Forward.UdpTimeout, 120)) * time.Second
	done := make(chan struct{}, 2)
	var timer *time.Timer
	if timeout > 0 {
		timer = time.AfterFunc(timeout, func() {
			lconn.Close()
			rconn.Close()
		})
		defer timer.Stop()
	}

	copyPacket := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := tunGetCopyBuffer(cmp.Or(h.mtu, 1500))
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
			if timer != nil {
				timer.Reset(timeout)
			}
		}
	}

	go copyPacket(rconn, lconn)
	go copyPacket(lconn, rconn)
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
	disableIPv6 := cmp.Or(h.Config.Forward.DisableIpv6, h.Config.DisableIpv6)
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

func (h *TunHandler) prepareDial(req TunRequest) (context.Context, Dialer, string, bool) {
	dialer := h.static.Dialer
	dialerName := h.static.DialerName
	disableIPv6 := h.static.DisableIPv6
	preferIPv6 := h.static.PreferIPv6

	if req.TLSClientHello == nil {
		req.TLSClientHello = func() (*tls.ClientHelloInfo, error) { return nil, nil }
	}
	if h.dialer != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = h.dialer.Execute(bb, map[string]any{
				"Request":        req,
				"ServerAddr":     req.ServerAddr,
				"TLSClientHello": req.TLSClientHello,
			})
		} else {
			err = h.dialer.Execute(bb, struct {
				Request        TunRequest
				ServerAddr     netip.AddrPort
				TLSClientHello func() (*tls.ClientHelloInfo, error)
			}{
				Request:        req,
				ServerAddr:     req.ServerAddr,
				TLSClientHello: req.TLSClientHello,
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

	ctx := context.Background()
	switch {
	case disableIPv6:
		ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
	}
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	})

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
		Str("forward_dialer_name", dialerName).
		Msg("")
}

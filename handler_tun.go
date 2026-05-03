package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

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
	TunName    string
	Network    string
	RemoteAddr netip.AddrPort
	ServerAddr netip.AddrPort
	Host       string
	Port       uint16
	TraceID    log.XID
}

type TunHandler struct {
	Config      TunConfig
	DataLogger  log.Logger
	GeoResolver *GeoResolver
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
}

func (h *TunHandler) Load() error {
	var err error

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = h.Functions.ParseTemplate("tun_dialer", s); err != nil {
			return err
		}
	}

	h.mtu = cmp.Or(h.Config.MTU, 1420)
	h.device, err = tun.CreateTUN(cmp.Or(h.Config.Name, "tun%d"), h.mtu)
	if err != nil {
		return err
	}
	loaded := false
	defer func() {
		if !loaded {
			h.device.Close()
		}
	}()
	if h.name, err = h.device.Name(); err != nil {
		h.name = cmp.Or(h.Config.Name, "tun")
	}
	if mtu, err := h.device.MTU(); err == nil && mtu > 0 {
		h.mtu = mtu
	}
	prefix, err := netip.ParsePrefix(cmp.Or(strings.TrimSpace(h.Config.Address), "198.18.0.1/15"))
	if err != nil {
		return fmt.Errorf("parse tun address: %w", err)
	}
	addressPrefix := prefix
	routePrefix := netip.Prefix{}
	route := cmp.Or(strings.TrimSpace(h.Config.Route), "none")
	if !strings.EqualFold(route, "none") {
		routePrefix, err = netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("parse tun route: %w", err)
		}
	}
	var bypassPrefixes []netip.Prefix
	autoBypass := routePrefix.IsValid() && routePrefix.Addr().Is4() && routePrefix.Bits() == 0
	if len(h.Config.RouteBypass) > 0 || autoBypass {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(cmp.Or(h.Config.Forward.DialTimeout, 10))*time.Second)
		defer cancel()
		seen := make(map[netip.Prefix]struct{})
		addBypass := func(value string) ([]netip.Addr, error) {
			value = strings.TrimSpace(value)
			if value == "" {
				return nil, nil
			}
			if u, err := url.Parse(value); err == nil && u.Host != "" {
				value = u.Host
			}
			if host, _, err := net.SplitHostPort(value); err == nil {
				value = host
			}
			value = strings.Trim(value, "[]")

			var ips []netip.Addr
			var prefixes []netip.Prefix
			switch {
			case strings.Contains(value, "/"):
				prefix, err := netip.ParsePrefix(value)
				if err != nil {
					return nil, err
				}
				prefixes = append(prefixes, prefix)
			default:
				if ip, err := netip.ParseAddr(value); err == nil {
					prefixes = append(prefixes, netip.PrefixFrom(ip, 32))
					break
				}
				if h.LocalDialer == nil || h.LocalDialer.DnsResolver == nil || h.LocalDialer.DnsResolver.Client == nil {
					return nil, errors.New("dns resolver unavailable")
				}
				var err error
				if ips, err = h.LocalDialer.DnsResolver.LookupNetIP(ctx, "ip4", value); err != nil {
					return nil, err
				}
				for _, ip := range ips {
					prefixes = append(prefixes, netip.PrefixFrom(ip, 32))
				}
			}
			for _, prefix := range prefixes {
				if !prefix.Addr().Is4() {
					return nil, errors.ErrUnsupported
				}
				prefix = prefix.Masked()
				if _, ok := seen[prefix]; ok {
					continue
				}
				seen[prefix] = struct{}{}
				bypassPrefixes = append(bypassPrefixes, prefix)
			}
			return ips, nil
		}
		for _, bypass := range h.Config.RouteBypass {
			if _, err := addBypass(bypass); err != nil {
				return fmt.Errorf("parse tun route_bypass %q: %w", bypass, err)
			}
		}
		if autoBypass {
			addHost := func(host string) []netip.Addr {
				ips, err := addBypass(host)
				if err != nil {
					log.Warn().Err(err).Str("tun_name", h.name).Str("host", host).Msg("resolve tun bypass route error")
					return nil
				}
				return ips
			}

			for _, dialer := range h.Dialers {
				for dialer != nil {
					switch d := dialer.(type) {
					case *HTTPDialer:
						host := d.Host
						for _, value := range d.Resolve {
							if value != "" {
								host = value
								break
							}
						}
						addHost(host)
						dialer = d.Dialer
					case *HTTP2Dialer:
						addHost(d.Host)
						dialer = d.Dialer
					case *HTTP3Dialer:
						if d.Resolve != "" {
							addHost(d.Resolve)
						} else if ips := addHost(d.Host); len(ips) > 0 {
							d.Resolve = ips[0].String()
						}
						dialer = nil
					case *SocksDialer:
						addHost(d.Host)
						dialer = d.Dialer
					case *SSHDialer:
						addHost(d.Host)
						dialer = d.Dialer
					default:
						dialer = nil
					}
				}
			}
			if h.LocalDialer != nil && h.LocalDialer.DnsResolver != nil && h.LocalDialer.DnsResolver.Client != nil {
				addHost(h.LocalDialer.DnsResolver.Client.Addr)
			}
		}
	}
	cleanup, err := ConfigureTunInterface(h.name, addressPrefix, routePrefix, cmp.Or(h.Config.RouteMetric, 32767), bypassPrefixes)
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
	if routePrefix.IsValid() {
		log.Info().Str("tun_name", h.name).Str("tun_route", routePrefix.String()).Msg("tun route updated")
	} else if strings.EqualFold(route, "none") {
		log.Info().Str("tun_name", h.name).Str("tun_route", "none").Msg("tun bound route updated")
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

	tcpForwarder := tcp.NewForwarder(s, 0, cmp.Or(h.Config.Forward.TcpMaxInFlight, 1024), h.forwardTCP)
	udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) { go h.serveUDP(r) })
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
		for i := range bufs {
			bufs[i] = make([]byte, 64*1024)
		}

		for {
			select {
			case <-ctx.Done():
				errc <- ctx.Err()
				return
			default:
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

			for i := 0; i < n; i++ {
				if sizes[i] == 0 {
					continue
				}
				packet := bufs[i][tunPacketOffset : tunPacketOffset+sizes[i]]
				var network tcpip.NetworkProtocolNumber
				switch packet[0] >> 4 {
				case 4:
					network = header.IPv4ProtocolNumber
				case 6:
					network = header.IPv6ProtocolNumber
				default:
					log.Debug().Str("tun_name", h.name).Int("packet_size", len(packet)).Msg("tun drop unknown ip packet")
					continue
				}
				pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
					Payload: buffer.MakeWithData(packet),
				})
				h.endpoint.InjectInbound(network, pkt)
				pkt.DecRef()
			}
		}
	}()
	go func() {
		for {
			pkt := h.endpoint.ReadContext(ctx)
			if pkt == nil {
				errc <- ctx.Err()
				return
			}

			pktSize := pkt.Size()
			if pktSize == 0 {
				pkt.DecRef()
				continue
			}

			slices := pkt.AsSlices()
			if len(slices) == 0 {
				pkt.DecRef()
				continue
			}
			buf := tunGetCopyBuffer(tunPacketOffset + pktSize)
			n := tunPacketOffset
			for _, s := range slices {
				n += copy(buf[n:], s)
			}
			_, err := h.device.Write([][]byte{buf[:n]}, tunPacketOffset)
			tunPutCopyBuffer(buf)
			pkt.DecRef()
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

	forward, ok := h.prepareDial(req)
	if !ok {
		r.Complete(true)
		return
	}

	rconn, err := forward.dialer.DialContext(forward.ctx, "tcp", req.ServerAddr.String())
	if err != nil {
		forward.cancel()
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", forward.dialerName).Msg("tun tcp dial error")
		r.Complete(true)
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer forward.cancel()

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", forward.dialerName).Str("error", tcpipErr.String()).Msg("tun tcp create endpoint error")
		r.Complete(true)
		rconn.Close()
		return
	}
	r.Complete(false)

	lconn := gonet.NewTCPConn(&wq, ep)
	defer lconn.Close()
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", forward.dialerName).Msg("forward tun request")

	go io.Copy(rconn, lconn)
	_, _ = io.Copy(lconn, rconn)

	h.logData(context.Background(), req, forward.dialerName)
}

func (h *TunHandler) serveUDP(r *udp.ForwarderRequest) {
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

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("error", tcpipErr.String()).Msg("tun udp create endpoint error")
		return
	}
	lconn := gonet.NewUDPConn(&wq, ep)
	defer lconn.Close()

	if req.Port == 53 && h.LocalDialer != nil && h.LocalDialer.DnsResolver != nil && h.LocalDialer.DnsResolver.Client != nil {
		log.Info().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", h.LocalDialer.DnsResolver.Client.Addr).Msg("forward tun request")
		defer h.logData(context.Background(), req, h.LocalDialer.DnsResolver.Client.Addr)

		client := h.LocalDialer.DnsResolver.Client
		buf := tunGetCopyBuffer(cmp.Or(h.mtu, 1500))
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
			ctx := context.Background()
			cancel := func() {}
			if h.Config.Forward.DialTimeout > 0 {
				ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.Forward.DialTimeout)*time.Second)
			}
			var rconn net.Conn
			if client.Dialer != nil {
				rconn, err = client.Dialer.DialContext(ctx, "", "")
			} else {
				rconn, err = (&net.Dialer{}).DialContext(ctx, "udp", client.Addr)
			}
			if err != nil {
				cancel()
				log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns dial error")
				return
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
			if _, err = rconn.Write(buf[:n]); err != nil {
				put()
				cancel()
				log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns write error")
				return
			}
			n, err = rconn.Read(buf)
			put()
			cancel()
			if err != nil {
				log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("dns_server", client.Addr).Msg("tun dns read error")
				return
			}
			if _, err = lconn.Write(buf[:n]); err != nil {
				return
			}
		}
	}

	forward, ok := h.prepareDial(req)
	if !ok {
		return
	}

	rconn, err := forward.dialer.DialContext(forward.ctx, "udp", req.ServerAddr.String())
	if err != nil {
		forward.cancel()
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", forward.dialerName).Msg("tun udp dial error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer forward.cancel()
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_dialer_name", forward.dialerName).Msg("forward tun request")

	timeout := time.Duration(cmp.Or(h.Config.Forward.UdpTimeout, 120)) * time.Second
	touch := make(chan struct{}, 1)
	done := make(chan struct{}, 2)
	stop := make(chan struct{})
	defer close(stop)

	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-timer.C:
					lconn.Close()
					rconn.Close()
					return
				case <-touch:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(timeout)
				}
			}
		}()
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
			select {
			case touch <- struct{}{}:
			default:
			}
		}
	}

	go copyPacket(rconn, lconn)
	go copyPacket(lconn, rconn)
	<-done

	h.logData(context.Background(), req, forward.dialerName)
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

func tunPutCopyBuffer(b []byte) {
	if cap(b) > 1024*1024 {
		return
	}
	b = b[:cap(b)]
	tunCopyBufferPool.Put(&b)
}

type tunForward struct {
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     Dialer
	dialerName string
}

func (h *TunHandler) prepareDial(req TunRequest) (tunForward, bool) {
	ctx := context.Background()
	cancel := func() {}
	if h.Config.Forward.DialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.Forward.DialTimeout)*time.Second)
	}
	forward := tunForward{ctx: ctx, cancel: cancel, dialerName: h.Config.Forward.Dialer}
	execute := func(t *template.Template) (string, error) {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = t.Execute(bb, map[string]any{
				"Request":    req,
				"ServerAddr": req.ServerAddr,
			})
		} else {
			err = t.Execute(bb, struct {
				Request    TunRequest
				ServerAddr netip.AddrPort
			}{
				Request:    req,
				ServerAddr: req.ServerAddr,
			})
		}
		return strings.TrimSpace(bb.String()), err
	}

	dialerValue := h.Config.Forward.Dialer
	if h.dialer != nil {
		if s, err := execute(h.dialer); err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute tun_dialer error")
			cancel()
			return forward, false
		} else {
			dialerValue = s
		}
	}

	forward.dialerName = dialerValue
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
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tun_dialer json error")
			cancel()
			return forward, false
		}
		forward.dialerName = v.Dialer
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tun_dialer query error")
			cancel()
			return forward, false
		}
		forward.dialerName = u.Get("dialer")
		if s := u.Get("disable_ipv6"); s != "" {
			disableIPv6, _ = strconv.ParseBool(s)
		}
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}
	if forward.dialerName == "direct" {
		forward.dialerName = ""
	}

	if forward.dialerName != "" {
		var ok bool
		if forward.dialer, ok = h.Dialers[forward.dialerName]; !ok {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", forward.dialerName).Msg("dialer not exists")
			cancel()
			return forward, false
		}
	} else {
		forward.dialer = h.LocalDialer
	}

	switch {
	case disableIPv6:
		forward.ctx = context.WithValue(forward.ctx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		forward.ctx = context.WithValue(forward.ctx, DialerPreferIPv6ContextKey, struct{}{})
	}
	forward.ctx = context.WithValue(forward.ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	})

	return forward, true
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

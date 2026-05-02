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

const (
	tunCopyBufferSize = 64 * 1024
	tunPacketOffset   = 16
)

var tunCopyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, tunCopyBufferSize)
		return &b
	},
}

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

	policy *template.Template
	dialer *template.Template
}

func (h *TunHandler) Load() error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = h.Functions.ParseTemplate("tun_policy", s); err != nil {
			return err
		}
	}

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
	route := cmp.Or(strings.TrimSpace(h.Config.Route), "0.0.0.0/0")
	if !strings.EqualFold(route, "none") {
		routePrefix, err = netip.ParsePrefix(route)
		if err != nil {
			return fmt.Errorf("parse tun route: %w", err)
		}
	}
	if err = ConfigureTunInterface(h.name, addressPrefix, routePrefix, cmp.Or(h.Config.RouteMetric, 32767)); err != nil {
		return fmt.Errorf("configure tun interface: %w", err)
	}
	log.Info().Str("tun_name", h.name).Str("tun_address", addressPrefix.String()).Msg("tun address updated")
	log.Info().Str("tun_name", h.name).Msg("tun link up")
	if routePrefix.IsValid() {
		log.Info().Str("tun_name", h.name).Str("tun_route", routePrefix.String()).Msg("tun route updated")
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
	loaded = true
	return nil
}

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

			n, err := h.device.Read(bufs, sizes, 0)
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
				packet := bufs[i][:sizes[i]]
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

	if h.device != nil {
		h.device.Close()
	}
	if h.endpoint != nil {
		h.endpoint.Close()
	}
	if h.stack != nil {
		h.stack.Close()
	}
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

	ctx, cancel, dialer, dialerName, policyName, ok := h.prepareDial(req)
	if !ok {
		r.Complete(true)
		return
	}

	rconn, err := dialer.DialContext(ctx, "tcp", req.ServerAddr.String())
	if err != nil {
		cancel()
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("tun tcp dial error")
		r.Complete(true)
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer cancel()

	var wq waiter.Queue
	ep, tcpipErr := r.CreateEndpoint(&wq)
	if tcpipErr != nil {
		log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Str("error", tcpipErr.String()).Msg("tun tcp create endpoint error")
		r.Complete(true)
		rconn.Close()
		return
	}
	r.Complete(false)

	lconn := gonet.NewTCPConn(&wq, ep)
	defer lconn.Close()
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("forward tun request")

	go func() {
		buf := tunGetCopyBuffer(tunCopyBufferSize)
		defer tunPutCopyBuffer(buf)
		_, _ = io.CopyBuffer(rconn, lconn, buf)
	}()
	buf := tunGetCopyBuffer(tunCopyBufferSize)
	_, _ = io.CopyBuffer(lconn, rconn, buf)
	tunPutCopyBuffer(buf)

	h.logData(context.Background(), req, policyName, dialerName)
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

	ctx, cancel, dialer, dialerName, policyName, ok := h.prepareDial(req)
	if !ok {
		cancel()
		return
	}

	rconn, err := dialer.DialContext(ctx, "udp", req.ServerAddr.String())
	if err != nil {
		cancel()
		log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("tun udp dial error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer cancel()
	defer rconn.Close()

	log.Info().Xid("trace_id", req.TraceID).Str("tun_name", h.name).Str("tun_network", req.Network).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tun_host", req.Host).Uint16("tun_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("forward tun request")

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

	h.logData(context.Background(), req, policyName, dialerName)
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

func (h *TunHandler) prepareDial(req TunRequest) (context.Context, context.CancelFunc, Dialer, string, string, bool) {
	ctx := context.Background()
	cancel := func() {}
	if h.Config.Forward.DialTimeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.Forward.DialTimeout)*time.Second)
	}

	policyName := h.Config.Forward.Policy
	if h.policy != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = h.policy.Execute(bb, map[string]any{
				"Request":    req,
				"ServerAddr": req.ServerAddr,
			})
		} else {
			err = h.policy.Execute(bb, struct {
				Request    TunRequest
				ServerAddr netip.AddrPort
			}{
				Request:    req,
				ServerAddr: req.ServerAddr,
			})
		}
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_policy", h.Config.Forward.Policy).Msg("execute tun_policy error")
			cancel()
			return ctx, cancel, nil, "", policyName, false
		}
		policyName = strings.TrimSpace(bb.String())
		log.Debug().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_policy_name", policyName).Msg("execute tun_policy ok")
	}

	dialerValue := h.Config.Forward.Dialer
	switch policyName {
	case "reject", "deny", "reset", "close":
		cancel()
		return ctx, cancel, nil, "", policyName, false
	case "", "direct", "allow":
	default:
		if dialerValue == "" && h.dialer == nil {
			dialerValue = policyName
		}
	}

	if h.dialer != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = h.dialer.Execute(bb, map[string]any{
				"Request":    req,
				"ServerAddr": req.ServerAddr,
			})
		} else {
			err = h.dialer.Execute(bb, struct {
				Request    TunRequest
				ServerAddr netip.AddrPort
			}{
				Request:    req,
				ServerAddr: req.ServerAddr,
			})
		}
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute tun_dialer error")
			cancel()
			return ctx, cancel, nil, "", policyName, false
		}
		dialerValue = strings.TrimSpace(bb.String())
	}

	dialerName := dialerValue
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
			return ctx, cancel, nil, "", policyName, false
		}
		dialerName = v.Dialer
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tun_dialer query error")
			cancel()
			return ctx, cancel, nil, "", policyName, false
		}
		dialerName = u.Get("dialer")
		if s := u.Get("disable_ipv6"); s != "" {
			disableIPv6, _ = strconv.ParseBool(s)
		}
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}
	if dialerName == "direct" {
		dialerName = ""
	}

	var dialer Dialer
	if dialerName != "" {
		var ok bool
		if dialer, ok = h.Dialers[dialerName]; !ok {
			log.Error().Xid("trace_id", req.TraceID).Str("tun_name", h.name).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
			cancel()
			return ctx, cancel, nil, dialerName, policyName, false
		}
	} else {
		dialer = h.LocalDialer
	}

	switch {
	case disableIPv6:
		ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
	}
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	})

	return ctx, cancel, dialer, dialerName, policyName, true
}

func (h *TunHandler) logData(ctx context.Context, req TunRequest, policyName, dialerName string) {
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
		Str("forward_policy_name", policyName).
		Str("forward_dialer_name", dialerName).
		Msg("")
}

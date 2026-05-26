package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"text/template"
	"time"

	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

type TProxyRequest struct {
	RemoteAddr netip.AddrPort
	ServerAddr netip.AddrPort
	Network    string
	Host       string
	Port       uint16
	TraceID    log.XID
}

type TProxyHandler struct {
	Config      TProxyConfig
	DataLogger  log.Logger
	DnsResolver *DnsResolver
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Functions   *Functions
	Dialers     map[string]Dialer

	dialer *template.Template
}

type tproxyUDPSession struct {
	h          *TProxyHandler
	req        TProxyRequest
	lconn      net.Conn
	rconn      net.Conn
	dialerName string
	lastActive atomic.Int64
	closed     atomic.Bool
	closeOnce  sync.Once
}

type tproxyUDPKey struct {
	remoteAddr netip.AddrPort
	serverAddr netip.AddrPort
}

func (h *TProxyHandler) Load() error {
	var err error

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = h.Functions.ParseTemplate("tproxy_dialer", s); err != nil {
			return err
		}
	}

	return nil
}

func (h *TProxyHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req TProxyRequest
	req.RemoteAddr = AddrPortFromNetAddr(conn.RemoteAddr())
	req.ServerAddr = AddrPortFromNetAddr(conn.LocalAddr())
	req.Network = "tcp"
	req.TraceID = log.NewXID()

	if (!req.ServerAddr.IsValid() || req.ServerAddr.Addr().IsUnspecified()) && conn.RemoteAddr() != nil {
		if tc, ok := conn.(*net.TCPConn); ok {
			if addrport, err := (ConnOps{tc, nil}).GetOriginalDST(); err == nil {
				req.ServerAddr = addrport
			}
		}
	}
	if !req.ServerAddr.IsValid() || req.ServerAddr.Port() == 0 {
		log.Error().Xid("trace_id", req.TraceID).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("server_addr", req.ServerAddr).Msg("invalid tproxy tcp original destination")
		return
	}
	req.Host, req.Port = req.ServerAddr.Addr().String(), req.ServerAddr.Port()

	tlsClientHello := func() (*tls.ClientHelloInfo, error) {
		data := make([]byte, 2048)
		n, err := conn.Read(data)
		if err != nil {
			if errors.Is(err, io.EOF) {
				log.Debug().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("failed to peek data from tproxy tcp connection")
				return nil, nil
			}
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("failed to peek data from tproxy tcp connection")
			return nil, err
		}
		data = data[:n]
		conn = &ConnWithData{conn, data}

		if n > 40 && data[0] == 0x16 && data[1] == 0x03 {
			var clienthello *tls.ClientHelloInfo
			err = tls.Server(&ConnWithData{nil, data}, &tls.Config{
				GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
					clienthello = hello
					return nil, nil
				},
			}).HandshakeContext(ctx)
			if clienthello != nil {
				return clienthello, nil
			}
			if err != nil {
				log.Debug().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("parse tproxy tls client hello failed")
			}
		}

		return nil, nil
	}

	dialCtx, dialer, dialerName, addrportStr, ok := h.selectDialer(ctx, req, tlsClientHello)
	if !ok {
		return
	}

	rconn, err := dialer.DialContext(dialCtx, "tcp", addrportStr)
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("req_hostport", req.ServerAddr).Str("tproxy_host", req.Host).Uint16("tproxy_port", req.Port).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dial tproxy tcp host error")
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, _ = io.Copy(conn, rconn)

	h.logData(req, dialerName)
}

func (h *TProxyHandler) ServePacket(ctx context.Context, conn *net.UDPConn) {
	defer conn.Close()

	timeout := time.Duration(h.Config.Forward.UdpTimeout) * time.Second
	if h.Config.Forward.UdpTimeout == 0 {
		timeout = 120 * time.Second
	}
	var cleanupInterval time.Duration
	if timeout > 0 {
		cleanupInterval = timeout
		if cleanupInterval > time.Minute {
			cleanupInterval = time.Minute
		}
	}

	const tproxyUDPMaxSessions = 1024

	sessions := make(map[tproxyUDPKey]*tproxyUDPSession)
	defer func() {
		for _, session := range sessions {
			session.close()
		}
	}()

	cleanup := func(now time.Time) {
		if timeout <= 0 {
			return
		}
		deadline := now.Add(-timeout).UnixNano()
		for key, session := range sessions {
			if session.closed.Load() || session.lastActive.Load() < deadline {
				session.close()
				delete(sessions, key)
			}
		}
	}
	var nextCleanup time.Time
	if cleanupInterval > 0 {
		nextCleanup = time.Now().Add(cleanupInterval)
	}

	evictSession := func() {
		var oldestKey tproxyUDPKey
		var oldestSession *tproxyUDPSession
		for key, session := range sessions {
			if session.closed.Load() {
				delete(sessions, key)
				continue
			}
			if oldestSession == nil || session.lastActive.Load() < oldestSession.lastActive.Load() {
				oldestKey = key
				oldestSession = session
			}
		}
		if oldestSession != nil && len(sessions) >= tproxyUDPMaxSessions {
			oldestSession.close()
			delete(sessions, oldestKey)
		}
	}

	buf := tproxyGetUDPBuffer(tproxyUDPBufferSize)
	defer tproxyUDPBufferPool.Put(&buf)
	var oob [256]byte
	for {
		if cleanupInterval > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(cleanupInterval))
		}
		n, oobn, _, remoteAddr, err := conn.ReadMsgUDPAddrPort(buf, oob[:])
		now := time.Now()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if cleanupInterval > 0 {
					cleanup(now)
					nextCleanup = now.Add(cleanupInterval)
				}
				continue
			}
			log.Error().Err(err).NetAddr("address", conn.LocalAddr()).Msg("read tproxy udp packet error")
			return
		}
		if timeout > 0 && !now.Before(nextCleanup) {
			cleanup(now)
			nextCleanup = now.Add(cleanupInterval)
		}
		if n == 0 {
			continue
		}

		serverAddr, err := tproxyOrigDstFromOOB(oob[:oobn])
		if err != nil {
			log.Error().Err(err).NetAddr("address", conn.LocalAddr()).NetIPAddr("remote_ip", remoteAddr.Addr()).Msg("failed to get original dst from tproxy udp packet")
			continue
		}
		if !serverAddr.IsValid() || serverAddr.Port() == 0 {
			log.Error().NetAddr("address", conn.LocalAddr()).NetIPAddr("remote_ip", remoteAddr.Addr()).NetIPAddrPort("server_addr", serverAddr).Msg("invalid tproxy udp original destination")
			continue
		}

		key := tproxyUDPKey{remoteAddr: remoteAddr, serverAddr: serverAddr}
		session := sessions[key]
		if session != nil && session.closed.Load() {
			delete(sessions, key)
			session = nil
		}
		if session == nil {
			req := TProxyRequest{
				RemoteAddr: remoteAddr,
				ServerAddr: serverAddr,
				Network:    "udp",
				Host:       serverAddr.Addr().String(),
				Port:       serverAddr.Port(),
				TraceID:    log.NewXID(),
			}
			dialCtx, dialer, dialerName, addrportStr, ok := h.selectDialer(ctx, req, nil)
			if !ok {
				continue
			}
			lconn, err := tproxyDialUDP(ctx, serverAddr, remoteAddr)
			if err != nil {
				log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_host", req.Host).Uint16("tproxy_port", req.Port).Msg("dial tproxy udp client error")
				continue
			}
			rconn, err := dialer.DialContext(dialCtx, "udp", addrportStr)
			if err != nil {
				if !errors.Is(err, errors.ErrUnsupported) {
					log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_host", req.Host).Uint16("tproxy_port", req.Port).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dial tproxy udp host error")
				}
				lconn.Close()
				if rconn != nil {
					rconn.Close()
				}
				continue
			}
			if len(sessions) >= tproxyUDPMaxSessions {
				evictSession()
			}
			session = &tproxyUDPSession{
				h:          h,
				req:        req,
				lconn:      lconn,
				rconn:      rconn,
				dialerName: dialerName,
			}
			session.lastActive.Store(now.UnixNano())
			sessions[key] = session
			go session.copyPacket(rconn, lconn)
			go session.copyPacket(lconn, rconn)
		}

		session.lastActive.Store(now.UnixNano())
		if _, err = session.rconn.Write(buf[:n]); err != nil {
			session.close()
			delete(sessions, key)
		}
	}
}

func (h *TProxyHandler) selectDialer(ctx context.Context, req TProxyRequest, tlsClientHello func() (*tls.ClientHelloInfo, error)) (context.Context, Dialer, string, string, bool) {
	if tlsClientHello == nil {
		tlsClientHello = func() (*tls.ClientHelloInfo, error) { return nil, nil }
	}

	dialerValue := h.Config.Forward.Dialer
	if h.dialer != nil {
		bb := bytebufferpool.Get()
		defer bytebufferpool.Put(bb)
		bb.Reset()
		var err error
		if obfuscated {
			err = h.dialer.Execute(bb, map[string]any{
				"Request":        req,
				"ServerAddr":     req.ServerAddr,
				"TLSClientHello": tlsClientHello,
			})
		} else {
			err = h.dialer.Execute(bb, struct {
				Request        TProxyRequest
				ServerAddr     netip.AddrPort
				TLSClientHello func() (*tls.ClientHelloInfo, error)
			}{
				Request:        req,
				ServerAddr:     req.ServerAddr,
				TLSClientHello: tlsClientHello,
			})
		}
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_network", req.Network).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute tproxy forward_dialer error")
			return nil, nil, "", "", false
		}
		dialerValue = strings.TrimSpace(bb.String())
	}

	dialerName := dialerValue
	addrportStr := req.ServerAddr.String()
	disableIPv6 := h.Config.Forward.DisableIpv6
	preferIPv6 := h.Config.Forward.PreferIpv6
	switch {
	case strings.HasPrefix(dialerValue, "{\""):
		var v struct {
			Dialer                string `json:"dialer"`
			DialerAddrPortContext string `json:"dialer-addrport-context"`
			DisableIPv6           bool   `json:"disable_ipv6"`
			PreferIPv6            bool   `json:"prefer_ipv6"`
		}
		err := json.Unmarshal([]byte(dialerValue), &v)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_network", req.Network).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tproxy forward_dialer error")
			return nil, nil, "", "", false
		}
		dialerName = v.Dialer
		if v.DialerAddrPortContext != "" {
			addrportStr = v.DialerAddrPortContext
		}
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_network", req.Network).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse tproxy forward_dialer error")
			return nil, nil, "", "", false
		}
		dialerName = u.Get("dialer")
		if s := u.Get("dialer-addrport-context"); s != "" {
			addrportStr = s
		}
		if s := u.Get("disable_ipv6"); s != "" {
			disableIPv6, _ = strconv.ParseBool(s)
		}
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}

	var dialer Dialer
	if dialerName != "" {
		var ok bool
		dialer, ok = h.Dialers[dialerName]
		if !ok {
			log.Error().Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("tproxy_network", req.Network).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
			return nil, nil, "", "", false
		}
	} else {
		dialer = h.LocalDialer
	}

	dialCtx := context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{req.RemoteAddr.Addr().String()},
	})
	switch {
	case disableIPv6:
		dialCtx = context.WithValue(dialCtx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		dialCtx = context.WithValue(dialCtx, DialerPreferIPv6ContextKey, struct{}{})
	}

	return dialCtx, dialer, dialerName, addrportStr, true
}

func (s *tproxyUDPSession) copyPacket(dst, src net.Conn) {
	buf := tproxyGetUDPBuffer(tproxyUDPBufferSize)
	defer tproxyUDPBufferPool.Put(&buf)
	for {
		n, err := src.Read(buf)
		if err != nil {
			s.close()
			return
		}
		if n == 0 {
			continue
		}
		s.lastActive.Store(time.Now().UnixNano())
		if _, err = dst.Write(buf[:n]); err != nil {
			s.close()
			return
		}
	}
}

const tproxyUDPBufferSize = 64 * 1024

var tproxyUDPBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, tproxyUDPBufferSize)
		return &b
	},
}

func tproxyGetUDPBuffer(size int) []byte {
	if size <= 0 {
		size = tproxyUDPBufferSize
	}
	p := tproxyUDPBufferPool.Get().(*[]byte)
	b := *p
	if cap(b) < size {
		tproxyUDPBufferPool.Put(p)
		return make([]byte, size)
	}
	return b[:size]
}

func (s *tproxyUDPSession) close() {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		s.lconn.Close()
		s.rconn.Close()
		s.h.logData(s.req, s.dialerName)
	})
}

func (h *TProxyHandler) logData(req TProxyRequest, dialerName string) {
	if !h.Config.Forward.Log {
		return
	}
	h.DataLogger.Log().
		Str("logger", "tproxy").
		Xid("trace_id", req.TraceID).
		NetIPAddrPort("server_addr", req.ServerAddr).
		NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
		Str("tproxy_network", req.Network).
		Str("tproxy_host", req.Host).
		Uint16("tproxy_port", req.Port).
		Str("forward_dialer_name", dialerName).
		Msg("")
}

func tproxyOrigDstFromOOB(oob []byte) (netip.AddrPort, error) {
	if runtime.GOOS != "linux" {
		return netip.AddrPort{}, errors.ErrUnsupported
	}

	const (
		linuxSOLIP             = 0
		linuxSOLIPv6           = 41
		linuxIPOrigDstAddr     = 20
		linuxIPv6OrigDstAddr   = 74
		linuxSockaddrIPv4Size  = 16
		linuxSockaddrIPv6Size  = 28
		linuxSockaddrPortStart = 2
		linuxSockaddrPortEnd   = 4
		linuxIPv4AddrStart     = 4
		linuxIPv4AddrEnd       = 8
		linuxIPv6AddrStart     = 8
		linuxIPv6AddrEnd       = 24
	)

	headerSize := 12
	if strconv.IntSize == 64 {
		headerSize = 16
	}
	dataOffset := tproxyCmsgAlign(headerSize)
	for i := 0; i+headerSize <= len(oob); {
		var (
			msgLen int
			level  int
			typ    int
		)
		if strconv.IntSize == 64 {
			msgLen = int(binary.NativeEndian.Uint64(oob[i:]))
			level = int(int32(binary.NativeEndian.Uint32(oob[i+8:])))
			typ = int(int32(binary.NativeEndian.Uint32(oob[i+12:])))
		} else {
			msgLen = int(binary.NativeEndian.Uint32(oob[i:]))
			level = int(int32(binary.NativeEndian.Uint32(oob[i+4:])))
			typ = int(int32(binary.NativeEndian.Uint32(oob[i+8:])))
		}
		if msgLen < dataOffset || i+msgLen > len(oob) {
			return netip.AddrPort{}, fmt.Errorf("invalid tproxy udp control message")
		}

		data := oob[i+dataOffset : i+msgLen]
		switch {
		case level == linuxSOLIP && typ == linuxIPOrigDstAddr:
			if len(data) < linuxSockaddrIPv4Size {
				return netip.AddrPort{}, fmt.Errorf("short tproxy ipv4 original destination")
			}
			port := binary.BigEndian.Uint16(data[linuxSockaddrPortStart:linuxSockaddrPortEnd])
			addr := netip.AddrFrom4(*(*[4]byte)(data[linuxIPv4AddrStart:linuxIPv4AddrEnd]))
			return netip.AddrPortFrom(addr, port), nil
		case level == linuxSOLIPv6 && typ == linuxIPv6OrigDstAddr:
			if len(data) < linuxSockaddrIPv6Size {
				return netip.AddrPort{}, fmt.Errorf("short tproxy ipv6 original destination")
			}
			port := binary.BigEndian.Uint16(data[linuxSockaddrPortStart:linuxSockaddrPortEnd])
			addr := netip.AddrFrom16(*(*[16]byte)(data[linuxIPv6AddrStart:linuxIPv6AddrEnd])).Unmap()
			return netip.AddrPortFrom(addr, port), nil
		}

		next := i + tproxyCmsgAlign(msgLen)
		if next <= i {
			break
		}
		i = next
	}
	return netip.AddrPort{}, fmt.Errorf("missing tproxy udp original destination")
}

func tproxyCmsgAlign(n int) int {
	wordSize := strconv.IntSize / 8
	return (n + wordSize - 1) & ^(wordSize - 1)
}

func tproxyDialUDP(ctx context.Context, localAddr, remoteAddr netip.AddrPort) (net.Conn, error) {
	localAddr = netip.AddrPortFrom(localAddr.Addr().Unmap(), localAddr.Port())
	remoteAddr = netip.AddrPortFrom(remoteAddr.Addr().Unmap(), remoteAddr.Port())
	if !localAddr.IsValid() || !remoteAddr.IsValid() {
		return nil, net.InvalidAddrError("invalid tproxy udp address")
	}
	if localAddr.Port() == 0 || remoteAddr.Port() == 0 {
		return nil, net.InvalidAddrError("empty tproxy udp port")
	}
	if localAddr.Addr().Is4() != remoteAddr.Addr().Is4() {
		return nil, net.InvalidAddrError("tproxy udp address family mismatched: " + localAddr.String() + " -> " + remoteAddr.String())
	}

	network := "udp6"
	if localAddr.Addr().Is4() {
		network = "udp4"
	}
	dialer := &net.Dialer{
		LocalAddr: net.UDPAddrFromAddrPort(localAddr),
		Control:   (&DailerController{Transparent: true}).Control,
	}
	return dialer.DialContext(ctx, network, remoteAddr.String())
}

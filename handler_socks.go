package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

const socksHandshakeTimeout = 10 * time.Second

type SocksRequest struct {
	RemoteAddr  netip.AddrPort
	ServerAddr  netip.AddrPort
	Version     SocksVersion
	ConnectType SocksCommand
	SupportAuth bool
	User        AuthUserInfo
	Host        string
	Port        int
	TraceID     log.XID
}

type SocksHandler struct {
	Config      SocksConfig
	DataLogger  log.Logger
	DnsResolver *DnsResolver
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Functions   *Functions
	Dialers     map[string]Dialer

	policy      *template.Template
	dialer      *template.Template
	userchecker AuthUserChecker
}

func (h *SocksHandler) Load(ctx context.Context) error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = h.Functions.ParseTemplate("socks_policy", s); err != nil {
			return err
		}
	}

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = h.Functions.ParseTemplate("socks_dialer", s); err != nil {
			return err
		}
	}

	if table := h.Config.Forward.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(ctx)
		if err != nil {
			log.Fatal().Err(err).Strs("socks_listens", h.Config.Listen).Str("auth_table", table).Msg("load auth_table failed")
		}
		log.Info().Strs("socks_listens", h.Config.Listen).Str("auth_table", table).Int("auth_table_size", len(records)).Msg("load auth_table ok")
		h.userchecker = &AuthUserLoadChecker{loader}
	}

	return nil
}

func (h *SocksHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req SocksRequest
	req.RemoteAddr = AddrPortFromNetAddr(conn.RemoteAddr())
	req.ServerAddr = AddrPortFromNetAddr(conn.LocalAddr())
	req.TraceID = log.NewXID()

	handshakeCtx := ctx
	var handshakeCancel context.CancelFunc
	if socksHandshakeTimeout > 0 {
		deadline := time.Now().Add(socksHandshakeTimeout)
		_ = conn.SetDeadline(deadline)
		handshakeCtx, handshakeCancel = context.WithDeadline(ctx, deadline)
		defer handshakeCancel()
	}

	var b [513]byte
	_, err := io.ReadFull(conn, b[:2])
	if err != nil {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read handshake error")
		return
	}

	req.Version = SocksVersion(b[0])
	switch req.Version {
	case VersionSocks4:
		conn.Write([]byte{0x00, byte(Socks4StatusConnectionForbidden), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_version", int(req.Version)).Msg("socks version unsupported")
		return
	case VersionSocks5:
	default:
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_version", int(req.Version)).Msg("socks version unsupported")
		return
	}

	nmethods := int(b[1])
	if nmethods == 0 {
		conn.Write([]byte{VersionSocks5, 0xff})
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks empty auth methods")
		return
	}
	_, err = io.ReadFull(conn, b[:nmethods])
	if err != nil {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read auth methods error")
		return
	}

	var supportNoAuth bool
	for i := 0; i < nmethods; i++ {
		switch b[i] {
		case Socks5AuthMethodNone:
			supportNoAuth = true
		case Socks5AuthMethodPassword:
			req.SupportAuth = true
		}
	}

	if h.userchecker != nil {
		if !req.SupportAuth {
			conn.Write([]byte{VersionSocks5, 0xff})
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks client not support auth")
			return
		}
		if _, err = conn.Write([]byte{VersionSocks5, Socks5AuthMethodPassword}); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks write auth method error")
			return
		}
		if _, err = io.ReadFull(conn, b[:2]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read auth error")
			return
		}
		if b[0] != 1 {
			conn.Write([]byte{0x01, 0x01})
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_auth_version", int(b[0])).Msg("socks auth version unsupported")
			return
		}
		ulen := int(b[1])
		if ulen == 0 {
			conn.Write([]byte{0x01, 0x01})
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks empty username")
			return
		}
		if _, err = io.ReadFull(conn, b[:ulen]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read username error")
			return
		}
		req.User.Username = string(b[:ulen])
		if _, err = io.ReadFull(conn, b[:1]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read password length error")
			return
		}
		plen := int(b[0])
		if _, err = io.ReadFull(conn, b[:plen]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read password error")
			return
		}
		req.User.Password = string(b[:plen])
		err := h.userchecker.CheckAuthUser(handshakeCtx, &req.User)
		if err != nil {
			log.Warn().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_version", int(req.Version)).Msg("auth error")
			conn.Write([]byte{0x01, 0x01})
			return
		}
		if _, err = conn.Write([]byte{0x01, 0x00}); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks write auth error")
			return
		}
	} else {
		if !supportNoAuth {
			conn.Write([]byte{VersionSocks5, 0xff})
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks client not support no-auth")
			return
		}
		if _, err = conn.Write([]byte{VersionSocks5, Socks5AuthMethodNone}); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks write auth error")
			return
		}
	}

	_, err = io.ReadFull(conn, b[:4])
	if err != nil {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read address error")
		return
	}
	if SocksVersion(b[0]) != VersionSocks5 {
		WriteSocks5Status(conn, Socks5StatusGeneralFailure)
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_version", int(b[0])).Str("forward_policy", h.Config.Forward.Policy).Msg("socks request version unsupported")
		return
	}
	if b[2] != 0 {
		WriteSocks5Status(conn, Socks5StatusGeneralFailure)
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_reserved", int(b[2])).Str("forward_policy", h.Config.Forward.Policy).Msg("socks request reserved byte invalid")
		return
	}

	req.ConnectType = SocksCommand(b[1])
	var addressType = Socks5AddressType(b[3])
	switch addressType {
	case Socks5IPv4Address:
		if _, err = io.ReadFull(conn, b[:4]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read ipv4 address error")
			return
		}
		req.Host = netip.AddrFrom4(*(*[4]byte)(b[:4])).String()
	case Socks5DomainName:
		if _, err = io.ReadFull(conn, b[:1]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read domain length error")
			return
		}
		domainLen := int(b[0])
		if domainLen == 0 {
			WriteSocks5Status(conn, Socks5StatusAddressTypeNotSupported)
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks empty domain")
			return
		}
		if _, err = io.ReadFull(conn, b[:domainLen]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read domain error")
			return
		}
		req.Host = string(b[:domainLen])
	case Socks5IPv6Address:
		if _, err = io.ReadFull(conn, b[:16]); err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read ipv6 address error")
			return
		}
		req.Host = netip.AddrFrom16(*(*[16]byte)(b[:16])).String()
	default:
		WriteSocks5Status(conn, Socks5StatusAddressTypeNotSupported)
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_address_type", int(addressType)).Str("forward_policy", h.Config.Forward.Policy).Msg("socks address type unsupported")
		return
	}
	if _, err = io.ReadFull(conn, b[:2]); err != nil {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read port error")
		return
	}
	req.Port = int(b[0])<<8 | int(b[1])
	_ = conn.SetDeadline(time.Time{})
	if handshakeCancel != nil {
		handshakeCancel()
		handshakeCancel = nil
	}

	switch req.ConnectType {
	case SocksCommandConnectTCP:
	case SocksCommandConnectUDP:
		WriteSocks5Status(conn, Socks5StatusCommandNotSupported)
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_command", int(req.ConnectType)).Str("forward_policy", h.Config.Forward.Policy).Msg("socks udp associate unsupported")
		return
	default:
		WriteSocks5Status(conn, Socks5StatusCommandNotSupported)
		log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_command", int(req.ConnectType)).Str("forward_policy", h.Config.Forward.Policy).Msg("socks command unsupported")
		return
	}

	var speedLimit int64
	if s := req.User.Attrs["speed_limit"]; s != "" {
		if n, _ := strconv.ParseInt(s, 10, 64); n > 0 {
			speedLimit = n
		}
	}

	var policyName = h.Config.Forward.Policy
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
				Request    SocksRequest
				ServerAddr netip.AddrPort
			}{
				Request:    req,
				ServerAddr: req.ServerAddr,
			})
		}
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("execute forward_policy error")
			return
		}
		policyName = strings.TrimSpace(bb.String())
		log.Debug().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Interface("request", req).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		switch policyName {
		case "reject", "deny":
			WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
			return
		}
	}

	log.Info().NetIPAddr("remote_ip", req.RemoteAddr.Addr()).NetIPAddrPort("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.User.Username).Str("socks_host", req.Host).Msg("forward socks request")

	var dialerValue = h.Config.Forward.Dialer
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
				Request    SocksRequest
				ServerAddr netip.AddrPort
			}{
				Request:    req,
				ServerAddr: req.ServerAddr,
			})
		}
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			WriteSocks5Status(conn, Socks5StatusGeneralFailure)
			return
		}
		dialerValue = strings.TrimSpace(bb.String())
	}

	var dialerName = dialerValue
	var disableIPv6 = h.Config.Forward.DisableIpv6
	var preferIPv6 = h.Config.Forward.PreferIpv6
	switch {
	case strings.HasPrefix(dialerValue, "{\""):
		var v struct {
			Dialer      string `json:"dialer"`
			DisableIPv6 bool   `json:"disable_ipv6"`
			PreferIPv6  bool   `json:"prefer_ipv6"`
		}
		err := json.Unmarshal([]byte(dialerValue), &v)
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse forward_dialer error")
			return
		}
		dialerName = v.Dialer
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("parse forward_dialer error")
			return
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
	if dialerName != "" {
		if d, ok := h.Dialers[dialerName]; !ok {
			log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
			return
		} else {
			dialer = d
		}
	} else {
		dialer = h.LocalDialer
	}

	network := "tcp"

	log.Info().NetIPAddrPort("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.User.Username).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("socks_network", network).Str("socks_host", req.Host).Int("socks_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("forward socks request")

	switch {
	case disableIPv6:
		ctx = context.WithValue(ctx, DialerDisableIPv6ContextKey, struct{}{})
	case preferIPv6:
		ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
	}
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For":  []string{req.RemoteAddr.Addr().String()},
		"X-Forwarded-User": []string{req.User.Username},
	})
	rconn, err := dialer.DialContext(ctx, network, net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	if err != nil {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("connect remote host failed")
		WriteSocks5Status(conn, Socks5StatusNetworkUnreachable)
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	WriteSocks5Status(conn, Socks5StatusRequestGranted)

	if tc, _ := conn.(*net.TCPConn); conn != nil && speedLimit > 0 {
		(ConnOps{tc, nil}).SetTcpMaxPacingRate(int(speedLimit))
	}

	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(rconn, conn)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(conn, rconn)
		done <- struct{}{}
	}()
	<-done
	_ = conn.Close()
	_ = rconn.Close()
	<-done

	if h.Config.Forward.Log {
		var info GeoIPInfo
		if h.GeoResolver.CityReader != nil {
			info = h.GeoResolver.GetGeoIPInfo(ctx, req.RemoteAddr.Addr())
		}
		h.DataLogger.Log().
			Str("logger", "socks").
			Xid("trace_id", req.TraceID).
			NetIPAddrPort("server_addr", req.ServerAddr).
			NetIPAddr("remote_ip", req.RemoteAddr.Addr()).
			Str("remote_country", info.Country).
			Str("remote_city", info.City).
			Str("remote_isp", info.ISP).
			Str("remote_connection_type", info.ConnectionType).
			Str("forward_dialer_name", h.Config.Forward.Dialer).
			Str("socks_host", req.Host).
			Int("socks_port", req.Port).
			Int("socks_version", int(req.Version)).
			Str("forward_dialer_name", dialerName).
			Msg("")
	}
}

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

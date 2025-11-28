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

	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

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
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer
	Functions   template.FuncMap

	policy      *template.Template
	dialer      *template.Template
	userchecker AuthUserChecker
}

func (h *SocksHandler) Load() error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
		if h.dialer, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if table := h.Config.Forward.AuthTable; table != "" {
		loader := NewAuthUserLoaderFromTable(table)
		records, err := loader.LoadAuthUsers(context.Background())
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

	var b [512]byte
	n, err := io.ReadAtLeast(conn, b[:], 2)
	if err != nil || n == 0 {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read handshake error")
		return
	}

	req.Version = SocksVersion(b[0])
	for i := 0; i < int(b[1]); i++ {
		if b[i+2] == Socks5AuthMethodPassword {
			req.SupportAuth = true
			break
		}
	}

	if h.userchecker != nil {
		if !req.SupportAuth {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks client not support auth")
			return
		}
		conn.Write([]byte{VersionSocks5, byte(Socks5AuthMethodPassword)})
		n, err = io.ReadAtLeast(conn, b[:], 4)
		if err != nil || n == 0 {
			log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Msg("socks read auth error")
			return
		}
		// unpack username & password
		req.User.Username = string(b[2 : 2+int(b[1])])
		req.User.Password = string(b[3+int(b[1]) : 3+int(b[1])+int(b[2+int(b[1])])])
		// auth plugin
		err := h.userchecker.CheckAuthUser(ctx, &req.User)
		if err != nil {
			log.Warn().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Int("socks_version", int(req.Version)).Msg("auth error")
			conn.Write([]byte{VersionSocks5, byte(Socks5StatusGeneralFailure)})
			return
		}
	}

	// auth ok
	n, err = conn.Write([]byte{VersionSocks5, Socks5AuthMethodNone})
	if err != nil || n == 0 {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks write auth error")
		return
	}

	n, err = io.ReadAtLeast(conn, b[:], 8)
	if (err != nil && !strings.HasSuffix(err.Error(), " EOF")) || n == 0 {
		log.Error().Err(err).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read address error")
		return
	}

	req.ConnectType = SocksCommand(b[1])

	var addressType = Socks5AddressType(b[3])
	switch addressType {
	case Socks5IPv4Address:
		req.Host = netip.AddrFrom4(*(*[4]byte)(b[4:8])).String()
	case Socks5DomainName:
		req.Host = string(b[5 : 5+int(b[4])]) //b[4]表示域名的长度
	case Socks5IPv6Address:
		req.Host = netip.AddrFrom16(*(*[16]byte)(b[4:20])).String()
	}
	req.Port = int(b[n-2])<<8 | int(b[n-1])

	var speedLimit int64
	if s := req.User.Attrs["speed_limit"]; s != "" {
		if n, _ := strconv.ParseInt(s, 10, 64); n > 0 {
			speedLimit = n
		}
	}

	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	var policyName = h.Config.Forward.Policy
	if h.policy != nil {
		bb.Reset()
		err := h.policy.Execute(bb, struct {
			Request    SocksRequest
			ServerAddr netip.AddrPort
		}{req, req.ServerAddr})
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
		bb.Reset()
		err := h.dialer.Execute(bb, struct {
			Request    SocksRequest
			ServerAddr netip.AddrPort
		}{req, req.ServerAddr})
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
	switch req.ConnectType {
	case SocksCommandConnectUDP:
		network = "udp"
	}

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

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

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

	return
}

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

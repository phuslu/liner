package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
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
	User        UserInfo
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

	policy     *template.Template
	dialer     *template.Template
	userloader *FileLoader[[]UserInfo]
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

	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		h.userloader = GetUserInfoCsvLoader(h.Config.Forward.AuthTable)
		records := h.userloader.Load()
		if records == nil {
			log.Fatal().Str("auth_table", h.Config.Forward.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Str("auth_table", h.Config.Forward.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	return nil
}

func (h *SocksHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req SocksRequest
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		req.RemoteAddr = addr.AddrPort()
	} else {
		req.RemoteAddr, _ = netip.ParseAddrPort(conn.RemoteAddr().String())
	}
	if addr, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		req.ServerAddr = addr.AddrPort()
	} else {
		req.ServerAddr, _ = netip.ParseAddrPort(conn.LocalAddr().String())
	}
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

	if h.Config.Forward.AuthTable != "" {
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
		err := LookupUserInfoFromCsvLoader(h.userloader, &req.User)
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
		req.Host = net.IP(b[4:8]).String()
	case Socks5DomainName:
		req.Host = string(b[5 : 5+int(b[4])]) //b[4]表示域名的长度
	case Socks5IPv6Address:
		req.Host = net.IP(b[4:20]).String()
	}
	req.Port = int(b[n-2])<<8 | int(b[n-1])

	var speedLimit int64
	if s, _ := req.User.Attrs["speed_limit"].(string); s != "" {
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

	var dialerName = h.Config.Forward.Dialer
	dail := h.LocalDialer.DialContext
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

		if dialerName = strings.TrimSpace(bb.String()); dialerName != "" {
			u, ok := h.Dialers[dialerName]
			if !ok {
				log.Error().NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
				return
			}
			dail = u.DialContext
		}
	}

	network := "tcp"
	switch req.ConnectType {
	case SocksCommandConnectUDP:
		network = "udp"
	}

	log.Info().NetIPAddrPort("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.User.Username).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("socks_network", network).Str("socks_host", req.Host).Int("socks_port", req.Port).Str("forward_policy_name", policyName).Str("forward_dialer_name", dialerName).Msg("forward socks request")

	ctx = context.WithValue(context.Background(), DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For":  []string{req.RemoteAddr.Addr().String()},
		"X-Forwarded-User": []string{req.User.Username},
	})
	rconn, err := dail(ctx, network, net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
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
		SetTcpMaxPacingRate(tc, int(speedLimit))
	}

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

	if h.Config.Forward.Log {
		var country, city string
		if h.GeoResolver.CityReader != nil {
			country, city, _ = h.GeoResolver.LookupCity(context.Background(), net.IP(req.RemoteAddr.Addr().AsSlice()))
		}
		h.DataLogger.Log().Str("logger", "socks").Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddr("remote_ip", req.RemoteAddr.Addr()).Str("remote_country", country).Str("remote_city", city).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_dialer_name", dialerName).Msg("")
	}

	return
}

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}

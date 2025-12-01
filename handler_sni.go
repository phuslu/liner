package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/log"
)

type SniRequest struct {
	RemoteAddr netip.AddrPort
	ServerAddr netip.AddrPort
	ServerName string
	Port       int
	TraceID    log.XID
}

var _ TLSServerNameHandle = (&SniHandler{}).ServeConn

type SniHandler struct {
	Config      SniConfig
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer
	Functions   template.FuncMap

	policy *template.Template
	dialer *template.Template
}

func (h *SniHandler) Load() error {
	var err error

	if h.policy, err = template.New(h.Config.Forward.Policy).Funcs(h.Functions).Parse(h.Config.Forward.Policy); err != nil {
		return err
	}

	if strings.Contains(h.Config.Forward.Dialer, "{{") {
		if h.dialer, err = template.New(h.Config.Forward.Dialer).Funcs(h.Functions).Parse(h.Config.Forward.Dialer); err != nil {
			return err
		}
	}

	return nil
}

func (h *SniHandler) ServeConn(ctx context.Context, servername string, header []byte, conn net.Conn) error {
	defer conn.Close()

	var req SniRequest
	req.RemoteAddr = AddrPortFromNetAddr(conn.RemoteAddr())
	req.ServerAddr = AddrPortFromNetAddr(conn.LocalAddr())
	req.ServerName = servername
	req.TraceID = log.NewXID()

	var sb strings.Builder
	err := h.policy.Execute(&sb, struct {
		Request SniRequest
	}{req})
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Msg("sniproxy execute policy template error")
		return err
	}

	hostport := strings.TrimSpace(sb.String())
	if hostport == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "443")
	}

	var dialerValue = h.Config.Forward.Dialer
	if h.dialer != nil {
		var sb strings.Builder
		err := h.policy.Execute(&sb, struct {
			Request SniRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Str("hostport", hostport).Msg("sniproxy execute dialer template error")
			return err
		}
		dialerValue = sb.String()
	}
	dialerValue = strings.TrimSpace(dialerValue)

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
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Str("hostport", hostport).Msg("sniproxy parse dialer json error")
			return err
		}
		dialerName = v.Dialer
		disableIPv6 = v.DisableIPv6
		preferIPv6 = v.PreferIPv6
	case strings.Contains(dialerValue, "="):
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Str("hostport", hostport).Msg("sniproxy parse dialer uri error")
			return err
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
			log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Str("hostport", hostport).Msg("no dialer exists")
			return fmt.Errorf("sniproxy: no dialer exists: %#v", dialerName)
		} else {
			dialer = d
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

	log.Info().
		Xid("trace_id", req.TraceID).
		NetIPAddrPort("server_addr", req.ServerAddr).
		NetIPAddrPort("remote_addr", req.RemoteAddr).
		Str("hostport", hostport).
		Str("dialer_name", dialerName).
		Bool("disable_ipv6", disableIPv6).
		Bool("prefer_ipv6", preferIPv6).
		Msg("sniproxy dailing")

	rconn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Xid("trace_id", req.TraceID).NetIPAddrPort("server_addr", req.ServerAddr).NetIPAddrPort("remote_addr", req.RemoteAddr).Str("hostport", hostport).Str("dialer_name", dialerName).Msg("sniproxy dail error")
		return err
	}

	_, err = rconn.Write(header)
	if err != nil {
		return fmt.Errorf("sniproxy: proxy_pass %s error: %w", req.ServerName, err)
	}

	go io.Copy(conn, rconn)
	_, err = io.Copy(rconn, conn)
	if err != nil {
		return fmt.Errorf("sniproxy: proxy_pass %s error: %w", req.ServerName, err)
	}

	return io.EOF
}

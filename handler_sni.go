package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
)

type SniRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	ServerName string
	Port       int
	TraceID    log.XID
}

type SniHandler struct {
	Config      SniConfig
	GeoResolver *GeoResolver
	LocalDialer *LocalDialer
	Dialers     map[string]Dialer
	Functions   template.FuncMap

	policy *template.Template
}

func (h *SniHandler) Load() error {
	var err error

	if h.policy, err = template.New(h.Config.Policy).Funcs(h.Functions).Parse(h.Config.Policy); err != nil {
		return err
	}

	return nil
}

func (h *SniHandler) ServeConn(ctx context.Context, servername string, header []byte, conn net.Conn) error {
	defer conn.Close()

	var req SniRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()
	req.ServerName = servername
	req.TraceID = log.NewXID()

	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)
	bb.Reset()

	err := h.policy.Execute(bb, struct {
		Request SniRequest
	}{req})
	if err != nil {
		return err
	}

	result := strings.TrimSpace(bb.String())
	if result == "" {
		return nil
	}

	parts := strings.Fields(result)
	hostport := parts[0]
	var dialer Dialer = h.LocalDialer
	if len(parts) > 1 {
		dialer = h.Dialers[parts[1]]
		if dialer == nil {
			return fmt.Errorf("sniproxy: dialer %#v is not found", parts[1])
		}
	}

	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "443")
	}

	log.Info().Str("hostport", hostport).Msg("sniproxy dailing")

	rconn, err := dialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Str("hostport", hostport).Msg("sniproxy dail error")
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

var _ TLSSniFallback = (&SniHandler{}).ServeConn

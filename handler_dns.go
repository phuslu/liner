package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
)

type DnsRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	TraceID    log.XID
	Raw        []byte
}

type DnsHandler struct {
	Config    DnsConfig
	Logger    log.Logger
	Functions template.FuncMap

	dialer *fastdns.HTTPDialer
}

var drPool = sync.Pool{
	New: func() interface{} {
		r := new(DnsRequest)
		r.Raw = make([]byte, 1500)
		return r
	},
}

func (h *DnsHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invaild length of listen: %#v", h.Config.Listen)
	}
	if !strings.HasPrefix(h.Config.ProxyPass, "https://") {
		return fmt.Errorf("unsupported proxy_pass scheme: %#v", h.Config.ProxyPass)
	}

	endpoint, err := url.Parse(h.Config.ProxyPass)
	if err != nil {
		return fmt.Errorf("invaild dns server: %#v: %w", h.Config.ProxyPass, err)
	}

	h.dialer = &fastdns.HTTPDialer{
		Endpoint: endpoint,
		Header: http.Header{
			"content-type": {"application/dns-message"},
			"user-agent":   {"fastdns/1.0"},
		},
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: false,
				ServerName:         endpoint.Hostname(),
				ClientSessionCache: tls.NewLRUClientSessionCache(1024),
			},
		},
	}

	return nil
}

func (h *DnsHandler) Serve(ctx context.Context, pc net.PacketConn) {
	defer pc.Close()

	for {
		req := drPool.Get().(*DnsRequest)
		req.Raw = req.Raw[:cap(req.Raw)]

		n, addr, err := pc.ReadFrom(req.Raw)
		if err != nil {
			log.Error().Err(err).Stringer("local_addr", pc.LocalAddr()).Msg("dns read from error")
			continue
		}
		req.Raw = req.Raw[:n]

		go func(req *DnsRequest, addr net.Addr) {
			defer drPool.Put(req)

			conn, err := h.dialer.DialContext(ctx, "", "")
			if err != nil {
				log.Error().Err(err).Stringer("local_addr", pc.LocalAddr()).Str("remote_url", h.Config.ProxyPass).Msg("dns dial error")
				return
			}
			defer h.dialer.Put(conn)

			_, err = conn.Write(req.Raw)
			if err != nil {
				log.Error().Err(err).Stringer("local_addr", pc.LocalAddr()).Str("remote_url", h.Config.ProxyPass).Msg("dns dial error")
				return
			}

			req.Raw = req.Raw[:cap(req.Raw)]
			n, err := conn.Read(req.Raw)
			if err != nil {
				log.Error().Err(err).Stringer("local_addr", pc.LocalAddr()).Str("remote_url", h.Config.ProxyPass).Msg("dns read raw data error")
				return
			}

			req.Raw = req.Raw[:n]

			pc.WriteTo(req.Raw, addr)
		}(req, addr)
	}
}

package main

import (
	"cmp"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type resolvererr struct {
	Resolver *Resolver
	Err      error
}

var resolvers = xsync.NewMap[string, resolvererr](xsync.WithSerialResize())

func GetResolver(addr string) (r *Resolver, err error) {
	racer, _ := resolvers.LoadOrCompute(addr, func() (r resolvererr, cancel bool) {
		r.Resolver = &Resolver{
			Client: &fastdns.Client{
				Addr: addr,
			},
			CacheDuration: 10 * time.Minute,
			LRUCache:      lru.NewTTLCache[string, []netip.Addr](64 * 1024),
		}

		switch {
		case addr == "":
			r.Err = fmt.Errorf("invalid dns_server addr: %s", addr)
		case strings.Contains(addr, "://"):
			u, err := url.Parse(addr)
			if err != nil {
				r.Err = fmt.Errorf("invalid dns_server addr: %s", addr)
			}
			switch u.Scheme {
			case "tcp":
				hostport := u.Host
				if _, _, err := net.SplitHostPort(hostport); err != nil {
					hostport = net.JoinHostPort(hostport, "53")
				}
				r.Resolver.Client.Dialer = &fastdns.TCPDialer{
					Addr:     func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr("tcp", hostport); return }(),
					MaxConns: 16,
				}
			case "tls", "dot":
				hostport := u.Host
				if _, _, err := net.SplitHostPort(hostport); err != nil {
					hostport = net.JoinHostPort(hostport, "853")
				}
				r.Resolver.Client.Dialer = &fastdns.TCPDialer{
					Addr: func() (ua *net.TCPAddr) { ua, _ = net.ResolveTCPAddr("tcp", hostport); return }(),
					TLSConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
					MaxConns: 16,
				}
			case "https", "http2", "h2", "doh":
				u.Scheme = "https"
				r.Resolver.Client.Dialer = &fastdns.HTTPDialer{
					Endpoint: u,
					Header: http.Header{
						"content-type": {"application/dns-message"},
						"user-agent":   {cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent)},
					},
					Transport: &http2.Transport{
						TLSClientConfig: &tls.Config{
							ServerName:         u.Hostname(),
							ClientSessionCache: tls.NewLRUClientSessionCache(128),
						},
					},
				}
			case "http3", "h3", "doh3":
				u.Scheme = "https"
				r.Resolver.Client.Dialer = &fastdns.HTTPDialer{
					Endpoint: u,
					Header: http.Header{
						"content-type": {"application/dns-message"},
						"user-agent":   {cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent)},
					},
					Transport: &http3.Transport{
						DisableCompression: false,
						EnableDatagrams:    true,
						TLSClientConfig: &tls.Config{
							NextProtos:         []string{"h3"},
							InsecureSkipVerify: u.Query().Get("insecure") == "true",
							ServerName:         u.Hostname(),
							ClientSessionCache: tls.NewLRUClientSessionCache(128),
						},
						QUICConfig: &quic.Config{
							DisablePathMTUDiscovery: false,
							EnableDatagrams:         true,
							MaxIncomingUniStreams:   200,
							MaxIncomingStreams:      200,
						},
					},
				}
			default:
				r.Err = fmt.Errorf("unspported dns_server addr: %s", addr)
			}
		default:
			host := addr
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "53")
			}
			u, err := net.ResolveUDPAddr("udp", host)
			if err != nil {
				r.Err = fmt.Errorf("invalid dns_server addr: %s", addr)
			}
			r.Resolver.Client.Dialer = &fastdns.UDPDialer{
				Addr:     u,
				Timeout:  3 * time.Second,
				MaxConns: 128,
			}
		}
		return
	})

	return racer.Resolver, racer.Err
}

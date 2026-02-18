package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v4"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/http2"
)

type DnsResolverPool struct {
	Logger      *log.Logger
	Cache       *lru.TTLCache[DnsResolverCacheKey, []netip.Addr]
	DisableIPv6 bool

	resolvers *xsync.Map[string, dnsresolvererr]
}

type DnsResolverCacheKey struct {
	Addr string
	Host string
}

type dnsresolvererr struct {
	DnsResolver *DnsResolver
	Err         error
}

func (pool *DnsResolverPool) Get(addr string, ttl time.Duration) (*DnsResolver, error) {
	if pool.resolvers == nil {
		pool.resolvers = xsync.NewMap[string, dnsresolvererr]()
	}
	racer, _ := pool.resolvers.LoadOrCompute(addr, func() (r dnsresolvererr, cancel bool) {
		r.DnsResolver = &DnsResolver{
			Logger: pool.Logger,
			Cache:  pool.Cache,
			Client: &fastdns.Client{
				Addr:    addr,
				Timeout: 5 * time.Second,
			},
			CacheDuration: cmp.Or(ttl, 600*time.Second),
			DisableIPv6:   pool.DisableIPv6,
		}

		tcp, udp := "tcp", "udp"
		if pool.DisableIPv6 {
			tcp, udp = "tcp4", "udp4"
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
				r.DnsResolver.Client.Dialer = &fastdns.TCPDialer{
					Addr:     func() (u *net.TCPAddr) { u, _ = net.ResolveTCPAddr(tcp, hostport); return }(),
					Timeout:  4 * time.Second,
					MaxConns: 8,
				}
			case "tls", "dot":
				hostport := u.Host
				if _, _, err := net.SplitHostPort(hostport); err != nil {
					hostport = net.JoinHostPort(hostport, "853")
				}
				r.DnsResolver.Client.Dialer = &fastdns.TCPDialer{
					Addr: func() (ua *net.TCPAddr) { ua, _ = net.ResolveTCPAddr(tcp, hostport); return }(),
					TLSConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
					Timeout:  5 * time.Second,
					MaxConns: 8,
				}
			case "https", "http2", "h2", "doh":
				u.Scheme = "https"
				r.DnsResolver.Client.Dialer = &fastdns.HTTPDialer{
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
						DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
							return (&tls.Dialer{Config: cfg}).DialContext(ctx, tcp, addr)
						},
					},
				}
			case "http3", "h3", "doh3":
				u.Scheme = "https"
				r.DnsResolver.Client.Dialer = &fastdns.HTTPDialer{
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
			u, err := net.ResolveUDPAddr(udp, host)
			if err != nil {
				r.Err = fmt.Errorf("invalid dns_server addr: %s", addr)
			}
			r.DnsResolver.Client.Dialer = &fastdns.UDPDialer{
				Addr:     u,
				MaxConns: 8,
			}
		}
		return
	})

	return racer.DnsResolver, racer.Err
}

type DnsResolver struct {
	Logger        *log.Logger
	Cache         *lru.TTLCache[DnsResolverCacheKey, []netip.Addr]
	CacheDuration time.Duration
	Client        *fastdns.Client
	DisableIPv6   bool
}

var godebugnetdns = strings.Contains(os.Getenv("GODEBUG"), "netdns=")

func (r *DnsResolver) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	if r.Cache != nil {
		if v, ok := r.Cache.Get(DnsResolverCacheKey{r.Client.Addr, host}); ok {
			return v, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	if r.DisableIPv6 {
		network = "ip4"
	}

	if !godebugnetdns {
		ips, err = r.Client.AppendLookupNetIP(ips, ctx, network, host)
	} else {
		ips, err = net.DefaultResolver.LookupNetIP(ctx, network, host)
	}
	if err != nil {
		if r.Logger != nil {
			r.Logger.Error().Err(err).Str("dns_server", r.Client.Addr).Str("host", host).NetIPAddrs("ips", ips).Msg("LookupNetIP")
		}
		if len(ips) == 0 {
			return nil, err
		}
	}

	if !r.DisableIPv6 {
		slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(btoi(b.Is4()), btoi(a.Is4())) })
	}

	if r.Cache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.Cache.Set(DnsResolverCacheKey{r.Client.Addr, host}, ips, r.CacheDuration)
	}

	if r.Logger != nil {
		r.Logger.Debug().Str("dns_server", r.Client.Addr).Str("host", host).NetIPAddrs("ips", ips).Msg("LookupNetIP")
	}

	return ips, nil
}

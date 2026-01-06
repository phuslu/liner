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

type DnsResolverGenerator struct {
	Logger      *log.Logger
	LRUCache    *lru.TTLCache[DnsResolverCacheKey, []netip.Addr]
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

func (rg *DnsResolverGenerator) Get(addr string, ttl time.Duration) (*DnsResolver, error) {
	if rg.resolvers == nil {
		rg.resolvers = xsync.NewMap[string, dnsresolvererr]()
	}
	racer, _ := rg.resolvers.LoadOrCompute(addr, func() (r dnsresolvererr, cancel bool) {
		r.DnsResolver = &DnsResolver{
			Logger:   rg.Logger,
			LRUCache: rg.LRUCache,
			Client: &fastdns.Client{
				Addr: addr,
			},
			CacheDuration: cmp.Or(ttl, 10*time.Second),
			DisableIPv6:   rg.DisableIPv6,
		}

		tcp := "tcp"
		if rg.DisableIPv6 {
			tcp = "tcp4"
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
					MaxConns: 16,
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
					MaxConns: 16,
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
			u, err := net.ResolveUDPAddr("udp", host)
			if err != nil {
				r.Err = fmt.Errorf("invalid dns_server addr: %s", addr)
			}
			r.DnsResolver.Client.Dialer = &fastdns.UDPDialer{
				Addr:     u,
				Timeout:  3 * time.Second,
				MaxConns: 128,
			}
		}
		return
	})

	return racer.DnsResolver, racer.Err
}

type DnsResolver struct {
	Logger        *log.Logger
	LRUCache      *lru.TTLCache[DnsResolverCacheKey, []netip.Addr]
	Client        *fastdns.Client
	CacheDuration time.Duration
	DisableIPv6   bool
}

var godebugnetdns = strings.Contains(os.Getenv("GODEBUG"), "netdns=")

func (r *DnsResolver) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.Get(DnsResolverCacheKey{r.Client.Addr, host}); ok {
			return v, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
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

	slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(btoi(b.Is4()), btoi(a.Is4())) })

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(DnsResolverCacheKey{r.Client.Addr, host}, ips, r.CacheDuration)
	}

	if r.Logger != nil {
		r.Logger.Debug().Str("dns_server", r.Client.Addr).Str("host", host).NetIPAddrs("ips", ips).Msg("LookupNetIP")
	}

	return ips, nil
}

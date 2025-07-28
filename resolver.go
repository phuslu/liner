package main

import (
	"cmp"
	"context"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/lru"
)

type Resolver struct {
	Client        *fastdns.Client
	Logger        *slog.Logger
	LRUCache      *lru.TTLCache[string, []netip.Addr]
	CacheDuration time.Duration
	NoIPv6Hosts   *lru.TTLCache[string, bool]
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.Get(host); ok {
			return v, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err = r.Client.AppendLookupNetIP(ips, ctx, network, host)
	if err != nil {
		return nil, err
	}

	slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(btoi(b.Is4()), btoi(a.Is4())) })

	if r.NoIPv6Hosts != nil {
		if ok, _ := r.NoIPv6Hosts.Get(host); ok {
			if i := slices.IndexFunc(ips, func(ip netip.Addr) bool { return ip.Is6() }); i > 0 {
				ips = ips[i:]
			}
		}
	}

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(host, ips, r.CacheDuration)
	}

	if r.Logger != nil {
		r.Logger.Debug("LookupNetIP", "host", host, "dns_server", r.Client.Addr, "ips", ips)
	}

	return ips, nil
}

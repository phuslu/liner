package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/phuslu/lru"
)

func TestResolver(t *testing.T) {
	r := &Resolver{
		Resolver: &net.Resolver{
			PreferGo: true,
		},
		CacheDuration: time.Minute,
		LRUCache:      lru.NewTTLCache[string, []netip.Addr](32 * 1024),
	}

	fmt.Println(r.LookupNetIP(context.Background(), "ip", "gmail.com"))
}

func TestDoHResolver(t *testing.T) {
	cases := []struct {
		Host string
		IP   string
	}{
		{"192-168-2-1.nip.io", "192.168.2.1"},
		{"forcesafesearch.google.com", "216.239.38.120"},
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: (&DoHResolverDialer{
			EndPoint:  "https://dns.google/dns-query",
			UserAgent: DefaultUserAgent,
		}).DialContext,
	}

	for _, c := range cases {
		v, err := r.LookupNetIP(context.Background(), "ip4", c.Host)
		// t.Logf("LookupAddr(%#v) return v=%+v err=%+v", c.Host, v, err)
		if err != nil || v[0].String() != c.IP {
			t.Errorf("LookupAddr(%#v) must return %#v, not %+v, err=%+v", c.Host, c.IP, v, err)
		}
	}
}

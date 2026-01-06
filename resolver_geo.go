package main

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
)

type GeoResolver struct {
	Logger               *log.Logger
	EnableCJKCityName    bool
	GeoIPCache           *lru.TTLCache[netip.Addr, GeoIPInfo]
	CityReader           *maxminddb.Reader
	ISPReader            *maxminddb.Reader
	DomainReader         *maxminddb.Reader
	ConnectionTypeReader *maxminddb.Reader
	GeoSiteCache         *lru.TTLCache[string, GeoSiteInfo]
	GeoSiteDLC           *geosite.DomainListCommunity
}

type GeoIPInfo struct {
	IP             string
	Country        string
	City           string
	ISP            string
	ASN            string
	Domain         string
	ConnectionType string
}

func (r *GeoResolver) GetGeoIPInfo(ctx context.Context, ip netip.Addr) (info GeoIPInfo) {
	if r.GeoIPCache != nil {
		info, _, _ = r.GeoIPCache.GetOrLoad(ctx, ip, r.getGeoIPInfo)
	} else {
		info, _, _ = r.getGeoIPInfo(ctx, ip)
	}
	return
}

func (r *GeoResolver) getGeoIPInfo(ctx context.Context, ip netip.Addr) (GeoIPInfo, time.Duration, error) {
	var info GeoIPInfo

	info.IP = ip.String()

	if r.CityReader != nil {
		if record, err := r.LookupCity(ctx, ip); err == nil {
			info.Country, info.City = record.Country.ISOCode, record.City.Names.EN
			if r.EnableCJKCityName {
				switch info.Country {
				case "CN", "HK":
					info.City = strings.TrimSuffix(record.City.Names.CN, "市")
				case "JP":
					info.City = record.City.Names.JP
				}
			}
		}
	}

	// if info.Country == "CN" && IsBogusChinaIP(ip) {
	// 	return info, time.Minute, nil
	// }

	if r.Logger != nil {
		r.Logger.Debug().NetIPAddr("ip", ip).Str("country", info.Country).Str("city", info.City).Msg("get city by ip")
	}

	if r.ISPReader != nil {
		if record, err := r.LookupISP(ctx, ip); err == nil {
			info.ISP = record.ISP
			if n := record.AutonomousSystemNumber; n > 0 {
				info.ASN = "AS" + strconv.FormatUint(uint64(n), 10)
			}
			if r.Logger != nil {
				r.Logger.Debug().NetIPAddr("ip", ip).Str("isp", info.ISP).Str("asn", info.ASN).Msg("get isp by ip")
			}
		}
	}

	if r.DomainReader != nil {
		if domain, err := r.LookupDomain(ctx, ip); err == nil {
			info.Domain = domain
			if r.Logger != nil {
				r.Logger.Debug().NetIPAddr("ip", ip).Str("domain", domain).Msg("get domain by ip")
			}
		}
	}

	if r.ConnectionTypeReader != nil {
		if conntype, err := r.LookupConnectionType(ctx, ip); err == nil {
			info.ConnectionType = conntype
			if r.Logger != nil {
				r.Logger.Debug().NetIPAddr("ip", ip).Str("connection_type", conntype).Msg("get connection_type by ip")
			}
		}
	}

	return info, 12 * time.Hour, nil
}

type GeoIPCityRecord struct {
	Country struct {
		GeoNameID uint   `maxminddb:"geoname_id"`
		ISOCode   string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		GeoNameID uint `maxminddb:"geoname_id"`
		Names     struct {
			EN string `maxminddb:"en"`
			JP string `maxminddb:"ja"`
			CN string `maxminddb:"zh-CN"`
		} `maxminddb:"names"`
	} `maxminddb:"city"`
	// Subdivisions []struct {
	// 	GeoNameID uint   `maxminddb:"geoname_id"`
	// 	IsoCode   string `maxminddb:"iso_code"`
	// 	Names     struct {
	// 		EN string `maxminddb:"en"`
	// 	} `maxminddb:"names"`
	// } `maxminddb:"subdivisions"`
}

func (r *GeoResolver) LookupCity(ctx context.Context, ip netip.Addr) (record GeoIPCityRecord, err error) {
	if r.CityReader == nil {
		err = errors.New("no maxmind city database found")
		return
	}

	err = r.CityReader.Lookup(ip).Decode(&record)
	return
}

type GeoIPISPRecord struct {
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
	ISP                          string `maxminddb:"isp"`
	MobileCountryCode            string `maxminddb:"mobile_country_code"`
	MobileNetworkCode            string `maxminddb:"mobile_network_code"`
	Organization                 string `maxminddb:"organization"`
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
}

func (r *GeoResolver) LookupISP(ctx context.Context, ip netip.Addr) (record GeoIPISPRecord, err error) {
	if r.ISPReader == nil {
		err = errors.New("no maxmind isp database found")
		return
	}

	err = r.ISPReader.Lookup(ip).Decode(&record)
	return
}

func (r *GeoResolver) LookupDomain(ctx context.Context, ip netip.Addr) (string, error) {
	if r.DomainReader == nil {
		return "", errors.New("no maxmind domain database found")
	}

	var domain string
	err := r.DomainReader.Lookup(ip).DecodePath(&domain, "domain")
	if err != nil {
		return "", err
	}

	return domain, nil
}

func (r *GeoResolver) LookupConnectionType(ctx context.Context, ip netip.Addr) (string, error) {
	if r.ConnectionTypeReader == nil {
		return "", errors.New("no maxmind domain database found")
	}

	var connectionType string
	err := r.ConnectionTypeReader.Lookup(ip).DecodePath(&connectionType, "connection_type")
	if err != nil {
		return "", err
	}

	return connectionType, nil
}

type GeoSiteInfo struct {
	Site string
	Atts []string
}

func (r *GeoResolver) GetGeoSiteInfo(ctx context.Context, domain string) (info GeoSiteInfo) {
	switch {
	case r.GeoSiteDLC == nil:
		return
	case r.GeoSiteCache != nil:
		info, _, _ = r.GeoSiteCache.GetOrLoad(ctx, domain, r.getGeoSiteInfo)
	default:
		info, _, _ = r.getGeoSiteInfo(ctx, domain)
	}
	return
}

func (r *GeoResolver) getGeoSiteInfo(ctx context.Context, domain string) (GeoSiteInfo, time.Duration, error) {
	site, attrs := r.GeoSiteDLC.SiteAttrs(domain)
	return GeoSiteInfo{site, attrs}, 12 * time.Hour, nil
}

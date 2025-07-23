package main

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"github.com/phuslu/lru"
)

type GeoResolver struct {
	Resolver             *Resolver
	Logger               *slog.Logger
	GeoIPCache           *lru.TTLCache[netip.Addr, GeoIPInfo]
	CityReader           *maxminddb.Reader
	ISPReader            *maxminddb.Reader
	DomainReader         *maxminddb.Reader
	ConnectionTypeReader *maxminddb.Reader
	EnableCJKCityName    bool
}

func (r *GeoResolver) LookupCity(ctx context.Context, ip netip.Addr) (string, string, error) {
	if r.CityReader == nil {
		return "", "", errors.New("no maxmind city database found")
	}

	var record struct {
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

	err := r.CityReader.Lookup(ip).Decode(&record)
	if err != nil {
		return "", "", err
	}

	code, name := record.Country.ISOCode, record.City.Names.EN
	if r.EnableCJKCityName {
		switch code {
		case "CN", "HK":
			name = strings.TrimSuffix(record.City.Names.CN, "市")
		case "JP":
			name = record.City.Names.JP
		}
	}

	return code, name, nil
}

func (r *GeoResolver) LookupISP(ctx context.Context, ip netip.Addr) (string, uint, error) {
	if r.ISPReader == nil {
		return "", 0, errors.New("no maxmind isp database found")
	}

	var record struct {
		AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
		ISP                          string `maxminddb:"isp"`
		MobileCountryCode            string `maxminddb:"mobile_country_code"`
		MobileNetworkCode            string `maxminddb:"mobile_network_code"`
		Organization                 string `maxminddb:"organization"`
		AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	}

	err := r.ISPReader.Lookup(ip).Decode(&record)
	if err != nil {
		return "", 0, err
	}

	return record.ISP, record.AutonomousSystemNumber, nil
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

type GeoIPInfo struct {
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
	if r.CityReader != nil {
		info.Country, info.City, _ = r.LookupCity(ctx, ip)
	}

	// if info.Country == "CN" && IsBogusChinaIP(ip) {
	// 	return info, time.Minute, nil
	// }

	if r.Logger != nil {
		r.Logger.Debug("get city by ip", "ip", ip, "country", info.Country, "city", info.City)
	}

	if r.ISPReader != nil {
		if isp, asn, err := r.LookupISP(ctx, ip); err == nil {
			info.ISP = isp
			info.ASN = "AS" + strconv.FormatUint(uint64(asn), 10)
			if r.Logger != nil {
				r.Logger.Debug("get isp by ip", "ip", ip, "isp", isp, "asn", asn)
			}
		}
	}

	if r.DomainReader != nil {
		if domain, err := r.LookupDomain(ctx, ip); err == nil {
			info.Domain = domain
			if r.Logger != nil {
				r.Logger.Debug("get domain by ip", "ip", ip, "domain", domain)
			}
		}
	}

	if r.ConnectionTypeReader != nil {
		if conntype, err := r.LookupConnectionType(ctx, ip); err == nil {
			info.ConnectionType = conntype
			if r.Logger != nil {
				r.Logger.Debug("get connection_type by ip", "ip", ip, "connection_type", conntype)
			}
		}
	}

	return info, 12 * time.Hour, nil
}

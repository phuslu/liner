package main

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/oschwald/maxminddb-golang/v2"
)

type GeoResolver struct {
	Resolver             *Resolver
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

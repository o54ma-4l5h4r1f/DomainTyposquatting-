package lib

import (
	"context"
	"log"
	"net"
	"time"
)

// dnsResolvers is the fallback chain: system default -> Google -> Cloudflare.
var dnsResolvers = []*net.Resolver{
	{}, // system default
	{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "8.8.8.8:53")
		},
	},
	{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", "1.1.1.1:53")
		},
	},
}

// LookupDNS resolves A, AAAA, MX, and NS records for a domain.
// Tries system resolver first, then falls back to Google and Cloudflare DNS.
func LookupDNS(ctx context.Context, domain string) *DNSResult {
	result := &DNSResult{
		A:    []string{},
		AAAA: []string{},
		MX:   []MXRecord{},
		NS:   []string{},
	}

	dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// A and AAAA records - try each resolver until one succeeds
	for _, resolver := range dnsResolvers {
		ips, err := resolver.LookupIPAddr(dnsCtx, domain)
		if err != nil {
			continue
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				result.A = append(result.A, ip.IP.String())
			} else if ip.IP.To16() != nil {
				result.AAAA = append(result.AAAA, ip.IP.String())
			}
		}
		break
	}
	if len(result.A) == 0 && len(result.AAAA) == 0 {
		log.Printf("DNS A/AAAA lookup failed for %s on all resolvers", domain)
	}

	// MX records - try each resolver until one succeeds
	for _, resolver := range dnsResolvers {
		mxRecords, err := resolver.LookupMX(dnsCtx, domain)
		if err != nil {
			continue
		}
		for _, mx := range mxRecords {
			result.MX = append(result.MX, MXRecord{
				Host:     mx.Host,
				Priority: mx.Pref,
			})
		}
		break
	}

	// NS records - try each resolver until one succeeds
	for _, resolver := range dnsResolvers {
		nsRecords, err := resolver.LookupNS(dnsCtx, domain)
		if err != nil {
			continue
		}
		for _, ns := range nsRecords {
			result.NS = append(result.NS, ns.Host)
		}
		break
	}

	return result
}

package lib

import (
	"context"
	"log"
	"net"
	"time"
)

// LookupDNS resolves A, AAAA, MX, and NS records for a domain.
func LookupDNS(domain string) *DNSResult {
	result := &DNSResult{
		A:    []string{},
		AAAA: []string{},
		MX:   []MXRecord{},
		NS:   []string{},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resolver := &net.Resolver{}

	// A and AAAA records via a single lookup
	ips, err := resolver.LookupIPAddr(ctx, domain)
	if err != nil {
		log.Printf("DNS IP lookup failed for %s: %v", domain, err)
	} else {
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				result.A = append(result.A, ip.IP.String())
			} else if ip.IP.To16() != nil {
				result.AAAA = append(result.AAAA, ip.IP.String())
			}
		}
	}

	// MX records
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		log.Printf("DNS MX lookup failed for %s: %v", domain, err)
	} else {
		for _, mx := range mxRecords {
			result.MX = append(result.MX, MXRecord{
				Host:     mx.Host,
				Priority: mx.Pref,
			})
		}
	}

	// NS records
	nsRecords, err := resolver.LookupNS(ctx, domain)
	if err != nil {
		log.Printf("DNS NS lookup failed for %s: %v", domain, err)
	} else {
		for _, ns := range nsRecords {
			result.NS = append(result.NS, ns.Host)
		}
	}

	return result
}

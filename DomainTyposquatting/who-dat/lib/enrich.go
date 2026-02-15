package lib

import (
	"context"
	"log"
	"sync"

	whoisparser "github.com/likexian/whois-parser"
)

// EnrichedResult wraps WHOIS data with DNS, network, and security enrichment.
type EnrichedResult struct {
	whoisparser.WhoisInfo
	DNS      *DNSResult      `json:"dns"`
	Network  *NetworkResult  `json:"network"`
	Security *SecurityResult `json:"security"`
}

// DNSResult holds DNS record lookups for a domain.
type DNSResult struct {
	A    []string   `json:"a"`
	AAAA []string   `json:"aaaa"`
	MX   []MXRecord `json:"mx"`
	NS   []string   `json:"ns"`
}

// MXRecord represents a single MX record with host and priority.
type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// NetworkResult holds network-level enrichment data.
type NetworkResult struct {
	GeoIP      *GeoIPResult `json:"geoip"`
	HTTPBanner string       `json:"http_banner"`
}

// GeoIPResult holds geolocation data for an IP address.
type GeoIPResult struct {
	IP          string  `json:"ip"`
	Country     string  `json:"country"`
	CountryCode string  `json:"country_code"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
}

// SecurityResult holds security-related enrichment data.
type SecurityResult struct {
	MXIntercept bool   `json:"mx_intercept"`
	SSDeep      string `json:"ssdeep"`
	TLSH        string `json:"tlsh"`
}

// Enrich performs WHOIS lookup and all enrichment in parallel for a single domain.
func Enrich(domain string) (*EnrichedResult, error) {
	result := &EnrichedResult{}
	var wg sync.WaitGroup

	var whoisResult whoisparser.WhoisInfo
	var whoisErr error
	var dnsResult *DNSResult
	var httpBody []byte
	var httpBanner string

	// Phase 1: WHOIS + DNS + HTTP fetch in parallel
	wg.Add(3)

	go func() {
		defer wg.Done()
		whoisResult, whoisErr = GetWhois(domain)
	}()

	go func() {
		defer wg.Done()
		dnsResult = LookupDNS(domain)
	}()

	go func() {
		defer wg.Done()
		httpBody, httpBanner = FetchHTTPBanner(domain)
	}()

	wg.Wait()

	// Populate WHOIS fields
	result.WhoisInfo = whoisResult
	result.DNS = dnsResult
	result.Network = &NetworkResult{HTTPBanner: httpBanner}
	result.Security = &SecurityResult{
		MXIntercept: dnsResult != nil && len(dnsResult.MX) > 0,
	}

	// Phase 2: GeoIP (needs A record IP) + security hashes (need HTTP body)
	wg.Add(2)

	go func() {
		defer wg.Done()
		if dnsResult != nil && len(dnsResult.A) > 0 {
			result.Network.GeoIP = LookupGeoIP(dnsResult.A[0])
		}
	}()

	go func() {
		defer wg.Done()
		if len(httpBody) > 0 {
			result.Security.SSDeep = ComputeSSDeep(httpBody)
			result.Security.TLSH = ComputeTLSH(httpBody)
		}
	}()

	wg.Wait()

	if whoisErr != nil {
		log.Printf("WHOIS failed for %s but enrichment data collected: %v", domain, whoisErr)
	}

	return result, whoisErr
}

// EnrichMulti performs enrichment for multiple domains concurrently.
func EnrichMulti(ctx context.Context, domains []string) ([]EnrichedResult, error) {
	results := make([]EnrichedResult, len(domains))
	var wg sync.WaitGroup

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			enriched, err := Enrich(d)
			if err != nil {
				log.Printf("Enrichment partially failed for %s: %v", d, err)
			}
			if enriched != nil {
				results[idx] = *enriched
			}
		}(i, domain)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return results, nil
	case <-ctx.Done():
		return results, ctx.Err()
	}
}

package lib

import (
	"log"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

// GetWhois does a WHOIS lookup for a supplied domain, falling back to RDAP on failure
func GetWhois(domain string) (whoisparser.WhoisInfo, error) {
	raw, err := whois.Whois(domain)
	if err == nil {
		result, parseErr := whoisparser.Parse(raw)
		if parseErr == nil {
			return result, nil
		}
		log.Printf("WHOIS parse failed for %s, trying RDAP: %v", domain, parseErr)
	} else {
		log.Printf("WHOIS lookup failed for %s, trying RDAP: %v", domain, err)
	}

	// Fallback to RDAP
	return GetRDAP(domain)
}

// GetChanWhois sends Whois data to a channel
func GetChanWhois(domain string, whoisCh chan<- whoisparser.WhoisInfo, errorCh chan<- error) {
	raw, err := whois.Whois(domain)
	if err == nil {
		result, parseErr := whoisparser.Parse(raw)
		if parseErr == nil {
			whoisCh <- result
			return
		}
		log.Printf("WHOIS parse failed for %s, trying RDAP: %v", domain, parseErr)
	} else {
		log.Printf("WHOIS lookup failed for %s, trying RDAP: %v", domain, err)
	}

	// Fallback to RDAP
	rdapResult, rdapErr := GetRDAP(domain)
	if rdapErr != nil {
		whoisCh <- whoisparser.WhoisInfo{}
		errorCh <- rdapErr
		return
	}
	whoisCh <- rdapResult
}

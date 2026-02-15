package lib

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var bannerClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// FetchHTTPBanner fetches the HTTP Server header and page body from a domain.
// Tries HTTPS first, then falls back to HTTP. Body is capped at 1 MB for hashing.
func FetchHTTPBanner(domain string) (body []byte, banner string) {
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, domain)
		resp, err := bannerClient.Get(url)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		banner = resp.Header.Get("Server")

		body, err = io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
		if err != nil {
			log.Printf("HTTP body read failed for %s: %v", domain, err)
			body = nil
		}

		return body, banner
	}

	log.Printf("HTTP banner fetch failed for %s (both HTTPS and HTTP)", domain)
	return nil, ""
}

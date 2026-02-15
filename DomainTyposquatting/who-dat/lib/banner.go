package lib

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var bannerClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	},
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return fmt.Errorf("too many redirects")
		}
		return nil
	},
}

// FetchHTTPBanner fetches the HTTP Server header and page body from a domain.
// Tries HTTPS first, then falls back to HTTP. Each scheme is retried once on failure.
// Body is capped at 1 MB for hashing.
func FetchHTTPBanner(ctx context.Context, domain string) (body []byte, banner string) {
	for _, scheme := range []string{"https", "http"} {
		var fetchErr error
		err := withRetry(2, 1*time.Second, fmt.Sprintf("HTTP[%s://%s]", scheme, domain), func() error {
			url := fmt.Sprintf("%s://%s", scheme, domain)
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				fetchErr = err
				return err
			}
			req.Header.Set("User-Agent", userAgent)
			req.Header.Set("Accept", "text/html,application/xhtml+xml,*/*")
			req.Header.Set("Accept-Language", "en-US,en;q=0.9")

			resp, err := bannerClient.Do(req)
			if err != nil {
				fetchErr = err
				return err
			}
			defer resp.Body.Close()

			banner = resp.Header.Get("Server")

			body, err = io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			if err != nil {
				log.Printf("HTTP body read failed for %s: %v", domain, err)
				body = nil
			}
			return nil
		})

		if err == nil {
			return body, banner
		}
		log.Printf("HTTP %s failed for %s: %v", scheme, domain, fetchErr)
	}

	log.Printf("HTTP banner fetch failed for %s (all schemes exhausted)", domain)
	return nil, ""
}

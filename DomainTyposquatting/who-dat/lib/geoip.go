package lib

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var geoIPClient = &http.Client{
	Timeout: 10 * time.Second,
}

type ipAPIResponse struct {
	Status      string  `json:"status"`
	Message     string  `json:"message"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Query       string  `json:"query"`
}

// LookupGeoIP queries ip-api.com for geolocation data of an IP address.
// Retries up to 3 times with exponential backoff on transient failures.
// Note: ip-api.com free tier only supports HTTP (HTTPS requires paid plan).
func LookupGeoIP(ctx context.Context, ip string) *GeoIPResult {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,city,isp,org,as,lat,lon,query", ip)

	var result *GeoIPResult

	err := withRetry(3, 500*time.Millisecond, fmt.Sprintf("GeoIP[%s]", ip), func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("create request: %w", err)
		}
		req.Header.Set("User-Agent", userAgent)

		resp, err := geoIPClient.Do(req)
		if err != nil {
			return fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()

		// Handle rate limiting explicitly
		if resp.StatusCode == http.StatusTooManyRequests {
			return fmt.Errorf("rate limited (429)")
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status %d", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("read body: %w", err)
		}

		var apiResp ipAPIResponse
		if err := json.Unmarshal(body, &apiResp); err != nil {
			return fmt.Errorf("parse JSON: %w", err)
		}

		if apiResp.Status != "success" {
			return fmt.Errorf("API returned: %s", apiResp.Message)
		}

		result = &GeoIPResult{
			IP:          apiResp.Query,
			Country:     apiResp.Country,
			CountryCode: apiResp.CountryCode,
			City:        apiResp.City,
			ISP:         apiResp.ISP,
			Org:         apiResp.Org,
			AS:          apiResp.AS,
			Lat:         apiResp.Lat,
			Lon:         apiResp.Lon,
		}
		return nil
	})

	if err != nil {
		log.Printf("GeoIP lookup failed for %s after retries: %v", ip, err)
		return nil
	}
	return result
}

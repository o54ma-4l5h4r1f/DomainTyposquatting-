package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

var geoIPClient = &http.Client{
	Timeout: 3 * time.Second,
}

type ipAPIResponse struct {
	Status      string  `json:"status"`
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
func LookupGeoIP(ip string) *GeoIPResult {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,country,countryCode,city,isp,org,as,lat,lon,query", ip)

	resp, err := geoIPClient.Get(url)
	if err != nil {
		log.Printf("GeoIP lookup failed for %s: %v", ip, err)
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("GeoIP read body failed for %s: %v", ip, err)
		return nil
	}

	var apiResp ipAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		log.Printf("GeoIP parse failed for %s: %v", ip, err)
		return nil
	}

	if apiResp.Status != "success" {
		log.Printf("GeoIP lookup returned non-success for %s", ip)
		return nil
	}

	return &GeoIPResult{
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
}

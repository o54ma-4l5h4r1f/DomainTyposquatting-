package lib

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	whoisparser "github.com/likexian/whois-parser"
)

// RDAP response structures

type rdapResponse struct {
	Handle     string       `json:"handle"`
	LDHName    string       `json:"ldhName"`
	Status     []string     `json:"status"`
	Events     []rdapEvent  `json:"events"`
	Entities   []rdapEntity `json:"entities"`
	Nameservers []rdapNS    `json:"nameservers"`
	SecureDNS  *rdapDNSSec  `json:"secureDNS"`
	Links      []rdapLink   `json:"links"`
	Port43     string       `json:"port43"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
}

type rdapEntity struct {
	Handle   string       `json:"handle"`
	Roles    []string     `json:"roles"`
	VCardArray interface{} `json:"vcardArray"`
	Entities []rdapEntity `json:"entities"`
}

type rdapNS struct {
	LDHName string `json:"ldhName"`
}

type rdapDNSSec struct {
	DelegationSigned bool `json:"delegationSigned"`
}

type rdapLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

var rdapClient = &http.Client{
	Timeout: 10 * time.Second,
}

// GetRDAP performs an RDAP lookup and maps the result to whoisparser.WhoisInfo
func GetRDAP(domain string) (whoisparser.WhoisInfo, error) {
	url := fmt.Sprintf("https://rdap.org/domain/%s", domain)

	resp, err := rdapClient.Get(url)
	if err != nil {
		return whoisparser.WhoisInfo{}, fmt.Errorf("RDAP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return whoisparser.WhoisInfo{}, fmt.Errorf("RDAP returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return whoisparser.WhoisInfo{}, fmt.Errorf("RDAP read body failed: %w", err)
	}

	var rdap rdapResponse
	if err := json.Unmarshal(body, &rdap); err != nil {
		return whoisparser.WhoisInfo{}, fmt.Errorf("RDAP parse failed: %w", err)
	}

	return mapRDAPToWhoisInfo(domain, &rdap), nil
}

func mapRDAPToWhoisInfo(domain string, rdap *rdapResponse) whoisparser.WhoisInfo {
	info := whoisparser.WhoisInfo{}

	// Build Domain
	d := &whoisparser.Domain{
		ID:     rdap.Handle,
		Domain: domain,
	}

	// Extract name and extension
	parts := strings.SplitN(domain, ".", 2)
	if len(parts) == 2 {
		d.Name = parts[0]
		d.Extension = parts[1]
	}

	d.WhoisServer = rdap.Port43
	d.Status = rdap.Status

	// Nameservers
	for _, ns := range rdap.Nameservers {
		if ns.LDHName != "" {
			d.NameServers = append(d.NameServers, strings.ToLower(ns.LDHName))
		}
	}

	// DNSSEC
	if rdap.SecureDNS != nil {
		d.DNSSec = rdap.SecureDNS.DelegationSigned
	}

	// Events (dates)
	for _, ev := range rdap.Events {
		t, err := time.Parse(time.RFC3339, ev.EventDate)
		switch ev.EventAction {
		case "registration":
			d.CreatedDate = ev.EventDate
			if err == nil {
				d.CreatedDateInTime = &t
			}
		case "last changed":
			d.UpdatedDate = ev.EventDate
			if err == nil {
				d.UpdatedDateInTime = &t
			}
		case "expiration":
			d.ExpirationDate = ev.EventDate
			if err == nil {
				d.ExpirationDateInTime = &t
			}
		}
	}

	info.Domain = d

	// Map entities by role
	for _, entity := range rdap.Entities {
		contact := extractContact(&entity)
		for _, role := range entity.Roles {
			switch role {
			case "registrar":
				info.Registrar = contact
			case "registrant":
				info.Registrant = contact
			case "administrative":
				info.Administrative = contact
			case "technical":
				info.Technical = contact
			case "billing":
				info.Billing = contact
			}
		}
		// Some RDAP responses nest registrant/admin/tech under the registrar entity
		for _, sub := range entity.Entities {
			subContact := extractContact(&sub)
			for _, role := range sub.Roles {
				switch role {
				case "registrant":
					if info.Registrant == nil {
						info.Registrant = subContact
					}
				case "administrative":
					if info.Administrative == nil {
						info.Administrative = subContact
					}
				case "technical":
					if info.Technical == nil {
						info.Technical = subContact
					}
				case "billing":
					if info.Billing == nil {
						info.Billing = subContact
					}
				}
			}
		}
	}

	return info
}

// extractContact parses a vCard from an RDAP entity into a whoisparser.Contact
func extractContact(entity *rdapEntity) *whoisparser.Contact {
	c := &whoisparser.Contact{
		ID: entity.Handle,
	}

	vcard := parseVCard(entity.VCardArray)
	if vcard == nil {
		return c
	}

	c.Name = vcard.fn
	c.Organization = vcard.org
	c.Email = vcard.email
	c.Phone = vcard.tel
	c.Street = vcard.street
	c.City = vcard.city
	c.Province = vcard.region
	c.PostalCode = vcard.postalCode
	c.Country = vcard.country

	return c
}

type vcardData struct {
	fn         string
	org        string
	email      string
	tel        string
	street     string
	city       string
	region     string
	postalCode string
	country    string
}

// parseVCard extracts fields from the jCard (JSON vCard) format used in RDAP.
// The vcardArray is: ["vcard", [ [prop, params, type, value], ... ]]
func parseVCard(vcardArray interface{}) *vcardData {
	arr, ok := vcardArray.([]interface{})
	if !ok || len(arr) < 2 {
		return nil
	}

	properties, ok := arr[1].([]interface{})
	if !ok {
		return nil
	}

	v := &vcardData{}

	for _, prop := range properties {
		entry, ok := prop.([]interface{})
		if !ok || len(entry) < 4 {
			continue
		}

		propName, _ := entry[0].(string)

		switch propName {
		case "fn":
			v.fn = vcardStringValue(entry[3])
		case "org":
			v.org = vcardStringValue(entry[3])
		case "email":
			v.email = vcardStringValue(entry[3])
		case "tel":
			v.tel = vcardStringValue(entry[3])
		case "adr":
			// adr value is an array: [pobox, ext, street, city, region, postal, country]
			adr := vcardAdrValue(entry[3])
			if len(adr) >= 7 {
				v.street = adr[2]
				v.city = adr[3]
				v.region = adr[4]
				v.postalCode = adr[5]
				v.country = adr[6]
			}
		}
	}

	return v
}

func vcardStringValue(val interface{}) string {
	if s, ok := val.(string); ok {
		return s
	}
	return ""
}

func vcardAdrValue(val interface{}) []string {
	arr, ok := val.([]interface{})
	if !ok {
		return nil
	}
	result := make([]string, len(arr))
	for i, v := range arr {
		result[i], _ = v.(string)
	}
	return result
}

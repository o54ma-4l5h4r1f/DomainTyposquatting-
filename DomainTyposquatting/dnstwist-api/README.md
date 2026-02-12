# DNSTwist API - Full Featured

REST API for [dnstwist](https://github.com/elceef/dnstwist) with **all features** exposed.

## Features

| Feature | Endpoint | Description |
|---------|----------|-------------|
| Domain Fuzzing | `/scan` | Multiple algorithms (homoglyph, bitsquatting, etc.) |
| DNS Lookups | `/scan` | A, AAAA, MX, NS records |
| WHOIS | `/scan?whois=true` | Registration info lookup |
| GeoIP | `/scan?geoip=true` | Country geolocation |
| Fuzzy Hashing | `/scan?lsh=ssdeep` | Phishing page detection |
| MX Check | `/scan?mxcheck=true` | Email interception detection |
| Banners | `/scan?banners=true` | HTTP/SMTP banner grabbing |
| CSV Export | `/scan/csv` | Download results as CSV |
| Permutations | `/permutations` | Fast, no DNS lookups |

## Quick Start

```bash
# Build and run
docker build -t dnstwist-api .
docker run -p 8000:8000 dnstwist-api

# Or with docker-compose
docker-compose up --build
```

## API Endpoints

### Health Check
```bash
curl http://localhost:8000/
```

### Basic Scan
```bash
curl "http://localhost:8000/scan?domain=example.com"
```

### Registered Domains Only
```bash
curl "http://localhost:8000/scan?domain=example.com&registered=true"
```

### Specific Fuzzers
```bash
curl "http://localhost:8000/scan?domain=example.com&fuzzers=homoglyph,bitsquatting"
```

### Full Scan (All Features)
```bash
curl "http://localhost:8000/scan?domain=example.com&registered=true&whois=true&geoip=true&mxcheck=true&banners=true"
```

### Phishing Detection (Fuzzy Hashing)
```bash
# Using ssdeep
curl "http://localhost:8000/scan?domain=example.com&registered=true&lsh=ssdeep"

# Using tlsh
curl "http://localhost:8000/scan?domain=example.com&registered=true&lsh=tlsh"
```

### Custom DNS Servers
```bash
curl "http://localhost:8000/scan?domain=example.com&nameservers=8.8.8.8,1.1.1.1"
```

### CSV Export
```bash
curl "http://localhost:8000/scan/csv?domain=example.com&registered=true" -o results.csv
```

### Permutations Only (No DNS)
```bash
# JSON format
curl "http://localhost:8000/permutations?domain=example.com"

# Plain text (one per line)
curl "http://localhost:8000/permutations/list?domain=example.com"
```

### POST Request (Complex Scans)
```bash
curl -X POST "http://localhost:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "registered": true,
    "threads": 20,
    "whois": true,
    "geoip": true,
    "lsh": "ssdeep",
    "mxcheck": true
  }'
```

## Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `domain` | string | required | Target domain to scan |
| `registered` | bool | false | Only return registered domains |
| `fuzzers` | string | all | Comma-separated fuzzer list |
| `nameservers` | string | system | Custom DNS servers |
| `threads` | int | 10 | Number of threads (1-100) |
| `whois` | bool | false | WHOIS lookup |
| `geoip` | bool | false | GeoIP country lookup |
| `lsh` | string | null | Fuzzy hash: `ssdeep` or `tlsh` |
| `lsh_url` | string | null | Custom URL for LSH comparison |
| `mxcheck` | bool | false | Check MX for email interception |
| `banners` | bool | false | Grab HTTP/SMTP banners |
| `useragent` | string | null | Custom User-Agent |

## Available Fuzzers

| Fuzzer | Description |
|--------|-------------|
| `addition` | Appends characters |
| `bitsquatting` | Single bit flips |
| `homoglyph` | Unicode lookalikes (IDN) |
| `hyphenation` | Adds hyphens |
| `insertion` | Inserts characters |
| `omission` | Removes characters |
| `repetition` | Repeats characters |
| `replacement` | Adjacent keyboard keys |
| `subdomain` | Prepends common words |
| `transposition` | Swaps adjacent chars |
| `vowel-swap` | Swaps vowels |
| `dictionary` | Dictionary word substitution |
| `tld-swap` | TLD variations |

## Response Format

```json
{
  "domain": "example.com",
  "total": 1547,
  "registered": 23,
  "results": [
    {
      "fuzzer": "homoglyph",
      "domain": "examp1e.com",
      "dns_a": ["192.0.2.1"],
      "dns_mx": ["mail.example.com"],
      "geoip": "US",
      "whois_registrar": "GoDaddy",
      "whois_created": "2020-01-15"
    }
  ]
}
```

## Swagger Docs

Interactive API documentation available at:
```
http://localhost:8000/docs
```

## Deploy to Azure

```bash
chmod +x deploy.sh
./deploy.sh
```

### Deployment Options

| Option | Cost | Best For |
|--------|------|----------|
| **1. App Service Free (F1)** | $0/month | Dev/testing (60 min CPU/day limit) |
| **2. App Service Basic (B1)** | ~$13/month | Production, always-on |
| **3. App Service Shared (D1)** | ~$10/month | Light production |
| **4. Container Apps** | Pay-per-use | Auto-scaling, scales to zero |
| **5. Container Instances** | ~$30/month | Simple, always-on |

### Manual App Service Deployment

```bash
# Login
az login

# Create resource group
az group create --name dnstwist-rg --location eastus

# Create App Service Plan (Free tier)
az appservice plan create \
  --name dnstwist-plan \
  --resource-group dnstwist-rg \
  --sku F1 --is-linux

# Create Web App
az webapp create \
  --name dnstwist-api \
  --resource-group dnstwist-rg \
  --plan dnstwist-plan \
  --runtime "PYTHON:3.11"

# Configure startup
az webapp config set \
  --name dnstwist-api \
  --resource-group dnstwist-rg \
  --startup-file "gunicorn -w 2 -k uvicorn.workers.UvicornWorker api:app --bind 0.0.0.0:8000"

# Deploy code
zip -r app.zip api.py requirements.txt
az webapp deploy --name dnstwist-api --resource-group dnstwist-rg --src-path app.zip --type zip
```

### Delete Resources
```bash
az group delete --name dnstwist-rg --yes
```

## Files

```
├── api.py              # Full-featured FastAPI wrapper
├── requirements.txt    # Python dependencies
├── Dockerfile          # For container deployments
├── docker-compose.yml  # Local development
├── startup.sh          # App Service startup command
└── deploy.sh           # Azure deployment (all options)
```

## License

Apache-2.0 (same as dnstwist)

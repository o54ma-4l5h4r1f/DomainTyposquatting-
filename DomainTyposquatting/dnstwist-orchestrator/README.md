# DNSTwist Orchestrator - Azure Function App

Orchestrates domain scanning via the DNSTwist API and stores results in Azure Blob Storage.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Your App      │───▶│   Orchestrator   │───▶│  DNSTwist API   │
│                 │    │  (Azure Func)    │    │  (Container)    │
└─────────────────┘    └────────┬─────────┘    └────────┬────────┘
                                │                       │
                                │◀──────────────────────┘
                                │      (callback)
                                ▼
                       ┌─────────────────┐
                       │  Azure Storage  │
                       │  - Blob: domains│
                       │  - Table: tasks │
                       └─────────────────┘
```

## Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/scan` | Submit domains for scanning |
| POST | `/api/callback` | Receive results from DNSTwist API |
| GET | `/api/status` | Get pending/running scans |
| GET | `/api/results` | Get domains found for customer/month |
| GET | `/api/customers` | List all customers |
| GET | `/api/health` | Health check |

## Storage Structure

```
Azure Blob Storage (dnstwist-results)
├── AcmeCorp/
│   ├── all_domains.txt        # Cumulative list (deduplicated)
│   ├── 2026-01/
│   │   └── domains.txt        # Domains found in January 2026
│   └── 2026-02/
│       └── domains.txt        # Domains found in February 2026
├── AnotherCustomer/
│   ├── all_domains.txt
│   └── ...
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DNSTWIST_API_URL` | URL of your DNSTwist API | Yes |
| `DNSTWIST_API_KEY` | API key for DNSTwist API | Yes |
| `AzureWebJobsStorage` | Azure Storage connection string | Yes (auto) |
| `BLOB_CONTAINER_NAME` | Container name for results | No (default: `dnstwist-results`) |
| `TABLE_NAME` | Table name for task tracking | No (default: `dnstwisttasks`) |

## Deployment

### Prerequisites

1. Azure CLI installed and logged in (`az login`)
2. DNSTwist API deployed and running

### Deploy

1. Edit `deploy.sh` and set:
   - `DNSTWIST_API_URL` - Your DNSTwist API URL
   - `DNSTWIST_API_KEY` - Your DNSTwist API key

2. Run:
   ```bash
   chmod +x deploy.sh
   ./deploy.sh
   ```

3. Update DNSTwist API callback URL:
   ```bash
   az containerapp update \
     --name YOUR_CONTAINER_APP \
     --resource-group dnstwist-rg \
     --set-env-vars "CALLBACK_URL=https://YOUR_FUNCTION.azurewebsites.net/api/callback?code=YOUR_FUNCTION_KEY"
   ```

## API Usage

### Submit Scan

Submit multiple domains for scanning:

```bash
curl -X POST "https://YOUR_FUNCTION.azurewebsites.net/api/scan?code=FUNCTION_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": "AcmeCorp",
    "domains": ["example.com", "another.com", "third.com"],
    "registered": true
  }'
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `customer` | string | Yes | Customer name for organizing results |
| `domains` | array | Yes | List of domains to scan |
| `registered` | bool | No | Only return registered domains (default: true) |
| `fuzzers` | string | No | Comma-separated list of fuzzers |
| `whois` | bool | No | Include WHOIS data |
| `geoip` | bool | No | Include GeoIP data |
| `callback_url` | string | No | Override callback URL |

**Response:**

```json
{
  "status": "submitted",
  "customer": "AcmeCorp",
  "domains_submitted": 3,
  "tracking_ids": ["uuid1", "uuid2", "uuid3"],
  "callback_url": "https://..."
}
```

### Get Status

Check pending/running scans:

```bash
# All pending
curl "https://YOUR_FUNCTION.azurewebsites.net/api/status?code=FUNCTION_KEY"

# Filter by customer
curl "https://YOUR_FUNCTION.azurewebsites.net/api/status?code=FUNCTION_KEY&customer=AcmeCorp"
```

**Response:**

```json
{
  "pending_count": 2,
  "by_customer": {
    "AcmeCorp": [
      {
        "domain": "example.com",
        "tracking_id": "abc-123",
        "submitted_at": "2026-01-22T10:30:00Z",
        "status": "pending"
      }
    ]
  }
}
```

### Get Results

Retrieve found domains:

```bash
# Current month
curl "https://YOUR_FUNCTION.azurewebsites.net/api/results?code=FUNCTION_KEY&customer=AcmeCorp"

# Specific month
curl "https://YOUR_FUNCTION.azurewebsites.net/api/results?code=FUNCTION_KEY&customer=AcmeCorp&month=2026-01"

# All-time cumulative list
curl "https://YOUR_FUNCTION.azurewebsites.net/api/results?code=FUNCTION_KEY&customer=AcmeCorp&all_time=true"
```

**Response:**

```json
{
  "customer": "AcmeCorp",
  "period": "2026-01",
  "domains_count": 45,
  "domains": [
    "examp1e.com",
    "exampl3.com",
    "example-login.com",
    "..."
  ]
}
```

### List Customers

```bash
curl "https://YOUR_FUNCTION.azurewebsites.net/api/customers?code=FUNCTION_KEY"
```

**Response:**

```json
{
  "customers": ["AcmeCorp", "AnotherCustomer"],
  "count": 2
}
```

## Workflow Example

```bash
# 1. Submit scan for multiple domains
curl -X POST "https://func.azurewebsites.net/api/scan?code=KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "customer": "AcmeCorp",
    "domains": ["acme.com", "acmecorp.com", "acme-inc.com"]
  }'

# 2. Check status (domains being processed)
curl "https://func.azurewebsites.net/api/status?code=KEY&customer=AcmeCorp"

# 3. Wait for callbacks... (async, results stored automatically)

# 4. Get results for this month
curl "https://func.azurewebsites.net/api/results?code=KEY&customer=AcmeCorp"

# 5. Get all-time cumulative domains (deduplicated)
curl "https://func.azurewebsites.net/api/results?code=KEY&customer=AcmeCorp&all_time=true"
```

## Features

- ✅ **Async Processing**: Submit and forget - results come via callback
- ✅ **Task Tracking**: Monitor pending scans via `/api/status`
- ✅ **Organized Storage**: Results stored by customer and month
- ✅ **Deduplication**: All-time list automatically removes duplicates
- ✅ **Scalable**: Azure Functions scale automatically
- ✅ **Cost Effective**: Consumption plan - pay only for execution

## Cost Estimate

- **Azure Functions**: ~$0.20 per million executions
- **Blob Storage**: ~$0.02/GB/month
- **Table Storage**: ~$0.07/GB/month

Total for moderate usage: **< $5/month**

## Local Development

1. Install Azure Functions Core Tools
2. Update `local.settings.json` with your values
3. Run:
   ```bash
   func start
   ```

## Troubleshooting

### Callback not received
- Check DNSTwist API `CALLBACK_URL` is correctly set
- Verify function key is included in callback URL
- Check function logs in Azure Portal

### Results not appearing
- Check `/api/status` for pending tasks
- Verify storage account connection
- Check function logs for errors

### Permission errors
- Ensure storage account allows table/blob access
- Check function app managed identity permissions

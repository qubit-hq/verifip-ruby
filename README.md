# VerifIP Ruby SDK

Official Ruby SDK for the [VerifIP](https://verifip.com) IP fraud scoring API.

Requires **Ruby 3.1+**. Zero runtime dependencies -- uses only Ruby stdlib (`net/http`, `json`, `uri`).

## Installation

### Gemfile

```ruby
gem "verifip", "~> 0.1.0"
```

### Manual

```bash
gem install verifip
```

## Quick Start

```ruby
require "verifip"

client = VerifIP::Client.new(api_key: "vip_your_key")
result = client.check("185.220.101.1")

puts result.fraud_score   # 0-100
puts result.vpn?          # true/false
puts result.country_code  # "DE"
```

## Configuration

```ruby
client = VerifIP::Client.new(
  api_key:     "vip_your_key",
  base_url:    "https://api.verifip.com",  # optional
  timeout:     15,                          # seconds, default: 30
  max_retries: 5                            # default: 3
)
```

## Methods

### `check(ip)` -- Single IP Check

```ruby
result = client.check("185.220.101.1")

result.request_id        # unique request ID
result.ip                # queried IP
result.fraud_score       # 0-100 risk score
result.is_proxy          # proxy detected
result.proxy?            # alias for is_proxy
result.is_vpn            # VPN detected
result.vpn?              # alias for is_vpn
result.is_tor            # Tor exit node
result.tor?              # alias for is_tor
result.is_datacenter     # datacenter IP
result.datacenter?       # alias for is_datacenter
result.country_code      # "US", "DE", etc.
result.country_name      # "United States", etc.
result.region            # state/province
result.city              # city name
result.isp               # ISP name
result.asn               # AS number
result.connection_type   # "residential", "datacenter", etc.
result.hostname          # reverse DNS hostname
result.signal_breakdown  # Hash of signal name => score
result.error             # error message if check failed, nil otherwise
```

### `check_batch(ips)` -- Batch Check

Check up to 100 IPs in a single request (Starter plan or higher):

```ruby
batch = client.check_batch(["8.8.8.8", "1.1.1.1", "185.220.101.1"])

batch.results.each do |r|
  puts "#{r.ip} -> score=#{r.fraud_score}"
end
```

### `health` -- Health Check

Check API server status (no authentication required):

```ruby
health = client.health
puts health.status          # "ok"
puts health.version         # API version
puts health.uptime_seconds  # server uptime
puts health.redis           # "connected"
puts health.postgres        # "connected"
```

### Rate Limit Info

After any API call, inspect the most recent rate limit headers:

```ruby
info = client.rate_limit_info
if info
  puts info.limit      # max requests
  puts info.remaining  # remaining
  puts info.reset      # Time object
end
```

## Error Handling

All errors inherit from `VerifIP::VerifIPError` (which inherits from `StandardError`):

| Error | HTTP Status | When |
|---|---|---|
| `AuthenticationError` | 401, 403 | Invalid or disabled API key |
| `RateLimitError` | 429 | Daily request limit exceeded |
| `InvalidRequestError` | 400 | Malformed IP, bad request body |
| `ServerError` | 5xx | Server-side errors |

```ruby
begin
  result = client.check("185.220.101.1")
rescue VerifIP::AuthenticationError => e
  puts "Bad API key: #{e.message}"
rescue VerifIP::RateLimitError => e
  puts "Rate limited, retry after: #{e.retry_after}s"
rescue VerifIP::InvalidRequestError => e
  puts "Bad request: #{e.message}"
rescue VerifIP::ServerError => e
  puts "Server error: #{e.status_code}"
rescue VerifIP::VerifIPError => e
  puts "API error: #{e.message}"
end
```

All errors expose:
- `status_code` -- HTTP status code (0 for connection errors)
- `error_code` -- machine-readable error code
- `retry_after` -- seconds to wait before retrying (may be nil)

## Automatic Retries

The SDK automatically retries on 429 and 5xx errors with exponential backoff and jitter. Configure with `max_retries:` (default 3, set to 0 to disable).

## License

MIT

#!/usr/bin/env ruby
# frozen_string_literal: true

require "verifip"

api_key = ENV.fetch("VERIFIP_API_KEY") do
  warn "Set VERIFIP_API_KEY environment variable"
  exit 1
end

client = VerifIP::Client.new(
  api_key: api_key,
  timeout: 15,
  max_retries: 3
)

# Health check (no auth required)
health = client.health
puts "API Status: #{health.status}"
puts "API Version: #{health.version}"
puts

# Single IP check
begin
  result = client.check("185.220.101.1")
  puts "=== Single IP Check ==="
  puts "IP:              #{result.ip}"
  puts "Fraud Score:     #{result.fraud_score}"
  puts "Is Proxy:        #{result.proxy?}"
  puts "Is VPN:          #{result.vpn?}"
  puts "Is Tor:          #{result.tor?}"
  puts "Is Datacenter:   #{result.datacenter?}"
  puts "Country:         #{result.country_name} (#{result.country_code})"
  puts "City:            #{result.city}"
  puts "ISP:             #{result.isp}"
  puts "ASN:             #{result.asn}"
  puts "Connection Type: #{result.connection_type}"
  puts "Signals:         #{result.signal_breakdown}"
  puts

  # Rate limit info
  if (info = client.rate_limit_info)
    puts "Rate Limit: #{info.remaining}/#{info.limit} remaining"
  end

  # Batch check
  batch = client.check_batch(["8.8.8.8", "1.1.1.1", "185.220.101.1"])
  puts
  puts "=== Batch Check ==="
  batch.results.each do |r|
    puts "  #{r.ip} -> score=#{r.fraud_score}, proxy=#{r.proxy?}, vpn=#{r.vpn?}"
  end

rescue VerifIP::AuthenticationError => e
  warn "Authentication failed: #{e.message}"
rescue VerifIP::RateLimitError => e
  warn "Rate limited. Retry after: #{e.retry_after}s"
rescue VerifIP::VerifIPError => e
  warn "API error (#{e.status_code}): #{e.message}"
end

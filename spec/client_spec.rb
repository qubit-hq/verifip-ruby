# frozen_string_literal: true

require "spec_helper"

RSpec.describe VerifIP::Client do
  let(:api_key)  { "vip_test_key_123" }
  let(:base_url) { "https://api.verifip.com" }
  let(:client)   { described_class.new(api_key: api_key, base_url: base_url, max_retries: 0) }

  let(:check_response_body) do
    {
      request_id: "req_abc123",
      ip: "185.220.101.1",
      fraud_score: 85,
      is_proxy: true,
      is_vpn: false,
      is_tor: true,
      is_datacenter: true,
      country_code: "DE",
      country_name: "Germany",
      region: "Hesse",
      city: "Frankfurt",
      isp: "Tor Exit Node",
      asn: 12345,
      connection_type: "datacenter",
      hostname: "tor-exit.example.com",
      signal_breakdown: { "tor_exit" => 40, "datacenter" => 30, "geo_risk" => 15 },
      error: nil
    }.to_json
  end

  let(:health_response_body) do
    {
      status: "ok",
      version: "1.2.3",
      data_loaded_at: "2025-01-15T10:30:00Z",
      redis: "connected",
      postgres: "connected",
      uptime_seconds: 86400
    }.to_json
  end

  describe "#initialize" do
    it "raises ArgumentError when api_key is nil" do
      expect { described_class.new(api_key: nil) }.to raise_error(ArgumentError, /api_key/)
    end

    it "raises ArgumentError when api_key is empty" do
      expect { described_class.new(api_key: "") }.to raise_error(ArgumentError, /api_key/)
    end

    it "creates a client with valid api_key" do
      c = described_class.new(api_key: "vip_test")
      expect(c).to be_a(described_class)
    end
  end

  describe "#check" do
    it "returns a CheckResponse for a valid IP" do
      stub_request(:get, "#{base_url}/v1/check?ip=185.220.101.1")
        .with(headers: {
          "Authorization" => "Bearer #{api_key}",
          "User-Agent"    => "verifip-ruby/#{VerifIP::VERSION}"
        })
        .to_return(
          status: 200,
          body: check_response_body,
          headers: {
            "Content-Type"          => "application/json",
            "X-RateLimit-Limit"     => "1000",
            "X-RateLimit-Remaining" => "999",
            "X-RateLimit-Reset"     => "1700000000"
          }
        )

      result = client.check("185.220.101.1")

      expect(result).to be_a(VerifIP::CheckResponse)
      expect(result.ip).to eq("185.220.101.1")
      expect(result.fraud_score).to eq(85)
      expect(result.is_proxy).to be true
      expect(result.proxy?).to be true
      expect(result.is_tor).to be true
      expect(result.tor?).to be true
      expect(result.is_vpn).to be false
      expect(result.vpn?).to be false
      expect(result.is_datacenter).to be true
      expect(result.country_code).to eq("DE")
      expect(result.country_name).to eq("Germany")
      expect(result.city).to eq("Frankfurt")
      expect(result.isp).to eq("Tor Exit Node")
      expect(result.asn).to eq(12345)
      expect(result.connection_type).to eq("datacenter")
      expect(result.hostname).to eq("tor-exit.example.com")
      expect(result.signal_breakdown).to eq({ "tor_exit" => 40, "datacenter" => 30, "geo_risk" => 15 })
      expect(result.error).to be_nil
    end

    it "raises ArgumentError when ip is empty" do
      expect { client.check("") }.to raise_error(ArgumentError)
    end

    it "parses rate limit headers" do
      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(
          status: 200,
          body: check_response_body,
          headers: {
            "X-RateLimit-Limit"     => "1000",
            "X-RateLimit-Remaining" => "500",
            "X-RateLimit-Reset"     => "1700000000"
          }
        )

      client.check("8.8.8.8")
      info = client.rate_limit_info

      expect(info).to be_a(VerifIP::RateLimitInfo)
      expect(info.limit).to eq(1000)
      expect(info.remaining).to eq(500)
      expect(info.reset).to be_a(Time)
    end
  end

  describe "#check_batch" do
    it "returns a BatchResponse for valid IPs" do
      batch_body = { results: [JSON.parse(check_response_body)] }.to_json

      stub_request(:post, "#{base_url}/v1/check/batch")
        .with(
          headers: { "Content-Type" => "application/json" },
          body: { ips: ["8.8.8.8", "1.1.1.1"] }.to_json
        )
        .to_return(status: 200, body: batch_body)

      result = client.check_batch(["8.8.8.8", "1.1.1.1"])

      expect(result).to be_a(VerifIP::BatchResponse)
      expect(result.size).to eq(1)
      expect(result.results.first.ip).to eq("185.220.101.1")
    end

    it "raises ArgumentError when ips is empty" do
      expect { client.check_batch([]) }.to raise_error(ArgumentError)
    end

    it "raises ArgumentError when ips exceeds 100" do
      ips = (1..101).map { |i| "1.1.1.#{i % 256}" }
      expect { client.check_batch(ips) }.to raise_error(ArgumentError, /100/)
    end
  end

  describe "#health" do
    it "returns a HealthResponse without auth" do
      stub_request(:get, "#{base_url}/health")
        .with { |req| !req.headers.key?("Authorization") }
        .to_return(status: 200, body: health_response_body)

      result = client.health

      expect(result).to be_a(VerifIP::HealthResponse)
      expect(result.status).to eq("ok")
      expect(result.version).to eq("1.2.3")
      expect(result.uptime_seconds).to eq(86400)
      expect(result.redis).to eq("connected")
      expect(result.postgres).to eq("connected")
    end
  end

  describe "error handling" do
    it "raises AuthenticationError on 401" do
      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(
          status: 401,
          body: { error: "invalid_key", message: "Invalid API key" }.to_json
        )

      expect { client.check("8.8.8.8") }.to raise_error(VerifIP::AuthenticationError) do |e|
        expect(e.status_code).to eq(401)
        expect(e.error_code).to eq("invalid_key")
      end
    end

    it "raises RateLimitError on 429" do
      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(
          status: 429,
          body: { error: "rate_limited", message: "Too many requests", retry_after: 60 }.to_json
        )

      expect { client.check("8.8.8.8") }.to raise_error(VerifIP::RateLimitError) do |e|
        expect(e.status_code).to eq(429)
        expect(e.retry_after).to eq(60)
      end
    end

    it "raises InvalidRequestError on 400" do
      stub_request(:get, "#{base_url}/v1/check?ip=invalid")
        .to_return(
          status: 400,
          body: { error: "invalid_ip", message: "Invalid IP address" }.to_json
        )

      expect { client.check("invalid") }.to raise_error(VerifIP::InvalidRequestError) do |e|
        expect(e.status_code).to eq(400)
      end
    end

    it "raises ServerError on 500" do
      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(status: 500, body: { error: "internal", message: "Server error" }.to_json)

      expect { client.check("8.8.8.8") }.to raise_error(VerifIP::ServerError) do |e|
        expect(e.status_code).to eq(500)
      end
    end
  end

  describe "retries" do
    it "retries on 429 and succeeds" do
      retry_client = described_class.new(api_key: api_key, base_url: base_url, max_retries: 1)

      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(
          { status: 429, body: { error: "rate_limited", message: "Slow down" }.to_json },
          { status: 200, body: check_response_body }
        )

      # Stub sleep to avoid actual delays in tests
      allow(retry_client).to receive(:sleep)

      result = retry_client.check("8.8.8.8")
      expect(result.fraud_score).to eq(85)
    end

    it "retries on 503 and succeeds" do
      retry_client = described_class.new(api_key: api_key, base_url: base_url, max_retries: 1)

      stub_request(:get, "#{base_url}/v1/check?ip=8.8.8.8")
        .to_return(
          { status: 503, body: { error: "unavailable", message: "Try again" }.to_json },
          { status: 200, body: check_response_body }
        )

      allow(retry_client).to receive(:sleep)

      result = retry_client.check("8.8.8.8")
      expect(result.fraud_score).to eq(85)
    end
  end
end

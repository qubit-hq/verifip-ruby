# frozen_string_literal: true

require "net/http"
require "uri"
require "json"

module VerifIP
  # Client for the VerifIP IP fraud scoring API.
  #
  # @example
  #   client = VerifIP::Client.new(api_key: "vip_your_key")
  #   result = client.check("185.220.101.1")
  #   puts result.fraud_score  # => 70
  #
  class Client
    DEFAULT_BASE_URL    = "https://api.verifip.com"
    DEFAULT_TIMEOUT     = 30
    DEFAULT_MAX_RETRIES = 3
    RETRYABLE_STATUSES  = [429, 500, 502, 503, 504].freeze
    USER_AGENT          = "verifip-ruby/#{VerifIP::VERSION}"

    # @return [RateLimitInfo, nil] most recently observed rate limit info
    def rate_limit_info
      @mutex.synchronize { @rate_limit_info }
    end

    # Create a new VerifIP client.
    #
    # @param api_key [String] your VerifIP API key (starts with "vip_")
    # @param base_url [String] API base URL (default: https://api.verifip.com)
    # @param timeout [Integer] request timeout in seconds (default: 30)
    # @param max_retries [Integer] max retry attempts on 429/5xx (default: 3)
    def initialize(api_key:, base_url: DEFAULT_BASE_URL, timeout: DEFAULT_TIMEOUT, max_retries: DEFAULT_MAX_RETRIES)
      raise ArgumentError, "api_key is required" if api_key.nil? || api_key.empty?

      @api_key         = api_key
      @base_url        = base_url.chomp("/")
      @timeout         = timeout
      @max_retries     = max_retries
      @rate_limit_info = nil
      @mutex           = Mutex.new
    end

    # Check a single IP address for fraud risk.
    #
    # @param ip [String] IPv4 or IPv6 address
    # @return [CheckResponse]
    # @raise [InvalidRequestError] if the IP is malformed or reserved
    # @raise [AuthenticationError] if the API key is invalid or disabled
    # @raise [RateLimitError] if the daily limit is exceeded
    def check(ip)
      raise ArgumentError, "ip is required" if ip.nil? || ip.empty?

      data = request(:get, "/v1/check?ip=#{URI.encode_uri_component(ip)}", auth: true)
      CheckResponse.from_hash(data)
    end

    # Check multiple IP addresses in a single request.
    #
    # Requires Starter plan or higher. Maximum 100 IPs per request.
    #
    # @param ips [Array<String>] list of IPv4/IPv6 addresses (1-100)
    # @return [BatchResponse]
    def check_batch(ips)
      raise ArgumentError, "ips list is required and cannot be empty" if ips.nil? || ips.empty?
      raise ArgumentError, "Maximum 100 IPs per batch request" if ips.size > 100

      body = JSON.generate({ ips: ips })
      data = request(:post, "/v1/check/batch", body: body, auth: true)
      BatchResponse.from_hash(data)
    end

    # Check API server health status. Does not require authentication.
    #
    # @return [HealthResponse]
    def health
      data = request(:get, "/health", auth: false)
      HealthResponse.from_hash(data)
    end

    def to_s = "VerifIP::Client(base_url=#{@base_url})"
    def inspect = to_s

    private

    def request(method, path, body: nil, auth: true)
      uri = URI("#{@base_url}#{path}")
      last_error = nil

      (@max_retries + 1).times do |attempt|
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = @timeout
        http.read_timeout = @timeout

        req = build_request(method, uri, body: body, auth: auth)

        begin
          response = http.request(req)
        rescue StandardError => e
          last_error = VerifIPError.new(
            "Connection error: #{e.message}",
            status_code: 0,
            error_code: "connection_error"
          )
          if attempt < @max_retries
            sleep(backoff_delay(attempt))
            next
          end
          raise last_error
        end

        status = response.code.to_i
        update_rate_limit(response)

        if status >= 200 && status < 300
          resp_body = response.body
          return (resp_body && !resp_body.empty?) ? JSON.parse(resp_body) : {}
        end

        # Parse error response
        error_data = begin
          JSON.parse(response.body || "")
        rescue JSON::ParserError
          {}
        end

        error_code  = error_data["error"] || ""
        message     = error_data["message"] || response.body || ""
        retry_after = error_data["retry_after"]

        err = make_error(status, error_code, message, retry_after)

        if RETRYABLE_STATUSES.include?(status) && attempt < @max_retries
          last_error = err
          delay = retry_after || (0.5 * (2**attempt))
          delay = [delay, 30].min
          delay += rand * 0.25 * delay
          sleep(delay)
          next
        end

        raise err
      end

      raise last_error || VerifIPError.new("Request failed after retries")
    end

    def build_request(method, uri, body: nil, auth: true)
      req = case method
            when :get
              Net::HTTP::Get.new(uri)
            when :post
              Net::HTTP::Post.new(uri)
            else
              raise ArgumentError, "Unsupported method: #{method}"
            end

      req["User-Agent"]   = USER_AGENT
      req["Accept"]       = "application/json"
      req["Authorization"] = "Bearer #{@api_key}" if auth

      if body
        req["Content-Type"] = "application/json"
        req.body = body
      end

      req
    end

    def update_rate_limit(response)
      info = RateLimitInfo.from_headers(response)
      @mutex.synchronize { @rate_limit_info = info } if info
    end

    def make_error(status, code, message, retry_after)
      kwargs = { status_code: status, error_code: code, retry_after: retry_after }
      case status
      when 400
        InvalidRequestError.new(message, **kwargs)
      when 401, 403
        AuthenticationError.new(message, **kwargs)
      when 429
        RateLimitError.new(message, **kwargs)
      when 500..599
        ServerError.new(message, **kwargs)
      else
        VerifIPError.new(message, **kwargs)
      end
    end

    def backoff_delay(attempt)
      0.5 * (2**attempt)
    end
  end
end

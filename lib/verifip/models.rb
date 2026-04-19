# frozen_string_literal: true

module VerifIP
  # Response from a single IP check containing fraud score, threat flags,
  # geolocation data, and signal breakdown.
  class CheckResponse
    FIELDS = %i[
      request_id ip fraud_score is_proxy is_vpn is_tor is_datacenter
      country_code country_name region city isp asn connection_type
      hostname signal_breakdown error
    ].freeze

    attr_reader(*FIELDS)

    def initialize(**kwargs)
      @request_id       = kwargs.fetch(:request_id, "")
      @ip               = kwargs.fetch(:ip, "")
      @fraud_score      = kwargs.fetch(:fraud_score, 0)
      @is_proxy         = kwargs.fetch(:is_proxy, false)
      @is_vpn           = kwargs.fetch(:is_vpn, false)
      @is_tor           = kwargs.fetch(:is_tor, false)
      @is_datacenter    = kwargs.fetch(:is_datacenter, false)
      @country_code     = kwargs.fetch(:country_code, "")
      @country_name     = kwargs.fetch(:country_name, "")
      @region           = kwargs.fetch(:region, "")
      @city             = kwargs.fetch(:city, "")
      @isp              = kwargs.fetch(:isp, "")
      @asn              = kwargs.fetch(:asn, 0)
      @connection_type  = kwargs.fetch(:connection_type, "")
      @hostname         = kwargs.fetch(:hostname, "")
      @signal_breakdown = kwargs.fetch(:signal_breakdown, {})
      @error            = kwargs.fetch(:error, nil)
    end

    # Build a CheckResponse from a parsed JSON hash.
    #
    # @param hash [Hash] parsed API response
    # @return [CheckResponse]
    def self.from_hash(hash)
      hash = _symbolize(hash)
      new(**hash.slice(*FIELDS))
    end

    def proxy?     = @is_proxy
    def vpn?       = @is_vpn
    def tor?       = @is_tor
    def datacenter? = @is_datacenter

    def to_h
      FIELDS.each_with_object({}) { |f, h| h[f] = send(f) }
    end

    def to_s
      "CheckResponse(ip=#{@ip}, fraud_score=#{@fraud_score}, proxy=#{@is_proxy}, vpn=#{@is_vpn})"
    end

    def inspect = to_s

    # @api private
    def self._symbolize(hash)
      hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
    end
    private_class_method :_symbolize
  end

  # Response from a batch IP check.
  class BatchResponse
    # @return [Array<CheckResponse>]
    attr_reader :results

    def initialize(results = [])
      @results = results.freeze
    end

    # Build a BatchResponse from a parsed JSON hash.
    #
    # @param hash [Hash] parsed API response with "results" key
    # @return [BatchResponse]
    def self.from_hash(hash)
      items = (hash["results"] || hash[:results] || []).map do |r|
        CheckResponse.from_hash(r)
      end
      new(items)
    end

    def size = @results.size

    def to_s = "BatchResponse(results=#{size})"
    def inspect = to_s
  end

  # Response from the health check endpoint.
  class HealthResponse
    attr_reader :status, :version, :data_loaded_at, :redis, :postgres, :uptime_seconds

    def initialize(**kwargs)
      @status         = kwargs.fetch(:status, "")
      @version        = kwargs.fetch(:version, "")
      @data_loaded_at = kwargs.fetch(:data_loaded_at, "")
      @redis          = kwargs.fetch(:redis, "")
      @postgres       = kwargs.fetch(:postgres, "")
      @uptime_seconds = kwargs.fetch(:uptime_seconds, 0)
    end

    # Build a HealthResponse from a parsed JSON hash.
    #
    # @param hash [Hash] parsed API response
    # @return [HealthResponse]
    def self.from_hash(hash)
      hash = hash.each_with_object({}) { |(k, v), h| h[k.to_sym] = v }
      new(**hash.slice(:status, :version, :data_loaded_at, :redis, :postgres, :uptime_seconds))
    end

    def to_s = "HealthResponse(status=#{@status}, version=#{@version})"
    def inspect = to_s
  end

  # Rate limit information parsed from response headers.
  class RateLimitInfo
    # @return [Integer] maximum requests in the current window
    attr_reader :limit

    # @return [Integer] remaining requests in the current window
    attr_reader :remaining

    # @return [Time, nil] time at which the window resets
    attr_reader :reset

    def initialize(limit:, remaining:, reset: nil)
      @limit     = limit
      @remaining = remaining
      @reset     = reset
    end

    # Parse rate limit info from HTTP response headers.
    #
    # @param headers [Hash, Net::HTTPResponse] response headers
    # @return [RateLimitInfo, nil] nil if rate limit headers are absent
    def self.from_headers(headers)
      limit_str = headers["X-RateLimit-Limit"] || headers["x-ratelimit-limit"]
      return nil if limit_str.nil?

      limit = limit_str.to_i
      remaining = (headers["X-RateLimit-Remaining"] || headers["x-ratelimit-remaining"] || "0").to_i

      reset_str = headers["X-RateLimit-Reset"] || headers["x-ratelimit-reset"]
      reset = nil
      if reset_str
        begin
          reset = Time.at(reset_str.to_i).utc
        rescue ArgumentError, TypeError
          # ignore
        end
      end

      new(limit: limit, remaining: remaining, reset: reset)
    end

    def to_s = "RateLimitInfo(limit=#{@limit}, remaining=#{@remaining}, reset=#{@reset})"
    def inspect = to_s
  end
end

# frozen_string_literal: true

module VerifIP
  # Base error class for all VerifIP API errors.
  class VerifIPError < StandardError
    # @return [Integer] HTTP status code (0 for connection errors)
    attr_reader :status_code

    # @return [String] machine-readable error code from the API
    attr_reader :error_code

    # @return [Integer, nil] suggested seconds to wait before retrying
    attr_reader :retry_after

    def initialize(message = nil, status_code: 0, error_code: "", retry_after: nil)
      super(message)
      @status_code = status_code
      @error_code  = error_code || ""
      @retry_after = retry_after
    end

    def to_s
      "#{self.class.name}(#{status_code}, '#{error_code}', '#{message}')"
    end
  end

  # Raised on 401 (invalid API key) or 403 (key disabled).
  class AuthenticationError < VerifIPError; end

  # Raised on 429 (rate limit exceeded). Check {#retry_after} for wait time.
  class RateLimitError < VerifIPError; end

  # Raised on 400 (invalid IP, bad request body).
  class InvalidRequestError < VerifIPError; end

  # Raised on 5xx server errors.
  class ServerError < VerifIPError; end
end

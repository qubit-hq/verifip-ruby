# frozen_string_literal: true

require_relative "verifip/version"
require_relative "verifip/errors"
require_relative "verifip/models"
require_relative "verifip/client"

module VerifIP
  # Convenience method to create a new client.
  #
  # @param api_key [String] your VerifIP API key
  # @param kwargs [Hash] additional options passed to {Client#initialize}
  # @return [Client]
  def self.client(api_key:, **kwargs)
    Client.new(api_key: api_key, **kwargs)
  end
end

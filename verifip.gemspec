require_relative "lib/verifip/version"

Gem::Specification.new do |s|
  s.name          = "verifip"
  s.version       = VerifIP::VERSION
  s.summary       = "Official Ruby SDK for the VerifIP IP fraud scoring API"
  s.description   = "Ruby client library for the VerifIP API. Check IP addresses " \
                     "for fraud risk, VPN/proxy/Tor detection, geolocation, and more."
  s.authors       = ["VerifIP"]
  s.email         = ["support@verifip.com"]
  s.homepage      = "https://github.com/verifip/verifip-ruby"
  s.license       = "MIT"

  s.required_ruby_version = ">= 3.1.0"

  s.files         = Dir["lib/**/*.rb", "README.md", "LICENSE", "verifip.gemspec"]
  s.require_paths = ["lib"]

  # Zero runtime dependencies — uses only Ruby stdlib (net/http, json, uri)

  s.add_development_dependency "rspec", "~> 3.13"
  s.add_development_dependency "webmock", "~> 3.23"

  s.metadata = {
    "bug_tracker_uri"   => "https://github.com/verifip/verifip-ruby/issues",
    "changelog_uri"     => "https://github.com/verifip/verifip-ruby/blob/main/CHANGELOG.md",
    "documentation_uri" => "https://docs.verifip.com",
    "homepage_uri"      => s.homepage,
    "source_code_uri"   => "https://github.com/verifip/verifip-ruby"
  }
end

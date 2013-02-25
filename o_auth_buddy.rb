require 'cgi'
require 'uri'
require 'base64'
require 'openssl'
require 'time'

class OAuthBuddy
  def initialize consumer_key, consumer_secret, token, token_secret,
                method='GET', signature_method='HMAC-SHA1',
                base_url = 'https://api.twitter.com/1.1/search/tweets.json',
                version = '1.0', timezone = 'PST'
    @consumer_key = consumer_key
    @consumer_secret = consumer_secret
    @token = token
    @token_secret = token_secret
    @method = method.upcase
    @signature_method = signature_method
    @base_url = base_url
    @version = version
    @timezone = timezone
  end

  def authorization_header query_string
    nonce = random_nonce
    timestamp = current_timestamp
    signature = signature query_string, nonce, timestamp
    [
      "Authorization: OAuth oauth_consumer_key=\"#{@consumer_key}\"",
      "oauth_nonce=\"#{nonce}\"", "oauth_signature=\"#{ percent_encode(signature) }\"",
      "oauth_signature_method=\"#{@signature_method}\"", "oauth_timestamp=\"#{timestamp}\"",
      "oauth_token=\"#{@token}\"",
      "oauth_version=\"#{@version}\""
    ].join(', ')
  end

  def signature query_string, nonce, timestamp
    base_string = signature_base_string query_string, nonce, timestamp
    key = "#{ percent_encode(@consumer_secret) }&#{ percent_encode(@token_secret) }"
    digest = OpenSSL::Digest::Digest.new('sha1')
    hmac = OpenSSL::HMAC.digest(digest, key, base_string)
    Base64.encode64(hmac).chomp.gsub(/\n/, '')
  end

  def signature_base_string query_string, nonce, timestamp
    sorted_query = sort_query [query_string, "oauth_consumer_key=#{@consumer_key}",
                               "oauth_nonce=#{nonce}", "oauth_signature_method=#{@signature_method}",
                               "oauth_timestamp=#{timestamp}",
                               "oauth_token=#{@token}", "oauth_version=#{@version}"].join('&')
    "#{@method}&#{ percent_encode @base_url }&#{ percent_encode urlize(sorted_query) }"
  end

  def random_nonce
    Array.new( 32 ) { rand(256) }.pack('C*').unpack('H*').first
  end

  def percent_encode string
    CGI.escape(string)
  end

  def sort_query query_string
    CGI.parse(query_string).sort.map { |k, v| "#{ k }=#{ v.first.gsub(' ', '+') }" }.join('&')
  end

  def urlize query_string
    query_string.gsub('+', '%20')
  end

  def current_timestamp
    ((Time.now.to_f - Time.zone_offset(@timezone))).to_i
  end
end


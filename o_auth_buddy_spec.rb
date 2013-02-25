require "rspec"
require_relative 'o_auth_buddy'

describe "TwitterOAuth behaviour" do

  before(:each) do
    @oauth = OAuthBuddy.new("82fFtDtz3IQj5Hc7M1whBQ", 'XtcjPlTeVo8ZroQOlQLUJFMYbCz0eipOAZIAmatvkpw',
                              '385960709-gYAi6Ld5K7fCoxFVDpjXVXBnDTZ25RrCs94g64pT',
                              'sUEUWMaj5EhXqS1QOjvCbqIecJpAqu3da3oy8Cinc')

    @oauth.stub(:random_nonce) { "f84a26af9d28928183c5907b9f274389" }
    @oauth.stub(:current_timestamp) { "1360838236" }
    @nonce = @oauth.random_nonce
    @timestamp = @oauth.current_timestamp
    @parameter_string = 'q=apple+macbook+pro&count=5'
  end

  it "returns query with sorted params" do
    @oauth.sort_query(@parameter_string).should eq('count=5&q=apple+macbook+pro')
  end

  it "returns signature base string" do
    signature_base_string = 'GET&https%3A%2F%2Fapi.twitter.com%2F1.1%2Fsearch%2Ftweets.json&count%3D5%26oauth_consumer_key%3D82fFtDtz3IQj5Hc7M1whBQ%26oauth_nonce%3Df84a26af9d28928183c5907b9f274389%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1360838236%26oauth_token%3D385960709-gYAi6Ld5K7fCoxFVDpjXVXBnDTZ25RrCs94g64pT%26oauth_version%3D1.0%26q%3Dapple%2520macbook%2520pro'
    @oauth.signature_base_string(@parameter_string, @nonce, @timestamp).should eq(signature_base_string)
  end

  it "returns signature" do
    @oauth.signature(@parameter_string, @nonce, @timestamp).should eq("fnhGlJURxyFykLqZKc9sIjn440E=")
  end

  it "returns authorization header" do
    header = 'Authorization: OAuth oauth_consumer_key="82fFtDtz3IQj5Hc7M1whBQ", oauth_nonce="f84a26af9d28928183c5907b9f274389", oauth_signature="fnhGlJURxyFykLqZKc9sIjn440E%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1360838236", oauth_token="385960709-gYAi6Ld5K7fCoxFVDpjXVXBnDTZ25RrCs94g64pT", oauth_version="1.0"'
    @oauth.authorization_header(@parameter_string).should eq(header)
  end

  it "returns random nonce" do
    @oauth.random_nonce.should eq("f84a26af9d28928183c5907b9f274389")
  end

  it "returns current timestamp" do
    @oauth.current_timestamp.should eq("1360838236")
  end
end
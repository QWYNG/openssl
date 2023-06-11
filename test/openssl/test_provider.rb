# frozen_string_literal: true
require_relative 'utils'
if defined?(OpenSSL) && defined?(OpenSSL::Provider) && !OpenSSL.fips_mode

class OpenSSL::TestProvider < OpenSSL::TestCase
  def test_openssl_provider_name_inspect
    with_openssl <<-'end;'
      provider = OpenSSL::Provider.load("default")
      assert_equal("default", provider.name)
      assert_not_nil(provider.inspect)
    end;
  end

  def test_openssl_providers
    with_openssl <<-'end;'
      legacy_provider = OpenSSL::Provider.load("legacy")
      assert_equal(2, OpenSSL::Provider.providers.size)
      assert_equal(true, legacy_provider.unload)
      assert_equal(1, OpenSSL::Provider.providers.size)
    end;
  end

  def test_openssl_legacy_provider
    with_openssl(<<-'end;')
      OpenSSL::Provider.load("legacy")
      algo = "RC4"
      data = "a" * 1000
      key = OpenSSL::Random.random_bytes(16)
      
      # default provider does not support RC4
      cipher = OpenSSL::Cipher.new(algo)
      cipher.encrypt
      cipher.key = key
      encrypted = cipher.update(data) + cipher.final
      
      other_cipher = OpenSSL::Cipher.new(algo)
      other_cipher.decrypt
      other_cipher.key = key
      decrypted = other_cipher.update(encrypted) + other_cipher.final

      assert_equal(data, decrypted)
    end;
  end

  private

  # this is required because OpenSSL::Provider methods change global state
  def with_openssl(code, **opts)
    assert_separately([{ "OSSL_MDEBUG" => nil }, "-ropenssl"], <<~"end;", **opts)
      #{code}
    end;
  end
end

end

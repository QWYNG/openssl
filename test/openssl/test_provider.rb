# frozen_string_literal: true
require_relative 'utils'
if defined?(OpenSSL)
class OpenSSL::TestProvider < OpenSSL::TestCase
  def test_openssl_providers
    with_openssl <<-'end;'
      orig = OpenSSL::Provider.providers
      loaded_legacy = OpenSSL::Provider.load("legacy")
      
      assert_equal(true, loaded_legacy)
      assert_equal(1, OpenSSL::Provider.providers.size - orig.size)
    end;
  end

  def test_openssl_provider_cipher_rc4
    with_openssl(<<-'end;', ignore_stderr: true)
      OpenSSL::Provider.load("legacy")
      algo = "RC4"
      data = "a" * 1000
      key = OpenSSL::Random.random_bytes(16)
      
      cipher = OpenSSL::Cipher.new(algo)
      cipher.encrypt
      cipher.key = key
      encrypted = cipher.update(data) + cipher.final
      
      cipher.decrypt
      cipher.key = key
      decrypted = cipher.update(encrypted) + cipher.final

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

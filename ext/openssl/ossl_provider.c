#include "ossl.h"

#ifdef OSSL_USE_PROVIDER
# include <openssl/provider.h>
#endif

VALUE mProvider;
VALUE eProviderError;

static VALUE
ossl_provider_s_load(VALUE self, VALUE name)
{
    OSSL_PROVIDER *provider = NULL;

    const char *provider_name_ptr = StringValueCStr(name);

    provider = OSSL_PROVIDER_load(NULL, provider_name_ptr);
    if (provider == NULL) {
      ossl_raise(eProviderError, "Failed to load %s provider\n", provider_name_ptr);
      return Qfalse;
    }

    return Qtrue;
}

void
Init_ossl_provider(void)
{
#if 0
    mOSSL = rb_define_module("OpenSSL");
    eOSSLError = rb_define_class_under(mOSSL, "OpenSSLError", rb_eStandardError);
#endif

    mProvider = rb_define_module_under(mOSSL, "Provider");
    eProviderError = rb_define_class_under(mProvider, "ProviderError", eOSSLError);
    rb_define_module_function(mProvider, "load", ossl_provider_s_load, 1);
}

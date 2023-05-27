#include "ossl.h"

#ifdef OSSL_USE_PROVIDER
# include <openssl/provider.h>

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

DEFINE_STACK_OF(OSSL_PROVIDER)
static int provider_cmp(const OSSL_PROVIDER * const *a,
                        const OSSL_PROVIDER * const *b)
{
    return strcmp(OSSL_PROVIDER_get0_name(*a), OSSL_PROVIDER_get0_name(*b));
}
static int collect_providers(OSSL_PROVIDER *provider, void *stack)
{
    STACK_OF(OSSL_PROVIDER) *provider_stack = stack;

    sk_OSSL_PROVIDER_push(provider_stack, provider);
    return 1;
}

static VALUE
ossl_provider_s_providers(VALUE self)
{
    STACK_OF(OSSL_PROVIDER) *providers = sk_OSSL_PROVIDER_new(provider_cmp);
    VALUE ary = rb_ary_new();

    OSSL_PROVIDER_do_all(NULL, &collect_providers, providers);
    sk_OSSL_PROVIDER_sort(providers);
    for (int i = 0; i < sk_OSSL_PROVIDER_num(providers); i++) {
        OSSL_PROVIDER *provider = sk_OSSL_PROVIDER_value(providers, i);
        rb_ary_push(ary, rb_str_new2(OSSL_PROVIDER_get0_name(provider)));
    }

    return ary;
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
    rb_define_module_function(mProvider, "providers", ossl_provider_s_providers, 0);
}
#endif

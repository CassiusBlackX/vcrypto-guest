#include <openssl/core_dispatch.h>
#include <openssl/crypto.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include <log.h>

#include "provider.h"
#include "ciphers.h"

// for OpenSSL to get information about the provider
// e.g. version & name
static OSSL_FUNC_provider_get_params_fn vcrypto_get_params;
static OSSL_FUNC_provider_gettable_params_fn vcrypto_gettable_params;
// return function pointers to OpenSSL libraries to functions of this provider's modules
static OSSL_FUNC_provider_query_operation_fn vcrypto_query_operation;
// shutdown provider and destroy its context
static OSSL_FUNC_provider_teardown_fn vcrypto_teardown;
// providers capabilities up front without having to enumerate all functions of provider
static OSSL_FUNC_provider_get_capabilities_fn vcrypto_get_capabilities;
// perform known answer tests on itseld
static OSSL_FUNC_provider_self_test_fn vcrypto_self_test;

 

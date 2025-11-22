#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/types.h>

#include <rte_eal.h>
#include <rte_mempool.h>

#include <log.h>

#include "provider.h"
#include "protocol.h"

// for OpenSSL to get information about the provider
// shutdown provider and destroy its context
static OSSL_FUNC_provider_teardown_fn vcrypto_teardown;
// define params that can be given to the core 
static OSSL_FUNC_provider_get_params_fn vcrypto_get_params;
static OSSL_FUNC_provider_gettable_params_fn vcrypto_gettable_params;
// return function pointers to OpenSSL libraries to functions of this provider's modules
static OSSL_FUNC_provider_query_operation_fn vcrypto_query_operation;
// providers capabilities up front without having to enumerate all functions of provider
static OSSL_FUNC_provider_get_capabilities_fn vcrypto_get_capabilities;
// perform known answer tests on itseld
static OSSL_FUNC_provider_self_test_fn vcrypto_self_test;

static void vcrypto_teardown(void *provctx) {
  log_debug("vcrypto provider teardown");
  // TODO: free ciphers
}

static const OSSL_PARAM vcrypto_provider_param_types[] = {
  OSSL_PARAM_DEFN(OSSL_PROV_PARAM_NAME, OSSL_PARAM_UTF8_PTR, NULL, 0),
  OSSL_PARAM_DEFN(OSSL_PROV_PARAM_VERSION, OSSL_PARAM_UTF8_PTR, NULL, 0),
  OSSL_PARAM_DEFN(OSSL_PROV_PARAM_BUILDINFO, OSSL_PARAM_UTF8_PTR, NULL, 0),
  OSSL_PARAM_DEFN(OSSL_PROV_PARAM_STATUS, OSSL_PARAM_INTEGER, NULL, 0),
};

static const OSSL_PARAM* vcrypto_gettable_params(void* provctx) {
  return vcrypto_provider_param_types;
}

static int vcrypto_get_params(void *provctx, OSSL_PARAM params[]) {
  OSSL_PARAM* p;
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_NAME);
  if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, VCRYPTO_PROVIDER_NAME_STR))
    return 0;
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_VERSION);
  if (p != NULL && OSSL_PARAM_set_utf8_ptr(p, VCRYPTO_PROVIDER_VERSION_STR))
    return 0;
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_BUILDINFO);
  if (p != NULL && OSSL_PARAM_set_utf8_ptr(p, VCRYPTO_PROVIDER_BUILD_INFO_STR))
    return 0;
  p = OSSL_PARAM_locate(params, OSSL_PROV_PARAM_STATUS);
  if (p != NULL && OSSL_PARAM_set_int(p, 1))
    return 0;

  return 1;
}

extern const OSSL_DISPATCH vcrypto_aes_128_cbc_fucntions[];
extern const OSSL_DISPATCH vcrypto_aes_256_cbc_fucntions[];

static const OSSL_ALGORITHM_CAPABLE vcrypto_defaul_ciphers[] = {
  ALG(VCRYPTO_PROVIDER_NAMES_AES_128_CBC, vcrypto_aes_128_cbc_fucntions),
  ALG(VCRYPTO_PROVIDER_NAMES_AES_256_CBC, vcrypto_aes_256_cbc_fucntions),

  // the following line must be kept to indicate the end of array
  {{NULL, NULL, NULL}, NULL},
};

static OSSL_ALGORITHM vcrypto_exported_sym_ciphers[OSSL_NELEM(vcrypto_defaul_ciphers)];


static const OSSL_ALGORITHM* vcrypto_query_operation(void *provctx, int operation_id, int *no_store) {
 static void *prov_init = 0;
 prov_init = OSSL_PROVIDER_load(NULL, "default"); 
 if (!prov_init) {
   log_error("failed to load vcrypto_provider");
   vcrypto_teardown(provctx);
   exit(1);
 }

 *no_store = 0;
 
 switch (operation_id) {
  case OSSL_OP_CIPHER:
    return vcrypto_exported_sym_ciphers;
  // case OSSL_OP_ASYM_CIPHER:
  //  return vcrypto_exported_asym_ciphers;
  default:
    return OSSL_PROVIDER_query_operation(prov_init, operation_id, no_store);
 }
}

static const OSSL_DISPATCH vcrypto_dispatch_table[] = {
  {OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))vcrypto_teardown},
  {OSSL_FUNC_PROVIDER_GETTABLE_PARAMS, (void (*)(void))vcrypto_gettable_params},
  {OSSL_FUNC_PROVIDER_GET_PARAMS, (void (*)(void))vcrypto_get_params},
  {OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))vcrypto_query_operation},
  {OSSL_FUNC_PROVIDER_GET_CAPABILITIES, (void (*)(void))vcrypto_get_capabilities},
  // the following line must be kept to indicate the end of arr
  {0, NULL},
};

static void vcrypto_prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in, OSSL_ALGORITHM *out) {
    int i, j;
    if (out[0].algorithm_names == NULL) {
        for (i = j = 0; in[i].alg.algorithm_names != NULL; ++i) {
            if (in[i].capable == NULL || in[i].capable())
                out[j++] = in[i].alg;
        }
        out[j++] = in[i].alg;
    }
}
 
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle, const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out, void **provctx) {
  log_set_level(LOG_TRACE);
  char *argv[8] = {
    "./vcrypto_engine_frontend", "--proc-type=secondary", "--file-prefix=vcrypto", "-l", "6-7", 0};
  if (rte_eal_init(5, argv) < 0) {
    log_error("error at rte_eal_init");
    return 0;
  }
  if (!vcrypto_fe_protocol_engine_init("/tmp/vcrypto_engine.socket")) {
    log_error("failed at vcrypto_fe_protocol_engine_init");
    return 0;
  }
  return 1;
}

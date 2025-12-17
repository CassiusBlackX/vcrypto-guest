#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/types.h>

#include <rte_eal.h>
#include <rte_mempool.h>

#include <log.h>
#include <stdio.h>

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

OSSL_PROVIDER *prov = NULL;

OSSL_LIB_CTX* prov_libctx_of(vcrypto_prov_ctx *ctx) {
  if (ctx == NULL) return NULL;
  return ctx->libctx;
}

static void vcrypto_teardown(void *provctx) {
  log_debug("vcrypto provider teardown");
  // TODO: free ciphers


  if (provctx) {
    vcrypto_prov_ctx *vcrypto_ctx = (vcrypto_prov_ctx*)provctx;
    OPENSSL_free(vcrypto_ctx);
    OSSL_PROVIDER_unload(prov);
  }
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

// extern const OSSL_DISPATCH vcrypto_aes_128_cbc_fucntions[];
// extern const OSSL_DISPATCH vcrypto_aes_256_cbc_fucntions[];

// static const OSSL_ALGORITHM_CAPABLE vcrypto_default_ciphers[] = {
//   // ALG(VCRYPTO_PROVIDER_NAMES_AES_128_CBC, vcrypto_aes_128_cbc_fucntions),
//   ALG(VCRYPTO_PROVIDER_NAMES_AES_256_CBC, vcrypto_aes_256_cbc_fucntions),

//   // the following line must be kept to indicate the end of array
//   {{NULL, NULL, NULL}, NULL},
// };

// static OSSL_ALGORITHM vcrypto_exported_sym_ciphers[OSSL_NELEM(vcrypto_default_ciphers)];

extern const OSSL_DISPATCH vcrypto_rsa2048_enc_dec_functions[];
static const OSSL_ALGORITHM vcrypto_exported_asym_ciphers[] = {
  {"RSA", VCRYPTO_DEFAULT_PROPERTIES, vcrypto_rsa2048_enc_dec_functions},
  {NULL, NULL, NULL},
};

static const OSSL_ALGORITHM* vcrypto_query_operation(void *provctx, int operation_id, int *no_cache) {
  static bool prov_init = false;
  prov = OSSL_PROVIDER_load(NULL, "default");
  if (!prov_init) {
    prov_init = true;
    // vcrypto provider takes higher priority than openssl default
    EVP_set_default_properties(NULL, "?provider=vcrypto");
  }

  if(no_cache) *no_cache = 0;
 
 switch (operation_id) {
  // case OSSL_OP_CIPHER:
    // log_debug("query vcrypto ciphers!");
    // return vcrypto_exported_sym_ciphers;
  case OSSL_OP_ASYM_CIPHER:
    log_debug("query vcrypto asym ciphers!");
   return vcrypto_exported_asym_ciphers;
  default:
    return OSSL_PROVIDER_query_operation(prov, operation_id, no_cache);
    // return NULL;
 }
}

static int vcrypto_get_capabilities(void* provctx, const char* capability, OSSL_CALLBACK* cb, void *arg) {
  assert(0 && "unimplement vcrypto get capabilities!");
  return 0;
}

// functions provided by the core
static OSSL_FUNC_core_gettable_params_fn *c_gettable_params = NULL;
static OSSL_FUNC_core_get_params_fn *c_get_params = NULL;
static OSSL_FUNC_core_get_libctx_fn *c_get_libctx = NULL;

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

  for (; in->function_id != 0; in++) {
    switch (in->function_id) {
      case OSSL_FUNC_CORE_GETTABLE_PARAMS:
        c_gettable_params = OSSL_FUNC_core_gettable_params(in);
        break;
      case OSSL_FUNC_CORE_GET_PARAMS:
        c_get_params = OSSL_FUNC_core_get_params(in);
        break;
      case OSSL_FUNC_CORE_GET_LIBCTX:
        c_get_libctx = OSSL_FUNC_core_get_libctx(in);
        break;
      default:
        // unknown stuffs, ignore
        break;
    }
  }

  vcrypto_prov_ctx* vcrypto_ctx = OPENSSL_zalloc(sizeof(vcrypto_prov_ctx));
  if (!vcrypto_ctx) {
    log_error("failed to create vcrypto_prov_ctx");
    return 0;
  }
  vcrypto_ctx->handle = handle;
  vcrypto_ctx->libctx = (OSSL_LIB_CTX*)OSSL_LIB_CTX_new_from_dispatch(handle, in);
  *provctx = (void*)vcrypto_ctx;

  *out = vcrypto_dispatch_table;
  // vcrypto_prov_cache_exported_algorithms(vcrypto_default_ciphers, vcrypto_exported_sym_ciphers);
  
  log_info("vcrypto provider init success");
  return 1;
}

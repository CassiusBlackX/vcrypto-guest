#ifndef VCRYPTO_GUEST_FE_PROVIDER_H
#define VCRYPTO_GUEST_FE_PROVIDER_H

#include <openssl/async.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include <stdatomic.h>
#define VCRYPTO_PROVIDER_NAME_STR "vCrypto OpenSSL Provider"
#define VCRYPTO_PROVIDER_VERSION_STR "v0.0.1"
#define VCRYPTO_PROVIDER_BUILD_INFO_STR "vCrypto Openssl Provider v0.0.1"

typedef struct vcrypto_provider_ctx_st {
  const OSSL_CORE_HANDLE* handle;
  OSSL_LIB_CTX *libctx;
} vcrypto_prov_ctx;

OSSL_LIB_CTX* prov_libctx_of(vcrypto_prov_ctx *ctx);

#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define VCRYPTO_PROVIDER_NAMES_AES_128_CBC "AES-128-CBC"
#define VCRYPTO_PROVIDER_NAMES_AES_256_CBC "AES-256-CBC"

# define ALGC(NAMES, FUNC, CHECK) { { NAMES, VCRYPTO_DEFAULT_PROPERTIES, FUNC }, CHECK }
# define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)
static const char VCRYPTO_DEFAULT_PROPERTIES[] = "provider=vcrypto";
typedef struct vcrypto_alg_capable_st {
  OSSL_ALGORITHM alg;
  int (*capable)(void);
} OSSL_ALGORITHM_CAPABLE;


typedef struct {
  _Atomic int val;
} VCRYPTO_REF_COUNT;

static inline int vcrypto_new_ref(VCRYPTO_REF_COUNT *refcnt, int n) {
  refcnt->val = n;
  return 1;
}

static inline int vcrypto_get_ref(VCRYPTO_REF_COUNT *refcnt, int *ret) {
  *ret = atomic_load_explicit(&refcnt->val, memory_order_acquire);
  return 1;
}

static inline int vcrypto_up_ref(VCRYPTO_REF_COUNT *refcnt, int *ret) {
  *ret = atomic_fetch_add_explicit(&refcnt->val, 1, memory_order_relaxed) + 1;
  return 1;
}

static inline int vcrypto_down_ref(VCRYPTO_REF_COUNT *refcnt, int *ret) {
  *ret = atomic_fetch_sub_explicit(&refcnt->val, 1, memory_order_release) - 1;
  if (*ret == 0) {
    atomic_thread_fence(memory_order_acquire);
  }
  return 1;
}

#endif // VCRYPTO_GUEST_FE_PROVIDER_H

#ifndef VCRYPTO_GUEST_FE_PROVIDER_H
#define VCRYPTO_GUEST_FE_PROVIDER_H

#include <openssl/async.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#define VCRYPTO_PROVIDER_NAME_STR "vCrypto OpenSSL Provider"
#define VCRYPTO_PROVIDER_VERSION_STR "v0.0.1"
#define VCRYPTO_PROVIDER_BUILD_INFO_STR "vCrypto Openssl Provider v0.0.1"

typedef struct vcrypto_provider_ctx_st {
  const OSSL_CORE_HANDLE* handle;
  OSSL_LIB_CTX *libctx;
} vcrypto_prov_ctx;

#define OSSL_NELEM(x)    (sizeof(x)/sizeof((x)[0]))
#define VCRYPTO_PROVIDER_NAMES_AES_128_CBC "AES-128-CBC"
#define VCRYPTO_PROVIDER_NAMES_AES_256_CBC "AES-256-CBC"

# define ALGC(NAMES, FUNC, CHECK) { { NAMES, VCRYPTO_DEFAULT_PROPERTIES, FUNC }, CHECK }
# define ALG(NAMES, FUNC) ALGC(NAMES, FUNC, NULL)
static const char VCRYPTO_DEFAULT_PROPERTIES[] = "provider=vcrypto_provider";
typedef struct vcrypto_alg_capable_st {
  OSSL_ALGORITHM alg;
  int (*capable)(void);
} OSSL_ALGORITHM_CAPABLE;


#endif // VCRYPTO_GUEST_FE_PROVIDER_H

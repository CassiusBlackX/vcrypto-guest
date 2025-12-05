#ifndef VCRYPTO_GUEST_FE_AES_CBC_H
#define VCRYPTO_GUEST_FE_AES_CBC_H

#include <rte_cryptodev.h>
#include <openssl/core_dispatch.h>

#include "cipher_common.h"

typedef struct vcrypto_aes_cbc_ctx_t {
  PROV_CIPHER_CTX base;  // must be the first member

  unsigned int ctx_status_inited : 1;
  unsigned int ctx_status_session_created : 1;

  struct rte_cryptodev_sym_session* sess;
} vcrypto_aes_cbc_ctx;

OSSL_FUNC_cipher_newctx_fn vcrypto_aes_cbc_newctx;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_encrypt_init_fn vcrypto_aes_cbc_einit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_decrypt_init_fn vcrypto_aes_cbc_dinit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_cipher_fn vcrypto_aes_cbc_cipher;
OSSL_FUNC_cipher_freectx_fn vcrypto_aes_cbc_freectx;

#endif  // VCRYPTO_GUEST_FE_AES_CBC_H

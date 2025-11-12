#ifndef VCRYPTO_GUEST_FE_AES_CBC_H
#define VCRYPTO_GUEST_FE_AES_CBC_H

#include <rte_cryptodev.h>
#include <openssl/core_dispatch.h>

typedef struct vcrypto_aes_cbc_ctx_t {
  cipher_auth_ctrl cipher_auth;
  struct rte_cryptodev_sym_session* sess;
  uint32_t init_flags;
} vcrypto_aes_cbc_ctx;

OSSL_FUNC_cipher_newctx_fn vcrypto_aes_cbc_newctx;
OSSL_FUNC_cipher_encrypt_init_fn vcrypto_aes_cbc_einit;
OSSL_FUNC_cipher_decrypt_init_fn vcrypto_aes_cbc_dinit;
OSSL_FUNC_cipher_update_fn vcrypto_aes_cbc_update;
OSSL_FUNC_cipher_final_fn vcrypto_aes_cbc_final;
OSSL_FUNC_cipher_freectx_fn vcrypto_aes_cbc_freectx;


#endif  // VCRYPTO_GUEST_FE_AES_CBC_H

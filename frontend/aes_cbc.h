#ifndef VCRYPTO_GUEST_FE_AES_CBC_H
#define VCRYPTO_GUEST_FE_AES_CBC_H

#include <rte_cryptodev.h>
#include <openssl/core_dispatch.h>

#define CIPHER_DIRECTION_ENCRYPT 0
#define CIPHER_DIRECTION_DECRYPT 1

typedef struct cipher_auth_t {
  uint32_t alg_nid;
  uint32_t direction; // 0 for encrypt, 1 for decrypt
  uint32_t cipher_key_len;
  uint32_t cipher_iv_len;
  uint32_t auth_key_len;
  uint8_t cipher_key_data[32];
  uint8_t auth_key_data[64];
  uint64_t alg_elems_md5;
} cipher_auth_ctrl;

#define CTX_STATUS_INITED 0x1
#define CTX_STATUS_SESSION_CREATED 0x2
#define CTX_SET_STATUS_FLAG(ctx, flag) ((ctx)->status_flags |= (flag))
#define CTX_UNSET_STATUS_FLAG(ctx, flag) ((ctx)->status_flags &= ~(flag))
#define CTX_GET_STATUS_FLAG(ctx, flag) ((ctx)->status_flags & (flag))

typedef struct vcrypto_aes_cbc_ctx_t {
  cipher_auth_ctrl cipher_auth;
  struct rte_cryptodev_sym_session* sess;
  uint32_t status_flags;
} vcrypto_aes_cbc_ctx;

OSSL_FUNC_cipher_newctx_fn vcrypto_aes_cbc_newctx;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_encrypt_init_fn vcrypto_aes_cbc_einit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_decrypt_init_fn vcrypto_aes_cbc_dinit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_update_fn vcrypto_aes_cbc_update;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_final_fn vcrypto_aes_cbc_final;
OSSL_FUNC_cipher_freectx_fn vcrypto_aes_cbc_freectx;


#endif  // VCRYPTO_GUEST_FE_AES_CBC_H

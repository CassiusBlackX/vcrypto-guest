#ifndef VCRYPTO_GUEST_FE_AES_CBC_H
#define VCRYPTO_GUEST_FE_AES_CBC_H

#include <rte_cryptodev.h>
#include <openssl/core_dispatch.h>

#define CIPHER_DIRECTION_ENCRYPT 0
#define CIPHER_DIRECTION_DECRYPT 1

#define PROV_CIPHER_FLAG_AEAD             0X0001
#define PROV_CIPHER_FLAGS_CUSTOM_IV       0x0002
#define PROV_CIPHER_FLAGS_CTS             0X0004
#define PROV_CIPHER_FLAGS_TLS1_MULTIBLOCK 0x0008
#define PROV_CIPHER_FLAG_RAND_KEY         0x0010

#define VCRYPTO_AES_CBC_CTX_BUF_SIZE 4096

typedef struct cipher_auth_t {
  uint32_t alg_nid;
  uint32_t direction; // 0 for encrypt, 1 for decrypt
  uint32_t cipher_key_len;
  uint32_t cipher_iv_len;
  uint32_t auth_key_len;
  uint8_t cipher_key_data[32];
  uint8_t cipher_iv_data[16];
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

  // stream input
  unsigned char* buf;
  size_t buf_size;
  size_t buf_len;
} vcrypto_aes_cbc_ctx;

OSSL_FUNC_cipher_newctx_fn vcrypto_aes_cbc_newctx;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_encrypt_init_fn vcrypto_aes_cbc_einit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_decrypt_init_fn vcrypto_aes_cbc_dinit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_cipher_fn vcrypto_aes_cbc_cipher;
OSSL_FUNC_cipher_freectx_fn vcrypto_aes_cbc_freectx;

OSSL_FUNC_cipher_get_params_fn vcrypto_aes_128_cbc_get_params;
OSSL_FUNC_cipher_get_params_fn vcrypto_aes_256_cbc_get_params;
OSSL_FUNC_cipher_get_ctx_params_fn vcrypto_aes_cbc_get_ctx_params;
OSSL_FUNC_cipher_set_ctx_params_fn vcrypto_aes_cbc_set_ctx_params;
OSSL_FUNC_cipher_gettable_params_fn vcrypto_aes_cbc_gettable_params;
OSSL_FUNC_cipher_gettable_ctx_params_fn vcrypto_aes_gettable_ctx_params;
OSSL_FUNC_cipher_settable_ctx_params_fn vcrypto_aes_settable_ctx_params;


#endif  // VCRYPTO_GUEST_FE_AES_CBC_H

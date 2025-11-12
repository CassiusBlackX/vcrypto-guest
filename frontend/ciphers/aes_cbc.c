#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <string.h>
#include <stddef.h>

#include <log.h>

#include "aes_cbc.h"
#include "cipher_auth_ctrl.h"

void *vcrypto_aes_cbc_newctx(void *provctx) {
  return OPENSSL_zalloc(sizeof(vcrypto_aes_cbc_ctx));  
}

void vcrypto_aes_cbc_freectx(void* cctx) {
  OPENSSL_clear_free(cctx, sizeof(vcrypto_aes_cbc_ctx));  
}

int vcrypto_aes_cbc_einit(void *cctx, const unsigned char* key, size_t keylen, 
                          const unsigned char* iv, size_t ivlen, 
                        const OSSL_PARAM params[]) {
  vcrypto_aes_cbc_ctx* ctx = (vcrypto_aes_cbc_ctx*)cctx;
  if (keylen != 16 && keylen != 32) {
    log_error("vcrypto aes_cbc only support for keylen == 16 or 32");
    return 0;
  }

  ctx->cipher_auth.direction = CIPHER_DIRECTION_ENCRYPT;

  // BUG: aes-256-cbc as default, should support other size as well
  ctx->cipher_auth.alg_nid = NID_aes_256_cbc; 
  
  memcpy(ctx->cipher_auth.cipher_key_data, key, keylen);
  ctx->cipher_auth.cipher_key_len = keylen;
  if (iv) {
    log_trace("using passed in iv!");
    ctx->cipher_auth.cipher_iv_len = ivlen;
  } else {
    log_trace("no passed in iv");
    ctx->cipher_auth.cipher_iv_len = 0;
  }
  return 1;
}

int vcrypto_aes_cbc_dinit(void *cctx, const unsigned char* key, size_t keylen, 
                          const unsigned char* iv, size_t ivlen, 
                        const OSSL_PARAM params[]) {
  vcrypto_aes_cbc_ctx* ctx = (vcrypto_aes_cbc_ctx*)cctx;
  if (keylen != 16 && keylen != 32) {
    log_error("vcrypto aes_cbc only support for keylen == 16 or 32");
    return 0;
  }

  ctx->cipher_auth.direction = CIPHER_DIRECTION_DECRYPT;

  // BUG: aes-256-cbc as default, should support other size as well
  ctx->cipher_auth.alg_nid = NID_aes_256_cbc; 
  
  memcpy(ctx->cipher_auth.cipher_key_data, key, keylen);
  ctx->cipher_auth.cipher_key_len = keylen;
  if (iv) {
    log_trace("using passed in iv!");
    ctx->cipher_auth.cipher_iv_len = ivlen;
  } else {
    log_trace("no passed in iv");
    ctx->cipher_auth.cipher_iv_len = 0;
  }
  return 1;
}

int vcrypto_aes_cbc_update(void* cctx, unsigned char* out, size_t *outl, size_t outsize, 
                           const unsigned char* in, size_t intl) {

}

int vcrypto_aes_cbc_final(void* cctx, unsigned char* out, size_t *outl, size_t outsize) {
  
}


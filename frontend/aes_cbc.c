#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stddef.h>

#include <openssl/crypto.h>
#include <openssl/obj_mac.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/types.h>
#include <openssl/evp.h>

#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_memcpy_64.h>
#include <rte_ring.h>

#include <log.h>
#include <xxhash.h>

#include "aes_cbc.h"
#include "cipher_common.h"
#include "protocol.h"

// #define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAGS_CUSTOM_IV)
#define AEAD_FLAGS 0

void *vcrypto_aes_cbc_newctx(void *provctx) {
  vcrypto_aes_cbc_ctx *ctx = OPENSSL_zalloc(sizeof((*ctx)));
  if (!ctx) {
    log_error("failed to alloc vcrypto_aes_cbc_ctx");
    return NULL;
  }
  ctx->buf_size = VCRYPTO_AES_CBC_CTX_BUF_SIZE;
  ctx->buf = OPENSSL_malloc(ctx->buf_size);
  if (!ctx->buf) {
    log_error("failed to alloc for ctx->buf_size");
    OPENSSL_free(ctx);
    return NULL;
  }
  return ctx;
}

void vcrypto_aes_cbc_freectx(void* cctx) {
  vcrypto_aes_cbc_ctx *ctx = (vcrypto_aes_cbc_ctx*)cctx;
  if (ctx) {
    OPENSSL_clear_free(ctx->buf, ctx->buf_size);
    OPENSSL_clear_free(ctx, sizeof(*ctx));
  }
}

int vcrypto_aes_cbc_einit(void *cctx, const unsigned char* key, size_t keylen, 
                          const unsigned char* iv, size_t ivlen, 
                        const OSSL_PARAM params[]) {
  vcrypto_aes_cbc_ctx* ctx = (vcrypto_aes_cbc_ctx*)cctx;
  if (keylen != 16 && keylen != 32) {
    log_error("vcrypto aes_cbc only support for keylen == 16 or 32, but got keylen: %d", keylen);
    return 0;
  }

  ctx->cipher_auth.direction = CIPHER_DIRECTION_ENCRYPT;

  ctx->cipher_auth.alg_nid = (keylen == 16) ? NID_aes_128_cbc : NID_aes_256_cbc; 
  
  memcpy(ctx->cipher_auth.cipher_key_data, key, keylen);
  ctx->cipher_auth.cipher_key_len = keylen;
  if (iv) {
    log_trace("using passed in iv!");
    ctx->cipher_auth.cipher_iv_len = ivlen;
    memcpy(ctx->cipher_auth.cipher_iv_data, iv, ivlen);
  } else {
    log_trace("no passed in iv");
    ctx->cipher_auth.cipher_iv_len = 0;
    memset(ctx->cipher_auth.cipher_iv_data, 0, sizeof(ctx->cipher_auth.cipher_iv_data));
  }

  CTX_SET_STATUS_FLAG(ctx, CTX_STATUS_INITED);
  log_debug("aes_cbc einit success");
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

  ctx->cipher_auth.alg_nid = (keylen == 16) ? NID_aes_128_cbc : NID_aes_256_cbc; 
  
  memcpy(ctx->cipher_auth.cipher_key_data, key, keylen);
  ctx->cipher_auth.cipher_key_len = keylen;
  if (iv) {
    log_trace("using passed in iv!");
    ctx->cipher_auth.cipher_iv_len = ivlen;
    memcpy(ctx->cipher_auth.cipher_iv_data, iv, ivlen);
  } else {
    log_trace("no passed in iv");
    ctx->cipher_auth.cipher_iv_len = 0;
    memset(ctx->cipher_auth.cipher_iv_data, 0, sizeof(ctx->cipher_auth.cipher_iv_data));
  }

  CTX_SET_STATUS_FLAG(ctx, CTX_STATUS_INITED);
  log_debug("aes_cbc dinit success");
  return 1;
}

int vcrypto_aes_cbc_cipher(void *cctx, unsigned char *out, size_t *outl, size_t outsize,
                           const unsigned char *in, size_t inl) {
  log_trace("entering vcrypto_aes_cbc_cipher");
  vcrypto_aes_cbc_ctx *ctx = (vcrypto_aes_cbc_ctx*)cctx;
  // 1. status check
  if (!ctx || !out || !in || !outl) {
    log_error("nullptr in passed in params");
    return 0;
  }
  if (!CTX_GET_STATUS_FLAG(ctx, CTX_STATUS_INITED)) {
    log_error("context not initialsed");
    return 0;
  }

  // 2. create session
  if (!CTX_GET_STATUS_FLAG(ctx, CTX_STATUS_SESSION_CREATED)) {
    uint64_t hash_val = XXH64(&(ctx->cipher_auth), sizeof(ctx->cipher_auth), 0);
    ctx->cipher_auth.alg_elems_md5 = hash_val;
    if (!vcrypto_fe_protocol_create_sess(ctx)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    CTX_SET_STATUS_FLAG(ctx, CTX_STATUS_SESSION_CREATED);
  }

  // 3. calculate padding length
  size_t block_size = 16;
  size_t padded_len = inl;
  bool is_encrypt = (ctx->cipher_auth.direction == CIPHER_DIRECTION_ENCRYPT);
  if (is_encrypt) {
    // encrypt
    padded_len = ((inl + block_size) / block_size) * block_size;
    if (padded_len == 0) padded_len = block_size;
    if (padded_len > outsize) {
      log_error("output buffer too small for encrypted data");
      return 0;
    }
  } else {
    // decrypt: inl must be multiple of block_size
    if (inl % block_size != 0) {
      log_error("decrypt input not block aligned");
      return 0;
    }
    if (inl > outsize) {
      log_error("output buffer too small for decrypted data");
      return 0;
    }
    padded_len = inl;  // will remove padding later
  }

  // 4. mbuf allocation
  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!mbuf || rte_pktmbuf_append(mbuf, padded_len) == 0) {
    log_error("mbuf alloc failed");
    return 0;
  }

  uint8_t *data = rte_pktmbuf_mtod(mbuf, uint8_t*);
  memcpy(data, in, inl);

  if (is_encrypt) {
    uint8_t pad = (uint8_t)(padded_len - inl);
    memset(data + inl, pad, pad);  // TODO: why not 0 instead of pad?
  }

  // 5. crypto op allocation
  struct rte_crypto_op *op = rte_crypto_op_alloc(sym_crypto_op_mempool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
  if (!op) {
    rte_pktmbuf_free(mbuf);
    log_error("crypto op alloc failed");
    return 0;
  }

  // 6. fill in op
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  rte_crypto_op_attach_sym_session(op, ctx->sess);
  op->sym->cipher.data.offset = 0;
  op->sym->cipher.data.length = padded_len;
  op->sym->m_src = mbuf;

  // 7. copy iv
  uint8_t* iv_ptr = rte_crypto_op_ctod_offset(op, uint8_t*, sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op));
  memcpy(iv_ptr, ctx->cipher_auth.cipher_iv_data, ctx->cipher_auth.cipher_iv_len);

  // 8. send to daemon
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    rte_crypto_op_free(op);
    rte_pktmbuf_free(mbuf);
    log_error("enqueue to backend the crypto op failed");
    return 0;
  }

  // 9. wait for response, NOTE: sync version!
  struct rte_crypto_op *completed_op = NULL;
  while (rte_ring_dequeue(rx_ring, (void**)&completed_op) != 0) {
    rte_pause();
  }

  if (!completed_op) {
    log_error("got NULL for completed_op");
    return 0;
  }
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    rte_crypto_op_free(completed_op);
    log_error("crypto operation process failed at backend");
    return 0;
  }

  // 10. copy result
  struct rte_mbuf *result_m = completed_op->sym->m_dst;
  size_t result_len = rte_pktmbuf_data_len(result_m);
  uint8_t *result_data = rte_pktmbuf_mtod(result_m, uint8_t*);

  if (is_encrypt) {
    // encrypt: output padded_len
    memcpy(out, result_data, result_len);
    *outl = result_len;
  } else {
    // decrypt: remove padding
    if (result_len < 1 || result_len % block_size != 0) {
      rte_crypto_op_free(completed_op);
      log_error("invalid decrypted length");
      return 0;
    }
    uint8_t pad = result_data[result_len - 1];
    if (pad > block_size || pad == 0) {
      rte_crypto_op_free(completed_op);
      log_error("invalid padding");
      return 0;
    }
    // validate padding
    for (size_t i = 0; i < pad; i++) {
      if (result_data[result_len - 1 - i] != pad) {
        rte_crypto_op_free(completed_op);
        log_error("padding validation failed");
        return 0;
      }
    }
    size_t unpadded_len = result_len - pad;
    memcpy(out, result_data, unpadded_len);
    *outl = unpadded_len;
  }

  // 11. cleanup
  rte_pktmbuf_free(result_m);
  rte_crypto_op_free(completed_op);

  return 1;
}

const OSSL_DISPATCH vcrypto_aes_256_cbc_fucntions[] = {
  {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))vcrypto_aes_cbc_newctx},
  {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))vcrypto_aes_cbc_freectx},
  {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_einit},
  {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_dinit},
  {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))vcrypto_aes_cbc_cipher},
  {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))ossl_cipher_generic_get_params},
  {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_get_ctx_params},
  {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_set_ctx_params},
  {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_params},
  {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_gettable_ctx_params}, 
  {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))ossl_cipher_generic_settable_ctx_params},
};

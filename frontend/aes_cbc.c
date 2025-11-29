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
    log_error("vcrypto aes_cbc only support for keylen == 16 or 32");
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

static int vcrypto_aes_cbc_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                              uint64_t flags, size_t kbits, size_t blkbits,
                                              size_t ivbits) {
  OSSL_PARAM* p;
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
  if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
    log_error("failed to set aes-%d-cbc md", kbits);
    return 0;
  } else {
    log_trace("set aes-%d-cbc mode", kbits);
  }
  // we do not support aead
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
  // if (p != NULL && OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
  //   log_error("failed to set aes-%d-cbc aead", kbits);
  //   return 0;
  // }
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
  // if (p != NULL && OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAGS_CUSTOM_IV) != 0)) {
  //   log_error("failed to set aes-%d-cbc custom iv", kbits);
  //   return 0;
  // }
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
  // if (p != NULL && OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAGS_CTS) != 0)) {
  //   log_error("failed to set aes-%d-cbc cts", kbits);
  //   return 0;
  // }
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
  // if (p != NULL && OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAGS_TLS1_MULTIBLOCK) != 0)){
  //   log_error("failed to set aes-%d-cbc tls1_multiblock", kbits);
  //   return 0;
  // }
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
  // if (p != NULL && OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
  //   log_error("failed to set aes-%d-cbc has_rand_key", kbits);
  //   return 0;
  // }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
    log_error("failed to set aes-%d-cbc keylen", kbits);
    return 0;
  } else {
    log_trace("set aes-%d-cbc keylen", kbits);
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
    log_error("failed to set aes-%d-cbc block size", kbits);
    return 0;
  } else {
    log_trace("set aes-%d-cbc block size", kbits);
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
    log_error("failed to set aes-%d-cbc iv len", kbits);
    return 0;
  } else {
    log_trace("set aes-%d-cbc block iv len", kbits);
  }
  log_debug("aes-%d-cbc generic param get success", kbits);
  return 1;
}

int vcrypto_aes_128_cbc_get_params(OSSL_PARAM params[]) {
  log_trace("enter aes-128-cbc get_params");
  return vcrypto_aes_cbc_generic_get_params(params, EVP_CIPH_CBC_MODE, AEAD_FLAGS, 128, 128, 128);
}
int vcrypto_aes_256_cbc_get_params(OSSL_PARAM params[]) {
  log_trace("enter aes-256-cbc get_params");
  return vcrypto_aes_cbc_generic_get_params(params, EVP_CIPH_CBC_MODE, AEAD_FLAGS, 256, 128, 128);
}

int vcrypto_aes_cbc_get_ctx_params(void *vctx, OSSL_PARAM params[]) {
  log_trace("enter get_ctx_params");
  vcrypto_aes_cbc_ctx* ctx = (vcrypto_aes_cbc_ctx*)vctx;
  if (!ctx) {
    log_error("null ptr ctx!");
  }
  if (ctx->cipher_auth.alg_nid != NID_aes_128_cbc &&
      ctx->cipher_auth.alg_nid != NID_aes_256_cbc) {
    log_error("unsupported alg_nid: %d", ctx->cipher_auth.alg_nid);
    return 0;
  }

  OSSL_PARAM *p;
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->cipher_auth.cipher_iv_len)) {
    log_error("failed to set cipher iv len");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->cipher_auth.cipher_key_len)) {
    log_error("failed to set cipher key len");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
  if (p != NULL) {
    if (ctx->cipher_auth.cipher_iv_len > p->data_size) {
      log_error("INVALID IV LEN: ctx->cipher_auth.cipher_iv-len > OSSL_CIPHER_PARAM_IV length!");
      return 0;
    }
    if (!OSSL_PARAM_set_octet_string(p, ctx->cipher_auth.cipher_iv_data, p->data_size)
        && !OSSL_PARAM_set_octet_ptr(p, &(ctx->cipher_auth.cipher_iv_data), p->data_size)) {
      log_error("failed to set cipher iv data");
    }
  }
  // p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
  // if (p != NULL) {
  //   log_debug("tring to set updated IV!, which we yet to implement!");
  //   return 0;
  // }
  
  // TODO: other parameters???
  log_debug("aes_cbc get_ctx_params success");
  return 1;
}

int vcrypto_aes_cbc_set_ctx_params(void *vctx, const OSSL_PARAM params[]) {
  log_trace("enter set_ctx_params");
  vcrypto_aes_cbc_ctx *ctx = (vcrypto_aes_cbc_ctx*)vctx;
  if (params == NULL) return 1;
  if (ctx->cipher_auth.alg_nid != NID_aes_128_cbc &&
      ctx->cipher_auth.alg_nid != NID_aes_256_cbc) {
    return 0;
  }

  log_debug("we do not allow setting of any ctx param");
  return 1;
}

static const OSSL_PARAM vcrypto_aes_cbc_known_gettable_params[] = {
  OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
  // FIXME: the following seems to be auth related
  // which we have yet to implement!
  // OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
  // OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
  // OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
  // OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
  // OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
  OSSL_PARAM_END
};

const OSSL_PARAM* vcrypto_aes_cbc_gettable_params(ossl_unused void* provctx) {
  log_trace("enter gettable_params");
  return vcrypto_aes_cbc_known_gettable_params;
}

static const OSSL_PARAM vcrypto_aes_cbc_known_gettable_ctx_params[] = {
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD_PAD, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
#if !defined(OPENSSL_NO_MULTIBLOCK)
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE, NULL),
  OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, NULL),
  OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN, NULL),
#endif  // !defined(OPENSSL_NO_MULTIBLOCK)
  OSSL_PARAM_END
};

const OSSL_PARAM* vcrypto_aes_cbc_gettable_ctx_params(ossl_unused void* provctx, ossl_unused void*ctx) {
  log_trace("enter gettable_ctx_params");
  return vcrypto_aes_cbc_known_gettable_ctx_params;
}

static const OSSL_PARAM vcrypto_aes_cbc_known_settable_ctx_params[] = {
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_MAC_KEY, NULL, 0),
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_AEAD_TLS1_AAD, NULL, 0),
# if !defined(OPENSSL_NO_MULTIBLOCK)
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT, NULL),
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_AAD, NULL),
  OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE, NULL),
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC, NULL, 0),
  OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN, NULL, 0),
# endif /* !defined(OPENSSL_NO_MULTIBLOCK) */
  OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
  OSSL_PARAM_END
};

const OSSL_PARAM* vcrypto_aes_cbc_settable_ctx_params(ossl_unused void*ctx, ossl_unused void* provctx) {
  return vcrypto_aes_cbc_known_settable_ctx_params;
}

const OSSL_DISPATCH vcrypto_aes_128_cbc_fucntions[] = {
  {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))vcrypto_aes_cbc_newctx},
  {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))vcrypto_aes_cbc_freectx},
  {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_einit},
  {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_dinit},
  {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))vcrypto_aes_cbc_cipher},
  {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))vcrypto_aes_128_cbc_get_params},
  {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_get_ctx_params},
  {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_set_ctx_params},
  {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))vcrypto_aes_cbc_gettable_params},
  {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_gettable_ctx_params},
  {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_settable_ctx_params},
};
const OSSL_DISPATCH vcrypto_aes_256_cbc_fucntions[] = {
  {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))vcrypto_aes_cbc_newctx},
  {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))vcrypto_aes_cbc_freectx},
  {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_einit},
  {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_dinit},
  {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))vcrypto_aes_cbc_cipher},
  {OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))vcrypto_aes_256_cbc_get_params},
  {OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_get_ctx_params},
  {OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_set_ctx_params},
  {OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))vcrypto_aes_cbc_gettable_params},
  {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_gettable_ctx_params},
  {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))vcrypto_aes_cbc_settable_ctx_params},
};

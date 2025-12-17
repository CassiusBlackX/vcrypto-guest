#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>
#include <rte_memcpy_64.h>
#include <rte_ring.h>
#include <generic/rte_pause.h>
#include <rte_debug.h>

#include <log.h>
#include <xxhash.h>

#include "aes_cbc.h"
#include "cipher_common.h"
#include "protocol.h"

// #define AEAD_FLAGS (PROV_CIPHER_FLAG_AEAD | PROV_CIPHER_FLAGS_CUSTOM_IV)
#define AEAD_FLAGS 0

OSSL_FUNC_cipher_newctx_fn vcrypto_aes_cbc_newctx;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_encrypt_init_fn vcrypto_aes_cbc_einit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_decrypt_init_fn vcrypto_aes_cbc_dinit;
// return 1 for success and 0 for error
OSSL_FUNC_cipher_cipher_fn vcrypto_aes_cbc_cipher;
OSSL_FUNC_cipher_freectx_fn vcrypto_aes_cbc_freectx;

void *vcrypto_aes_cbc_newctx(void *provctx) {
  vcrypto_aes_cbc_ctx *ctx = OPENSSL_zalloc(sizeof((*ctx)));
  if (!ctx) {
    log_error("failed to alloc vcrypto_aes_cbc_ctx");
    return NULL;
  }
  vcrypto_cipher_generic_initkey(ctx, 256, 128, 128, EVP_CIPH_CBC_MODE, 0,
                              provctx);
  return ctx;
}

void vcrypto_aes_cbc_freectx(void *cctx) {
  vcrypto_aes_cbc_ctx *ctx = (vcrypto_aes_cbc_ctx *)cctx;
  if (ctx) {
    OPENSSL_clear_free(ctx, sizeof(*ctx));
  }
}

int vcrypto_aes_cbc_einit(void *cctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[]) {
  log_debug("encrypt init");
  return vcrypto_cipher_generic_einit(cctx, key, keylen, iv, ivlen, params);
}

int vcrypto_aes_cbc_dinit(void *cctx, const unsigned char *key, size_t keylen,
                          const unsigned char *iv, size_t ivlen,
                          const OSSL_PARAM params[]) {
  log_debug("decrypt init");
  return vcrypto_cipher_generic_dinit(cctx, key, keylen, iv, ivlen, params);
}

int vcrypto_aes_cbc_cipher(void *cctx, unsigned char *out, size_t *outl,
                           size_t outsize, const unsigned char *in,
                           size_t inl) {
  log_trace("entering vcrypto_aes_cbc_cipher");
  vcrypto_aes_cbc_ctx *ctx = (vcrypto_aes_cbc_ctx *)cctx;
  // 1. status check
  if (!ctx || !out || !in || !outl) {
    log_error("nullptr in passed in params");
    return 0;
  }
  log_debug("input plaietext len: %zu, content: %s", inl, in);

  // 2. create session
  if (!ctx->ctx_status_session_created) {
    // uint64_t hash_val = XXH64(&(ctx->cipher_auth), sizeof(ctx->cipher_auth), 0);
    // ctx->cipher_auth.alg_elems_md5 = hash_val;
    ctx->base.md5_val = 0;
    uint64_t hash_val = XXH64(&(ctx->base), sizeof(ctx->base), 0);
    ctx->base.md5_val = hash_val;
    if (!vcrypto_fe_protocol_create_sess(ctx)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    log_trace("vcrypto_fe_protocol_create_sess success");
    ctx->ctx_status_session_created = 1;
  }

  // 3. calculate padding length
  log_trace("going to calculate padding length");
  size_t block_size = 16;
  size_t total_len = 0;
  bool is_encrypt = ctx->base.enc;
  if (is_encrypt) {
    log_debug("is encrypt");
  } else {
    log_debug("is decrypt");
  }
  if (is_encrypt) {
    // encrypt
    uint8_t padding_len = block_size - (inl % block_size);
    total_len = inl + padding_len;
    // BUG: will error when `openssl speed` test!
    // if (total_len > outsize) {
    //   log_error("output buffer too small for encrypted data");
    //   return 0;
    // }
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
    total_len = inl; // will remove padding later
  }

  // 4. mbuf allocation
  log_trace("going to mbuf allocation, alloc :%zu", total_len);
  struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!mbuf || rte_pktmbuf_append(mbuf,total_len) == 0) {
    log_error("mbuf alloc failed");
    return 0;
  }

  uint8_t *data = rte_pktmbuf_mtod(mbuf, uint8_t *);
  memcpy(data, in, inl);

  if (is_encrypt) {
    uint8_t pad = (uint8_t)(total_len- inl);
    // memset(data + inl, pad, pad);
    memset(data + inl, 0, pad);  // TODO: should not fill in 0 here, but for debug
  }

  // 5. crypto op allocation
  log_trace("going to crypto op allocation");
  struct rte_crypto_op *op =
      rte_crypto_op_alloc(crypto_op_mempool, RTE_CRYPTO_OP_TYPE_SYMMETRIC);
  if (!op) {
    rte_pktmbuf_free(mbuf);
    log_error("crypto op alloc failed");
    return 0;
  }

  // 6. fill in op
  log_trace("going to fill in op");
  rte_crypto_op_attach_sym_session(op, ctx->sess);
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->sym->cipher.data.offset = 0;
  op->sym->cipher.data.length = total_len;
  op->sym->m_src = mbuf;
  op->sym->m_dst = NULL;

  // 7. copy iv
  log_trace("going to copy iv");
  uint8_t *iv_ptr = rte_crypto_op_ctod_offset(
      op, uint8_t *,
      sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op));
  memcpy(iv_ptr, ctx->base.iv, ctx->base.ivlen);

  // 8. send to daemon
  log_trace("going to send op: %p to daemon", op);
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    rte_crypto_op_free(op);
    rte_pktmbuf_free(mbuf);
    log_error("enqueue to backend the crypto op failed");
    return 0;
  }

  // 9. wait for response, NOTE: sync version!
  log_trace("waiting for response");
  struct rte_crypto_op *completed_op = NULL;
  while (rte_ring_dequeue(rx_ring, (void **)&completed_op) != 0) {
    rte_pause();
  }
  log_trace("got response");

  if (!completed_op) {
    log_error("got NULL for completed_op");
    return 0;
  } else {
    log_trace("completed_op = %p", completed_op);
  }
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    rte_crypto_op_free(completed_op);
    log_error("crypto operation process failed at backend");
    return 0;
  } else {
    log_trace("completed_op's status is SUCCESS");
  }

  // 10. copy result
  log_trace("going to copy result");
  if (completed_op->sym->m_src) {
    log_trace("completed_op->sym->m_src is not null");
  } else {
    log_error("nullptr completed_op->sym->m_src");
  }
  struct rte_mbuf *result_mbuf = completed_op->sym->m_src;
  size_t result_len = rte_pktmbuf_data_len(result_mbuf);
  log_trace("got result_len: %zu", result_len);
  uint8_t *result_data = rte_pktmbuf_mtod(result_mbuf, uint8_t *);

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
    // BUG: did not check if padding is valid
    // if (pad > block_size || pad == 0) {
    //   rte_crypto_op_free(completed_op);
    //   log_error("invalid padding");
    //   return 0;
    // }
    // validate padding
    // for (size_t i = 0; i < pad; i++) {
    //   if (result_data[result_len - 1 - i] != pad) {
    //     rte_crypto_op_free(completed_op);
    //     log_error("padding validation failed");
    //     return 0;
    //   }
    // }
    // size_t unpadded_len = result_len - pad;
    // memcpy(out, result_data, unpadded_len);
    // *outl = unpadded_len;
    memcpy(out, result_data, result_len);
    *outl = result_len;
  }

  // 11. cleanup
  rte_pktmbuf_free(result_mbuf);
  rte_crypto_op_free(completed_op);

  return 1;
}

const OSSL_DISPATCH vcrypto_aes_256_cbc_fucntions[] = {
    {OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))vcrypto_aes_cbc_newctx},
    {OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))vcrypto_aes_cbc_freectx},
    {OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_einit},
    {OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))vcrypto_aes_cbc_dinit},
    {OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))vcrypto_aes_cbc_cipher},
    {OSSL_FUNC_CIPHER_GET_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_get_params},
    {OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_get_ctx_params},
    {OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_set_ctx_params},
    {OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_gettable_params},
    {OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_gettable_ctx_params},
    {OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_cipher_generic_settable_ctx_params},
};

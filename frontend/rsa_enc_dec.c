#include <stdint.h>
#include <string.h>

#include <generic/rte_pause.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include <log.h>
#include <xxhash.h>

#include "protocol.h"
#include "provider.h"
#include "rsa.h"

#define VCRYPTO_RSA_ENC_DEC_MAX_NAME_SIZE 50   /* algorithm name */
#define VCRYPTO_RSA_ENC_DEC_PROPQUERY_SIZE 256 /* property query strings */

static OSSL_ITEM vcrypto_padding_item[] = {
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
    {RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE},
    {RSA_PKCS1_OAEP_PADDING,
     OSSL_PKEY_RSA_PAD_MODE_OAEP}, /* Correct spelling first */
    {RSA_PKCS1_OAEP_PADDING, "oeap"},
    {RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931},
    {0, NULL}};

static OSSL_FUNC_asym_cipher_newctx_fn vcrypto_rsa_enc_dec_newctx;
static OSSL_FUNC_asym_cipher_freectx_fn vcrypto_rsa_enc_dec_freectx;
static OSSL_FUNC_asym_cipher_get_ctx_params_fn
    vcrypto_rsa_enc_dec_get_ctx_params;
static OSSL_FUNC_asym_cipher_gettable_ctx_params_fn
    vcrypto_rsa_enc_dec_gettable_ctx_params;
static OSSL_FUNC_asym_cipher_set_ctx_params_fn
    vcrypto_rsa_enc_dec_set_ctx_params;
static OSSL_FUNC_asym_cipher_settable_ctx_params_fn
    vcrypto_rsa_enc_dec_settable_ctx_params;
static OSSL_FUNC_asym_cipher_encrypt_init_fn vcrypto_rsa_einit;
static OSSL_FUNC_asym_cipher_decrypt_init_fn vcrypto_rsa_dinit;
static OSSL_FUNC_asym_cipher_encrypt_fn vcrypto_rsa_encrypt;
static OSSL_FUNC_asym_cipher_decrypt_fn vcrypto_rsa_decrypt;

static void *vcrypto_rsa_enc_dec_newctx(void *provctx) {
  vcrypto_rsa_enc_dec_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
  if (!ctx) {
    log_error("failed to alloc vcrypto_rsa_enc_dec_ctx");
    return NULL;
  }
  ctx->libctx = prov_libctx_of(provctx);
  return ctx;
}

static void vcrypto_rsa_enc_dec_freectx(void *cctx) {
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)cctx;
  if (!ctx) return;
  vcrypto_rsa_free(ctx->rsa);
  EVP_MD_free(ctx->mgf1_md);
  EVP_MD_free(ctx->oaep_md);
  OPENSSL_free(ctx->oaep_label);
  OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int vcrypto_rsa_init(void *vctx, void *vrsa, const OSSL_PARAM params[],
                            int operation) {
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)vctx;
  if (!ctx) {
    log_error("rsa_init: vctx is NULL");
    return 0;
  }
  ctx->rsa = vrsa;
  ctx->operation = operation;
  ctx->ctx_status_inited = 1;
  ctx->ctx_status_session_created = 0;
  ctx->session_data = NULL;

  return vcrypto_rsa_enc_dec_set_ctx_params(ctx, params);
}

static int vcrypto_rsa_einit(void *ctx, void *rsa, const OSSL_PARAM params[]) {
  log_trace("encrypt init");
  return vcrypto_rsa_init(ctx, rsa, params, EVP_PKEY_OP_ENCRYPT);
}

static int vcrypto_rsa_dinit(void *ctx, void *rsa, const OSSL_PARAM params[]) {
  log_trace("decrypt init");
  return vcrypto_rsa_init(ctx, rsa, params, EVP_PKEY_OP_DECRYPT);
}
static int vcrypto_rsa_enc_dec_set_ctx_params(void *vctx,
                                              const OSSL_PARAM params[]) {
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)vctx;
  if (!ctx) {
    log_error("rsa_enc_dec_set_ctx_params, null ptr ctx");
    return 0;
  }

  char mdname[VCRYPTO_RSA_ENC_DEC_MAX_NAME_SIZE];
  char mdprops[VCRYPTO_RSA_ENC_DEC_PROPQUERY_SIZE];
  char *str = NULL;

  const OSSL_PARAM *p;
  if (!params) {
    return 1;
  }

  p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
  if (p != NULL) {
    str = mdname;
    if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname))) {
      log_error("failed to get OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST");
      return 0;
    }

    p = OSSL_PARAM_locate_const(params,
                                OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS);
    if (p != NULL) {
      str = mdprops;
      if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops))) {
        log_error("failed to get OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST_PROPS");
        return 0;
      }
    }

    EVP_MD_free(ctx->oaep_md);
    ctx->oaep_md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    if (ctx->oaep_md == NULL) {
      log_error("failed to fetch oaep_md");
      return 0;
    }
  }

  p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
  if (p != NULL) {
    int pad_mode = 0;
    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (!OSSL_PARAM_get_int(p, &pad_mode)) {
        log_error("failed to get pad_mode");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING: {
      if (p->data == NULL) {
        log_error("p->data is NULL");
        return 0;
      }
      for (int i = 0; vcrypto_padding_item[i].id != 0; i++) {
        if (strcmp(p->data, vcrypto_padding_item[i].ptr) == 0) {
          pad_mode = vcrypto_padding_item[i].id;
          break;
        }
      }
      break;
    }
    default:
      log_error("invalid param when locating OSSL_ASYM_CIPHER_PARAM_PAD_MODE");
      return 0;
    }

    if (pad_mode == RSA_PKCS1_PSS_PADDING) {
      // FIXME: QAT_Engine return 0 here, why?
      // we return 0 as well here, temporarily
      log_error("pad_mode is RSA_PKCS1_PSS_PADDING, do not support");
      return 0;
    }
    if (pad_mode == RSA_PKCS1_OAEP_PADDING && ctx->oaep_md == NULL) {
      ctx->oaep_md = EVP_MD_fetch(ctx->libctx, "SHA1", mdprops);
      if (ctx->oaep_md == NULL) {
        log_error("failed to get SHA1 as oaep_md");
        return 0;
      }
    }
    ctx->pad_mode = pad_mode;
  }

  p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
  if (p != NULL) {
    str = mdname;
    if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdname))) {
      log_error("failed to get MGF1_DIGEST");
      return 0;
    }
    p = OSSL_PARAM_locate_const(params,
                                OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS);
    if (p != NULL) {
      str = mdprops;
      if (!OSSL_PARAM_get_utf8_string(p, &str, sizeof(mdprops))) {
        log_error("failed to get MGF1_DIGEST_PROPS");
        return 0;
      }
    } else {
      str = NULL;
    }
    EVP_MD_free(ctx->mgf1_md);
    ctx->mgf1_md = EVP_MD_fetch(ctx->libctx, mdname, str);
    if (ctx->mgf1_md == NULL) {
      return 0;
    }
  }

  p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
  if (p != NULL) {
    void *tmp_label = NULL;
    size_t tmp_labellen;
    if (!OSSL_PARAM_get_octet_string(p, &tmp_label, 0, &tmp_labellen)) {
      log_error("failed to get OAEP_LABEL");
      return 0;
    }
    OPENSSL_free(ctx->oaep_label);
    ctx->oaep_label = (unsigned char *)tmp_label;
    ctx->oaep_labellen = tmp_labellen;
  }

  p = OSSL_PARAM_locate_const(params,
                              OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
  if (p != NULL) {
    unsigned int client_version;
    if (!OSSL_PARAM_get_uint(p, &client_version)) {
      log_error("failed to get TLS_CLIENT_VERSION");
      return 0;
    }
    ctx->client_version = client_version;
  }

  p = OSSL_PARAM_locate_const(params,
                              OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
  if (p != NULL) {
    unsigned int alt_version;
    if (!OSSL_PARAM_get_uint(p, &alt_version)) {
      log_error("failed to get TLS_NECOTIATED_VERSION");
      return 0;
    }
    ctx->alt_version = alt_version;
  }

  return 1;
}

static const OSSL_PARAM vcrypto_rsa_enc_dec_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST_PROPS, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *
vcrypto_rsa_enc_dec_settable_ctx_params(ossl_unused void *cctx,
                                        ossl_unused void *provctx) {
  return vcrypto_rsa_enc_dec_known_settable_ctx_params;
}

static int vcrypto_rsa_enc_dec_get_ctx_params(void *cctx, OSSL_PARAM params[]) {
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)cctx;
  if (!ctx) {
    log_error("NULL ptr ctx");
    return 0;
  }

  OSSL_PARAM *p;
  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
  if (p != NULL) {
    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (!OSSL_PARAM_set_int(p, ctx->pad_mode)) {
        log_error("failed to set PAD_MODE");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING: {
      char *word = NULL;
      for (int i = 0; vcrypto_padding_item[i].id != 0; i++) {
        if (ctx->pad_mode == (int)vcrypto_padding_item[i].id) {
          word = vcrypto_padding_item[i].ptr;
          break;
        }
      }
      if (word != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, word)) {
          log_error("failed to set PAD_MODE");
          return 0;
        } else {
          log_error("failed to get pad_mode_param in padding_item");
        }
      }
    } break;
    default:
      return 0;
    }
  }

  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
  if (p != NULL &&
      !OSSL_PARAM_set_utf8_string(
          p, ctx->oaep_md == NULL ? "" : EVP_MD_get0_name(ctx->oaep_md))) {
    log_error("failed to set OAEP_DIGEST");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
  if (p != NULL) {
    EVP_MD *mgf1_md = ctx->mgf1_md == NULL ? ctx->oaep_md : ctx->mgf1_md;
    if (!OSSL_PARAM_set_utf8_string(
            p, mgf1_md == NULL ? "" : EVP_MD_get0_name(mgf1_md))) {
      log_error("failed to set MGF1_MD");
      return 0;
    }
  }

  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
  if (p != NULL &&
      !OSSL_PARAM_set_octet_ptr(p, ctx->oaep_label, ctx->oaep_labellen)) {
    log_error("failed to set OAEP_LABEL");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION);
  if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->client_version)) {
    log_error("failed to set CLIENT_VERSION");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION);
  if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->alt_version)) {
    log_error("failed to set NEGOTIATED_VERSION");
  }

  return 1;
}

static const OSSL_PARAM vcrypto_rsa_enc_dec_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_DEFN(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, OSSL_PARAM_OCTET_PTR,
                    NULL, 0),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_CLIENT_VERSION, NULL),
    OSSL_PARAM_uint(OSSL_ASYM_CIPHER_PARAM_TLS_NEGOTIATED_VERSION, NULL),
    OSSL_PARAM_END};

static const OSSL_PARAM *
vcrypto_rsa_enc_dec_gettable_ctx_params(ossl_unused void *cctx,
                                        ossl_unused void *provctx) {
  return vcrypto_rsa_enc_dec_known_gettable_ctx_params;
}

static int vcrypto_rsa_encrypt(void *cctx, unsigned char *out, size_t *outlen,
                               size_t outsize, const unsigned char *in,
                               size_t inlen) {
  log_trace("enter vcrypto_rsa_encrypt");
  int ret = 0;
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)cctx;

  // 1. status check
  if (!ctx || !out || !in || !outlen) {
    log_error("nullptr in passed in params");
    return 0;
  }

  // 2. create session
  if (!ctx->ctx_status_session_created) {
    ctx->session_data->key_data = VC_RSA_to_rsa_data(ctx->rsa);
    if (!vcrypto_fe_protocol_create_sess(ctx->session_data)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    log_trace("vcrypto_fe_protocol_create_sess success");
    ctx->ctx_status_session_created = 1;
  }

  // 3. data prepare
  if (inlen > RSA_MAX_KEY_SIZE_BYTES) {
    log_error("inlen: %d > RSA_MAX_KEY_SIZE_BYTES: %d", inlen,
              RSA_MAX_KEY_SIZE_BYTES);
    return 0;
  }
  // 3.1 text
  struct rte_mbuf *text_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!text_mbuf ||
      rte_pktmbuf_append(text_mbuf, RSA_MAX_KEY_SIZE_BYTES) == 0) {
    log_error("text_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *text_ptr = rte_pktmbuf_mtod(text_mbuf, uint8_t *);
  memcpy(text_ptr, in, inlen);
  // 3.2 cipher
  struct rte_mbuf *cipher_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!cipher_mbuf ||
      rte_pktmbuf_append(cipher_mbuf, RSA_MAX_KEY_SIZE_BYTES) == 0) {
    log_error("cipher_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *cipher_ptr = rte_pktmbuf_mtod(cipher_mbuf, uint8_t *);

  // 4. crypto op allocation
  struct rte_crypto_op *op =
      rte_crypto_op_alloc(crypto_op_mempool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    log_error("crypto op alloc failed");
    goto cleanup;
  }

  // 5. fill in op
  rte_crypto_op_attach_asym_session(op, ctx->session_data->sess);
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_ENCRYPT;
  // FIXME: rsa.message.data requires uint8_t, instead of mbuf!
  op->asym->rsa.message.data = text_ptr;
  op->asym->rsa.message.length = inlen;
  op->asym->rsa.cipher.data = cipher_ptr;
  op->asym->rsa.cipher.length = RSA_MAX_KEY_SIZE_BYTES;

  // 6. send to daemon
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    log_error("enqueue to backend the crypto op failed");
    goto cleanup;
  }

  // 7. wait for response
  log_trace("waiting for response...");
  struct rte_crypto_op *completed_op = NULL;
  while (rte_ring_dequeue(rx_ring, (void **)&completed_op) != 0) {
    rte_pause();
  }
  log_trace("got response");

  if (!completed_op) {
    log_error("got NULL for completed_op");
    goto cleanup;
  } else {
    log_trace("completed_op = %p", completed_op);
  }
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    log_error("crypto operation process failed at backend");
    goto cleanup;
  } else {
    log_trace("completed_op's status is SUCCESS");
  }

  // 8. copy result
  uint8_t *result_ptr = completed_op->asym->rsa.cipher.data;
  if (outsize < RSA_MAX_KEY_SIZE_BYTES) {
    log_error("outsize: %zu < RSA_MAX_KEY_SIZE_BYTES: %zu", outsize,
              RSA_MAX_KEY_SIZE_BYTES);
    goto cleanup;
  }
  memcpy(out, result_ptr, RSA_MAX_KEY_SIZE_BYTES);
  *outlen = RSA_MAX_KEY_SIZE_BYTES;
  ret = 1;

cleanup:
  if (text_mbuf)
    rte_pktmbuf_free(text_mbuf);
  if (cipher_mbuf)
    rte_pktmbuf_free(cipher_mbuf);
  if (op)
    rte_crypto_op_free(op);
  return ret;
}

static int vcrypto_rsa_decrypt(void *cctx, unsigned char *out, size_t *outlen,
                               size_t outsize, const unsigned char *in,
                               size_t inlen) {
  log_trace("enter vcrypto_rsa_decrypt");
  int ret = 0;
  log_trace("entering vcrypto_rsa_encrypt");
  vcrypto_rsa_enc_dec_ctx *ctx = (vcrypto_rsa_enc_dec_ctx *)cctx;

  // 1. status check
  if (!ctx || !out || !in || !outlen) {
    log_error("nullptr in passed in params");
    return 0;
  }

  // 2. create session
  if (!ctx->ctx_status_session_created) {
    ctx->session_data->key_data = VC_RSA_to_rsa_data(ctx->rsa);
    if (!vcrypto_fe_protocol_create_sess(ctx->session_data)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    log_trace("vcrypto_fe_protocol_create_sess success");
    ctx->ctx_status_session_created = 1;
  }

  // 3. data prepare
  if (inlen > RSA_MAX_KEY_SIZE_BYTES) {
    log_error("inlen: %d > RSA_MAX_KEY_SIZE_BYTES: %d", inlen,
              RSA_MAX_KEY_SIZE_BYTES);
    return 0;
  }
  // 3.1 cipher
  struct rte_mbuf *cipher_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!cipher_mbuf ||
      rte_pktmbuf_append(cipher_mbuf, RSA_MAX_KEY_SIZE_BYTES) == 0) {
    log_error("text_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *cipher_ptr = rte_pktmbuf_mtod(cipher_mbuf, uint8_t *);
  memcpy(cipher_ptr, in, inlen);
  // 3.2 result
  struct rte_mbuf *decrypt_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!decrypt_mbuf ||
      rte_pktmbuf_append(decrypt_mbuf, RSA_MAX_KEY_SIZE_BYTES) == 0) {
    log_error("cipher_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *decrypt_ptr = rte_pktmbuf_mtod(decrypt_mbuf, uint8_t *);

  // 4. crypto op allocation
  struct rte_crypto_op *op =
      rte_crypto_op_alloc(crypto_op_mempool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    log_error("crypto op alloc failed");
    goto cleanup;
  }

  // 5. fill in op
  rte_crypto_op_attach_asym_session(op, ctx->session_data->sess);
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_DECRYPT;
  op->asym->rsa.cipher.data = cipher_ptr;
  op->asym->rsa.cipher.length = RSA_MAX_KEY_SIZE_BYTES;
  op->asym->rsa.message.data = decrypt_ptr;
  op->asym->rsa.message.length = RSA_MAX_KEY_SIZE_BYTES;

  // 6. send to daemon
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    log_error("enqueue to backend the crypto op failed");
    goto cleanup;
  }

  // 7. wait for response
  log_trace("waiting for response...");
  struct rte_crypto_op *completed_op = NULL;
  while (rte_ring_dequeue(rx_ring, (void **)&completed_op) != 0) {
    rte_pause();
  }
  log_trace("got response");

  if (!completed_op) {
    log_error("got NULL for completed_op");
    goto cleanup;
  } else {
    log_trace("completed_op = %p", completed_op);
  }
  if (completed_op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
    log_error("crypto operation process failed at backend");
    goto cleanup;
  } else {
    log_trace("completed_op's status is SUCCESS");
  }

  // 8. copy result
  uint8_t *result_ptr = completed_op->asym->rsa.message.data;
  *outlen = completed_op->asym->rsa.message.length;
  if (outsize < *outlen) {
    log_error("outsize: %zu < decrypted_data_len: %zu", outsize, *outlen);
    goto cleanup;
  }
  memcpy(out, result_ptr, RSA_MAX_KEY_SIZE_BYTES);
  ret = 1;

cleanup:
  if (cipher_mbuf)
    rte_pktmbuf_free(cipher_mbuf);
  if (decrypt_mbuf)
    rte_pktmbuf_free(decrypt_mbuf);
  if (op)
    rte_crypto_op_free(op);
  return ret;
}

const OSSL_DISPATCH vcrypto_rsa2048_enc_dec_functions[] = {
    {OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))vcrypto_rsa_enc_dec_newctx},
    {OSSL_FUNC_ASYM_CIPHER_FREECTX,
     (void (*)(void))vcrypto_rsa_enc_dec_freectx},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT_INIT, (void (*)(void))vcrypto_rsa_einit},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))vcrypto_rsa_dinit},
    {OSSL_FUNC_ASYM_CIPHER_ENCRYPT, (void (*)(void))vcrypto_rsa_encrypt},
    {OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))vcrypto_rsa_decrypt},
    {OSSL_FUNC_ASYM_CIPHER_GET_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_enc_dec_get_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_enc_dec_set_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_GETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_enc_dec_gettable_ctx_params},
    {OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_enc_dec_settable_ctx_params},
};

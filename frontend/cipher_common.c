#include <stdlib.h>
#include <string.h>

#include <openssl/proverr.h>

#include <log.h>

#include "cipher_common.h"
#include "openssl/e_os2.h"
#include "openssl/params.h"

static const OSSL_PARAM cipher_known_gettable_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_AEAD, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CUSTOM_IV, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_CTS, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK, NULL),
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_HAS_RAND_KEY, NULL),
    OSSL_PARAM_END};

const OSSL_PARAM *
ossl_cipher_generic_gettable_params(ossl_unused void *provctx) {
  return cipher_known_gettable_params;
}

int ossl_cipher_generic_get_params(OSSL_PARAM params[], unsigned int md,
                                   uint64_t flags, size_t kbits, size_t blkbits,
                                   size_t ivbits) {
  OSSL_PARAM *p;

  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE);
  if (p != NULL && !OSSL_PARAM_set_uint(p, md)) {
    log_error("OSSL_CIPHER_PARAM_MODE set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_AEAD);
  if (p != NULL &&
      !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_AEAD) != 0)) {
    log_error("PROV_CIPHER_FLAG_AEAD set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CUSTOM_IV);
  if (p != NULL &&
      !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CUSTOM_IV) != 0)) {
    log_error("PROV_CIPHER_FLAG_CUSTOM_IV set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_CTS);
  if (p != NULL &&
      !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_CTS) != 0)) {
    log_error("PROV_CIPHER_FLAG_CTS set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS1_MULTIBLOCK);
  if (p != NULL &&
      !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_TLS1_MULTIBLOCK) != 0)) {
    log_error("PROV_CIPHER_FLAG_TLS1_MULTIBLOCK set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_HAS_RAND_KEY);
  if (p != NULL &&
      !OSSL_PARAM_set_int(p, (flags & PROV_CIPHER_FLAG_RAND_KEY) != 0)) {
    log_error("PROV_CIPHER_FLAG_RAND_KEY set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, kbits / 8)) {
    log_error("OSSL_CIPHER_PARAM_KEYLEN set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, blkbits / 8)) {
    log_error("OSSL_CIPHER_PARAM_BLOCK_SIZE set failed");
    return 0;
  }
  p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
  if (p != NULL && !OSSL_PARAM_set_size_t(p, ivbits / 8)) {
    log_error("OSSL_CIPHER_PARAM_IVLEN set failed");
    return 0;
  }
  return 1;
}

static const OSSL_PARAM ossl_cipher_generic_known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_UPDATED_IV, NULL, 0),
    {OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0,
     OSSL_PARAM_UNMODIFIED},
    OSSL_PARAM_END
};

const OSSL_PARAM *ossl_cipher_generic_gettable_ctx_params(ossl_unused void *cctx,
                                        ossl_unused void *provctx) {
  return ossl_cipher_generic_known_gettable_ctx_params;
}

static const OSSL_PARAM ossl_cipher_generic_known_settable_ctx_params[] = {
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_PADDING, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_NUM, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_USE_BITS, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_TLS_VERSION, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
    OSSL_PARAM_END
};


const OSSL_PARAM *ossl_cipher_generic_settable_ctx_params(ossl_unused void *cctx,
                                        ossl_unused void *provctx) {
  return ossl_cipher_generic_known_settable_ctx_params;
}

void ossl_cipher_generic_reset_ctx(PROV_CIPHER_CTX *ctx) {
    if (ctx != NULL && ctx->alloced) {
        OPENSSL_free(ctx->tlsmac);
        ctx->alloced = 0;
        ctx->tlsmac = NULL;
    }
}

static int cipher_generic_init_internal(PROV_CIPHER_CTX *ctx,
                                        const unsigned char *key, size_t keylen,
                                        const unsigned char *iv, size_t ivlen,
                                        const OSSL_PARAM params[], int enc)
{
    ctx->num = 0;
    ctx->bufsz = 0;
    ctx->updated = 0;
    ctx->enc = enc ? 1 : 0;

    if (iv != NULL && ctx->mode != EVP_CIPH_ECB_MODE) {
        if (!ossl_cipher_generic_initiv(ctx, iv, ivlen))
            return 0;
    }
    if (iv == NULL && ctx->iv_set
        && (ctx->mode == EVP_CIPH_CBC_MODE
            || ctx->mode == EVP_CIPH_CFB_MODE
            || ctx->mode == EVP_CIPH_OFB_MODE))
        /* reset IV for these modes to keep compatibility with 1.1.1 */
        memcpy(ctx->iv, ctx->oiv, ctx->ivlen);

    if (key != NULL) {
        if (ctx->variable_keylength == 0) {
            if (keylen != ctx->keylen) {
                log_error("invalid key length at cipher_generic_init_internal");
                return 0;
            }
        } else {
            ctx->keylen = keylen;
        }
    }
    return ossl_cipher_generic_set_ctx_params(ctx, params);
}

int ossl_cipher_generic_einit(void *vctx, const unsigned char *key,
                              size_t keylen, const unsigned char *iv,
                              size_t ivlen, const OSSL_PARAM params[])
{
    return cipher_generic_init_internal((PROV_CIPHER_CTX *)vctx, key, keylen,
                                        iv, ivlen, params, 1);
}

int ossl_cipher_generic_dinit(void *vctx, const unsigned char *key,
                              size_t keylen, const unsigned char *iv,
                              size_t ivlen, const OSSL_PARAM params[])
{
    return cipher_generic_init_internal((PROV_CIPHER_CTX *)vctx, key, keylen,
                                        iv, ivlen, params, 0);
}

int ossl_cipher_generic_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->ivlen)) {
        log_error("failed to set OSSL_CIPHER_PARAM_IVLEN");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->pad)) {
        log_error("failed to set OSSL_CIPHER_PARAM_PADDING");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->oiv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->oiv, ctx->ivlen)) {
        log_error("failed to set OSSL_CIPHER_PARAM_IV");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_UPDATED_IV);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, &ctx->iv, ctx->ivlen)
        && !OSSL_PARAM_set_octet_string(p, &ctx->iv, ctx->ivlen)) {
        log_error("failed to set OSSL_CIPHER_PARAM_UPDATED_IV");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->num)) {
        log_error("failed to set OSSL_CIPHER_PARAM_NUM");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->keylen)) {
        log_error("failed to set OSSL_CIPHER_PARAM_KEYLEN");
        return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
        && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize)) {
        log_error("failed to set OSSL_CIPHER_PARAM_TLS_MAC");
        return 0;
    }
    return 1;
}

int ossl_cipher_generic_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_CIPHER_CTX *ctx = (PROV_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad)) {
            log_error("failed to get OSSL_CIPHER_PARAM_PADDING");
            return 0;
        }
        ctx->pad = pad ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_USE_BITS);
    if (p != NULL) {
        unsigned int bits;

        if (!OSSL_PARAM_get_uint(p, &bits)) {
            log_error("failed to get OSSL_CIPHER_PARAM_USE_BITS");
            return 0;
        }
        ctx->use_bits = bits ? 1 : 0;
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_VERSION);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint(p, &ctx->tlsversion)) {
            log_error("failed to get OSSL_CIPHER_PARAM_TLS_VERSION");
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize)) {
            log_error("failed to get OSSL_CIPHER_PARAM_TLS_MAC_SIZE");
            return 0;
        }
    }
    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL) {
        unsigned int num;

        if (!OSSL_PARAM_get_uint(p, &num)) {
            log_error("failed to get OSSL_CIPHER_PARAM_NUM");
            return 0;
        }
        ctx->num = num;
    }
    return 1;
}

int ossl_cipher_generic_initiv(PROV_CIPHER_CTX *ctx, const unsigned char *iv,
                               size_t ivlen)
{
    if (ivlen != ctx->ivlen
        || ivlen > sizeof(ctx->iv)) {
        log_error("invalid iv key length in ossl_cipher_generic_initiv");
        return 0;
    }
    ctx->iv_set = 1;
    memcpy(ctx->iv, iv, ivlen);
    memcpy(ctx->oiv, iv, ivlen);
    return 1;
}


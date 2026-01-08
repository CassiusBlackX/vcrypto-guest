#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <generic/rte_pause.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

#include <openssl/bio.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include <log.h>
#include <xxhash.h>

#include "protocol.h"
#include "provider.h"
#include "rsa.h"
#include "rsa_keymgmt_utils.h"

#define rsa_pss_restricted(ctx) (ctx->min_saltlen != -1)
#define RSA_DEFAULT_DIGEST_NAME OSSL_DIGEST_NAME_SHA1
#define RSA_PSS_SALTLEN_AUTO_DIGEST_MAX -4

static const OSSL_ITEM oaeppss_name_nid_map[] = {
    {NID_sha1, OSSL_DIGEST_NAME_SHA1},
    {NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
    {NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
    {NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
    {NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
    {NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224},
    {NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256},
};

static OSSL_ITEM padding_item[] = {
    {RSA_PKCS1_PADDING, OSSL_PKEY_RSA_PAD_MODE_PKCSV15},
    {RSA_NO_PADDING, OSSL_PKEY_RSA_PAD_MODE_NONE},
    {RSA_X931_PADDING, OSSL_PKEY_RSA_PAD_MODE_X931},
    {RSA_PKCS1_PSS_PADDING, OSSL_PKEY_RSA_PAD_MODE_PSS},
    {0, NULL}};

const VCRYPTO_RSA_PSS_PARAMS_30 default_RSASSA_PSS_params = {
    NID_sha1, /* default hash alg */
    {
        NID_mgf1, /* default mask gen alg  */
        NID_sha1, /* default mgf1 hash */
    },
    20, /* default salt len */
    1,  /* default trailer field (0xbc) */
};

static int vcrypto_digest_md_to_nid(const EVP_MD *md, const OSSL_ITEM *it,
                                    size_t it_len) {
  if (md == NULL)
    return NID_undef;

  for (size_t i = 0; i < it_len; i++) {
    if (EVP_MD_is_a(md, it[i].ptr))
      return (int)it[i].id;
  }
  return NID_undef;
}

static int vcrypto_digest_get_approved_nid(const EVP_MD *md) {
  static const OSSL_ITEM name_to_nid[] = {
      {NID_sha1, OSSL_DIGEST_NAME_SHA1},
      {NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
      {NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
      {NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
      {NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
      {NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224},
      {NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256},
      {NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224},
      {NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256},
      {NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384},
      {NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512},
  };
  return vcrypto_digest_md_to_nid(md, name_to_nid, OSSL_NELEM(name_to_nid));
}

static int vcrypto_digest_rsa_sign_get_md_nid(OSSL_LIB_CTX *ctx,
                                              const EVP_MD *md,
                                              int sha1_allowed) {
  return vcrypto_digest_get_approved_nid(md);
}

// return 1 on success, 0 on failure
static int vcrypto_rsa_check_padding(const vcrypto_rsa_sign_ctx *ctx,
                                     const char *mdname,
                                     const char *mgf1_mdname, int mdnid) {
  switch (ctx->pad_mode) {
  case RSA_NO_PADDING:
    log_error("pad_mode is no_padding");
    return 0;
  case RSA_X931_PADDING:
    log_error("I don't know what exactly it is, do not support it!");
    return 0;
  case RSA_PKCS1_PSS_PADDING:
    if (rsa_pss_restricted(ctx)) {
      if ((mdname != NULL && !EVP_MD_is_a(ctx->md, mdname)) ||
          (mgf1_mdname != NULL && !EVP_MD_is_a(ctx->mgf1_md, mgf1_mdname))) {
        log_error("though is PKCS1_PSS_padding, but still no right");
        return 0;
      }
    }
    break;
  default:
    break;
  }
  return 1;
}

// setup mgf1 digest method for RSA-PSS ops
// return 1 on success, 0 on failure
static int vcrypto_rsa_setup_mgf1_md(vcrypto_rsa_sign_ctx *ctx,
                                     const char *mdname, const char *mdprops) {
  size_t len;
  EVP_MD *md = NULL;
  int mdnid;
  if (mdprops == NULL)
    mdprops = ctx->propq;

  if ((md = EVP_MD_fetch(ctx->libctx, mdname, mdprops)) == NULL) {
    log_error("%s could not be fetch", mdname);
    return 0;
  }
  // the default for mgf1 is SHA1
  if ((mdnid = vcrypto_digest_rsa_sign_get_md_nid(ctx->libctx, md, 1)) <= 0 ||
      !vcrypto_rsa_check_padding(ctx, NULL, mdname, mdnid)) {
    if (mdnid <= 0) {
      log_error("digest=%s, but mdnid <= 0", mdname);
    }
    EVP_MD_free(md);
    return 0;
  }
  len = OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
  if (len >= sizeof(ctx->mgf1_mdname)) {
    log_error("%s exceeds name buffer length", mdname);
    EVP_MD_free(md);
    return 0;
  }
  EVP_MD_free(ctx->mgf1_md);
  ctx->mgf1_md = md;
  ctx->mgf1_mdnid = mdnid;
  ctx->mgf1_md_set = 1;
  return 1;
}

// setup main digest method for rsa ops
// return 1 on success and 0 on failure
static int vcrypto_rsa_setup_md(vcrypto_rsa_sign_ctx *ctx, const char *mdname,
                                const char *mdprops) {
  if (mdprops == NULL)
    mdprops = ctx->propq;

  if (mdname != NULL) {
    EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
    int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);
    int md_nid =
        vcrypto_digest_rsa_sign_get_md_nid(ctx->libctx, md, sha1_allowed);
    size_t mdname_len = strlen(mdname);

    if (md == NULL) {
      log_error("%s could not be fetched", mdname);
      return 0;
    }
    if (md_nid <= 0) {
      log_error("digest=%s, but md_nid <= 0", mdname);
      EVP_MD_free(md);
      return 0;
    }
    if (mdname_len >= sizeof(ctx->mdname)) {
      log_error("%s exceeds name buffer length", mdname);
      EVP_MD_free(md);
      return 0;
    }

    if (!ctx->mgf1_md_set) {
      if (!EVP_MD_up_ref(md)) {
        EVP_MD_free(md);
        return 0;
      }
      EVP_MD_free(ctx->mgf1_md);
      ctx->mgf1_md = md;
      ctx->mgf1_mdnid = md_nid;
      OPENSSL_strlcpy(ctx->mgf1_mdname, mdname, sizeof(ctx->mgf1_mdname));
    }
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->mdctx = NULL;
    ctx->md = md;
    ctx->mdnid = md_nid;
    OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
  }
  return 1;
}

const char *nid2name(int meth, const OSSL_ITEM *items, size_t items_n) {
  for (size_t i = 0; i < items_n; i++) {
    if (meth == (int)items[i].id)
      return items[i].ptr;
  }
  return NULL;
}

const char *vcrypto_rsa_oaeppss_nid2name(int md) {
  return nid2name(md, oaeppss_name_nid_map, OSSL_NELEM(oaeppss_name_nid_map));
}

static int vcrypto_rsa_check_parameters(vcrypto_rsa_sign_ctx *ctx,
                                        int min_saltlen) {
  if (ctx->pad_mode == RSA_PKCS1_PSS_PADDING) {
    int max_saltlen;

    // see if minimum salt length exceeds maximum possible
    max_saltlen = vcrypto_rsa_size(ctx->rsa) - EVP_MD_size(ctx->md);
    if ((vcrypto_rsa_bits(ctx->rsa) & 0x7) == 1)
      max_saltlen--;
    if (min_saltlen < 0 || min_saltlen > max_saltlen) {
      log_error("min_saltlen < 0 or min_saltlen > max_saltlen");
      return 0;
    }
    ctx->min_saltlen = min_saltlen;
  }
  return 1;
}

static OSSL_FUNC_signature_newctx_fn vcrypto_rsa_sign_newctx;
static OSSL_FUNC_signature_freectx_fn vcrypto_rsa_sign_freectx;
static OSSL_FUNC_signature_sign_init_fn vcrypto_rsa_sinit;
static OSSL_FUNC_signature_verify_init_fn vcrypto_rsa_vinit;
static OSSL_FUNC_signature_sign_fn vcrypto_rsa_sign;
static OSSL_FUNC_signature_verify_fn vcrypto_rsa_verify;
// TODO: currently we do not implement digest_sign/verify func!
// static OSSL_FUNC_signature_digest_sign_init_fn vcrypto_rsa_digest_sinit;
// static OSSL_FUNC_signature_digest_sign_fn vcrypto_rsa_digest_sign;
// static OSSL_FUNC_signature_digest_verify_init_fn vcrypto_rsa_digest_vinit;
// static OSSL_FUNC_signature_digest_verify_fn vcrypto_rsa_digest_verify;
static OSSL_FUNC_signature_set_ctx_params_fn vcrypto_rsa_sign_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn
    vcrypto_rsa_sign_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_params_fn vcrypto_rsa_sign_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn
    vcrypto_rsa_gettable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn vcrypto_rsa_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn
    vcrypto_rsa_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn vcrypto_rsa_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn
    vcrypto_rsa_settable_ctx_md_params;

static void *vcrypto_rsa_sign_newctx(void *provctx, const char *propq) {
  vcrypto_rsa_sign_ctx *sctx = OPENSSL_zalloc(sizeof(vcrypto_rsa_sign_ctx));
  if (!sctx) {
    log_error("failed to alloc for vcrypto_rsa_sign_ctx");
    return NULL;
  }
  char *propq_copy = OPENSSL_strdup(propq);
  if (!propq_copy) {
    log_error("failed to copy propq");
    OPENSSL_free(sctx);
    return NULL;
  }

  sctx->libctx = prov_libctx_of(provctx);
  sctx->flag_allow_md = 1;
  sctx->propq = propq_copy;
  sctx->saltlen = RSA_PSS_SALTLEN_AUTO_DIGEST_MAX;
  return sctx;
}

static void vcrypto_rsa_sign_freectx(void *vsctx) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (!ctx)
    return;

  EVP_MD_CTX_free(ctx->mdctx);
  EVP_MD_free(ctx->md);
  EVP_MD_free(ctx->mgf1_md);
  OPENSSL_free(ctx->propq);
  vcrypto_rsa_free(ctx->rsa);
  OPENSSL_clear_free(ctx, sizeof(*ctx));
}

static int vcrypto_rsa_sign_set_ctx_params(void *vsctx,
                                           const OSSL_PARAM params[]) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  const OSSL_PARAM *p;
  int pad_mode;
  int saltlen;
  char mdname[50] = "", *mdname_ptr = NULL;
  char mdprops[256] = "", *mdprops_ptr = NULL;
  char mgf1mdname[50] = "", *mgf1mdname_ptr = NULL;
  char mgf1mdprops[256] = "", *mgf1mdprops_ptr = NULL;

  if (!ctx) {
    log_error("nullptr in vcrypto_rsa_sign_set_ctx_params");
    return 0;
  }
  if (params == NULL || params->key == NULL)
    return 1;

  pad_mode = ctx->pad_mode;
  saltlen = ctx->saltlen;

  p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
  if (p != NULL && !ctx->flag_allow_md) {
    log_error("ctx does not allow setting md");
    return 0;
  }
  if (p != NULL) {
    const OSSL_PARAM *propsp =
        OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
    mdname_ptr = mdname;
    if (!OSSL_PARAM_get_utf8_string(p, &mdname_ptr, sizeof(mdname))) {
      log_error("failed to get mdname");
      return 0;
    }
    if (propsp != NULL) {
      mdprops_ptr = mdprops;
      if (!OSSL_PARAM_get_utf8_string(propsp, &mdprops_ptr, sizeof(mdprops))) {
        log_error("failed to get mdprops");
        return 0;
      }
    }
  }

  p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
  if (p != NULL) {
    const char *err_extra_text = NULL;
    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (OSSL_PARAM_get_int(p, &pad_mode)) {
        log_error("failed to get pad_mode");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING: {
      if (p->data == NULL) {
        log_error("p->data_type is utf8_string, but data is null");
        return 0;
      }
      for (int i = 0; padding_item[i].id != 0; i++) {
        if (strcmp(p->data, padding_item[i].ptr) == 0) {
          pad_mode = padding_item[i].id;
          break;
        }
      }
    } break;
    default:
      return 0;
    }

    switch (pad_mode) {
    case RSA_PKCS1_OAEP_PADDING:
      /*
       * OAEP padding is for asym cipher only,
       * should never be used in sign
       */
      log_error("invalid padmod!");
      return 0;
    case RSA_PKCS1_PSS_PADDING:
      if ((ctx->operation & (EVP_PKEY_OP_SIGN | EVP_PKEY_OP_VERIFY)) == 0) {
        log_error("PSS padding but not used for sign or verify!");
        return 0;
      }
      break;
    case RSA_PKCS1_PADDING:
      log_error("PKCS#1 padding not allowed with RSA-PSS");
      return 0;
    case RSA_NO_PADDING:
      log_error("no padding not allowed with RSA-PSS");
      return 0;
    case RSA_X931_PADDING:
      log_error("X.931 padding not allowed with RSA-PSS");
      return 0;
    default:
      log_error("unrecognized pad mode");
      return 0;
    }
  }

  p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
  if (p != NULL) {
    if (pad_mode != RSA_PKCS1_PSS_PADDING) {
      log_error("PSS salt len can only be specified if PSS padding has been "
                "specified first");
      return 0;
    }

    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (!OSSL_PARAM_get_int(p, &saltlen)) {
        log_error("failed to get salt_len");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING:
      if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST) == 0)
        saltlen = RSA_PSS_SALTLEN_DIGEST;
      else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_MAX) == 0)
        saltlen = RSA_PSS_SALTLEN_MAX;
      else if (strcmp(p->data, OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO) == 0)
        saltlen = RSA_PSS_SALTLEN_AUTO;
      else {
        saltlen = atoi(p->data);
        log_warn("not commonly seen salt len %d", saltlen);
      }
      break;
    default:
      return 0;
    }

    /*
     * RSA_PSS_SALTLEN_MAX is the currently lowest saltlen number possible
     */
    if (saltlen < RSA_PSS_SALTLEN_MAX) {
      log_error("current salt_len < RSA_PSS_SALTLEN_MAX");
      return 0;
    }
    if (rsa_pss_restricted(ctx)) {
      switch (saltlen) {
      case RSA_PSS_SALTLEN_AUTO:
      case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
        if (ctx->operation == EVP_PKEY_OP_VERIFY) {
          log_error("cannot use autodetected salt length");
          return 0;
        }
        break;
      case RSA_PSS_SALTLEN_DIGEST:
        if (ctx->min_saltlen > EVP_MD_size(ctx->md)) {
          log_error(
              "minimum salt length set to %d, but the digest only gives %d",
              ctx->min_saltlen, EVP_MD_get_size(ctx->md));
          return 0;
        }
        break;
      default:
        if ((saltlen >= 0) && (saltlen < ctx->min_saltlen)) {
          log_error("minimum salt len set to %d, but the actual salt len is "
                    "only set to %d",
                    ctx->min_saltlen, ctx->saltlen);
          return 0;
        }
      }
    }
  }

  p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
  if (p != NULL) {
    const OSSL_PARAM *propsp =
        OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES);
    mgf1mdname_ptr = mgf1mdname;
    if (!OSSL_PARAM_get_utf8_string(propsp, &mgf1mdname_ptr,
                                    sizeof(mgf1mdname))) {
      log_error("failed to get mgf1 mdname");
      return 0;
    }
    if (pad_mode != RSA_PKCS1_PSS_PADDING) {
      log_error("pad mode should be RSA_PKCS1_PSS_PADDING when using mgf1 md");
      return 0;
    }
  }

  ctx->saltlen = saltlen;
  ctx->pad_mode = pad_mode;
  if (ctx->md == NULL && mdname_ptr == NULL &&
      pad_mode == RSA_PKCS1_PSS_PADDING)
    mdname_ptr = RSA_DEFAULT_DIGEST_NAME;

  if (mgf1mdname_ptr != NULL &&
      !vcrypto_rsa_setup_mgf1_md(ctx, mgf1mdname_ptr, mgf1mdprops_ptr)) {
    log_error("failed to setup mgf1 md");
    return 0;
  }
  if (mdname_ptr != NULL &&
      !vcrypto_rsa_setup_md(ctx, mdname_ptr, mdprops_ptr)) {
    log_error("failed to setup md");
    return 0;
  } else {
    if (!vcrypto_rsa_check_padding(ctx, NULL, NULL, ctx->mdnid)) {
      log_error("padding check failed!");
      return 0;
    }
  }

  return 1;
}

static const OSSL_PARAM vcrypto_rsa_known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END,
};

static const OSSL_PARAM vcrypto_rsa_known_settable_ctx_params_no_digest[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_PROPERTIES, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *
vcrypto_rsa_sign_settable_ctx_params(void *vsctx, ossl_unused void *provctx) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (ctx != NULL && !ctx->flag_allow_md)
    return vcrypto_rsa_known_settable_ctx_params_no_digest;
  return vcrypto_rsa_known_settable_ctx_params;
}

static int vcrypto_rsa_sign_get_ctx_params(void *vsctx, OSSL_PARAM params[]) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  OSSL_PARAM *p;
  if (!ctx) {
    log_error("null ptr ctx in get_ctx_params");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
  if (p != NULL) {
    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (!OSSL_PARAM_set_int(p, ctx->pad_mode)) {
        log_error("failed to set pad_mode");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING: {
      const char *word = NULL;
      for (int i = 0; padding_item[i].id != 0; i++) {
        if (ctx->pad_mode == (int)padding_item[i].id) {
          word = padding_item[i].ptr;
          break;
        }
      }
      if (word != NULL) {
        if (!OSSL_PARAM_set_utf8_string(p, word)) {
          log_error("failed to set padding_item");
          return 0;
        }
      } else {
        log_error("failed to find matched padding_item");
        return 0;
      }
    } break;
    default:
      return 0;
    }
  }

  p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
  if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mdname)) {
    log_error("failed to set digest func, mdname");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
  if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->mgf1_mdname)) {
    log_error("failed to set mgf1 mdname");
    return 0;
  }

  p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
  if (p != NULL) {
    switch (p->data_type) {
    case OSSL_PARAM_INTEGER:
      if (!OSSL_PARAM_set_int(p, ctx->saltlen)) {
        log_error("failed to set salt len");
        return 0;
      }
      break;
    case OSSL_PARAM_UTF8_STRING: {
      const char *value = NULL;
      switch (ctx->saltlen) {
      case RSA_PSS_SALTLEN_DIGEST:
        value = OSSL_PKEY_RSA_PSS_SALT_LEN_DIGEST;
        break;
      case RSA_PSS_SALTLEN_MAX:
        value = OSSL_PKEY_RSA_PSS_SALT_LEN_MAX;
        break;
      case RSA_PSS_SALTLEN_AUTO:
        value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO;
        break;
      case RSA_PSS_SALTLEN_AUTO_DIGEST_MAX:
        value = OSSL_PKEY_RSA_PSS_SALT_LEN_AUTO_DIGEST_MAX;
        break;
      default: {
        int len = BIO_snprintf(p->data, p->data_size, "%d", ctx->saltlen);
        if (len <= 0) {
          log_error("failed to use BIO_snprintf to format ctx->saltlen");
          return 0;
        }
        p->return_size = len;
      } break;
      }
      if (value != NULL && !OSSL_PARAM_set_utf8_string(p, value)) {
        log_error("failed to set salt len");
        return 0;
      }
    } break;
    default:
      break;
    }
  }
  return 1;
}

static const OSSL_PARAM vcrypto_rsa_known_gettable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL, 0),
    OSSL_PARAM_END};

static const OSSL_PARAM *
vcrypto_rsa_gettable_ctx_params(ossl_unused void *vsctx,
                                ossl_unused void *provctx) {
  return vcrypto_rsa_known_gettable_ctx_params;
}

static int vcrypto_rsa_get_ctx_md_params(void *vsctx, OSSL_PARAM params[]) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (!ctx) {
    log_error("null ptr ctx in vcrypto_rsa_get_ctx_md_params");
    return 0;
  }
  if (ctx->mdctx == NULL) {
    log_error("ctx->mdctx is null, there is nothing to get");
    return 0;
  }
  return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *vcrypto_rsa_gettable_ctx_md_params(void *vsctx) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (!ctx) {
    log_error("null ptr ctx in vcrypto_rsa_gettable_ctx_md_params");
    return 0;
  }
  if (ctx->md == NULL) {
    log_error("ctx->md is null, there is nothing to get");
    return 0;
  }
  return EVP_MD_gettable_ctx_params(ctx->md);
}

static int vcrypto_rsa_set_ctx_md_params(void *vsctx,
                                         const OSSL_PARAM params[]) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (!ctx) {
    log_error("null ptr ctx in vcrypto_rsa_set_ctx_md_params");
    return 0;
  }
  if (ctx->mdctx == NULL) {
    log_error("ctx->mdctx is null, there is nothing to set");
    return 0;
  }
  return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *vcrypto_rsa_settable_ctx_md_params(void *vsctx) {
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;
  if (!ctx) {
    log_error("null ptr ctx in vcrypto_rsa_settable_ctx_md_params");
    return 0;
  }
  if (ctx->md == NULL) {
    log_error("ctx->md is null, there is nothing to set");
    return 0;
  }
  return EVP_MD_settable_ctx_params(ctx->md);
}

static int vcrypto_rsa_sign_verify_init(vcrypto_rsa_sign_ctx *ctx, void *vrsa,
                                        const OSSL_PARAM params[],
                                        int operation) {
  if (!ctx || !vrsa) {
    log_error("null ptr in ctx or vrsa");
    return 0;
  }

  VCRYPTO_RSA *rsa = (VCRYPTO_RSA *)vrsa;
  if (rsa) {
    if (!vcrypto_rsa_up_ref(rsa)) {
      log_error("failed to up ref rsa");
      return 0;
    }
    vcrypto_rsa_free(ctx->rsa);
    ctx->rsa = rsa;
  }
  ctx->operation = operation;
  ctx->flag_allow_update = 1;
  ctx->flag_allow_final = 1;
  ctx->flag_allow_oneshot = 1;

  /* maximum for sign, auto for verify */
  ctx->saltlen = RSA_PSS_SALTLEN_AUTO;
  ctx->min_saltlen = -1;

  switch (vcrypto_rsa_test_flags(ctx->rsa, RSA_FLAG_TYPE_MASK)) {
  case RSA_FLAG_TYPE_RSA:
    ctx->pad_mode = RSA_PKCS1_PADDING;
    break;
  case RSA_FLAG_TYPE_RSASSAPSS: {
    ctx->pad_mode = RSA_PKCS1_PSS_PADDING;
    const VCRYPTO_RSA_PSS_PARAMS_30 *pss =
        vcrypto_rsa_get0_pss_params_30(ctx->rsa);
    if (!vcrypto_rsa_pss_params_30_is_unrestricted(pss)) {
      int md_nid = vcrypto_rsa_pss_params_30_hashalg(pss);
      int mgf1md_nid = vcrypto_rsa_pss_params_30_maskgenhashalg(pss);
      int min_saltlen = vcrypto_rsa_pss_params_30_saltlen(pss);
      const char *mdname, *mgf1mdname;
      size_t len;

      mdname = vcrypto_rsa_oaeppss_nid2name(md_nid);
      mgf1mdname = vcrypto_rsa_oaeppss_nid2name(mgf1md_nid);

      if (mdname == NULL) {
        log_error("PSS restrictions lack hash alg");
        return 0;
      }
      if (mgf1mdname == NULL) {
        log_error("PSS restrictions lack MGF1 hash alg");
        return 0;
      }
      len = OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
      if (len >= sizeof(ctx->mdname)) {
        log_error("hash algorithm name too long");
        return 0;
      }
      len = OPENSSL_strlcpy(ctx->mgf1_mdname, mgf1mdname,
                            sizeof(ctx->mgf1_mdname));
      if (len >= sizeof(ctx->mgf1_mdname)) {
        log_error("MGF1 hash alg name too long");
        return 0;
      }
      ctx->saltlen = min_saltlen;

      // call rsa_setup_mgf1_md before rsa_setuip_md to avoid duplication
      return vcrypto_rsa_setup_mgf1_md(ctx, mgf1mdname, ctx->propq) &&
             vcrypto_rsa_setup_md(ctx, mdname, ctx->propq) &&
             vcrypto_rsa_check_parameters(ctx, min_saltlen);
    }
  } break;
  default:
    log_error("invalid flag in ctx->rsa");
    return 0;
  }

  if (!vcrypto_rsa_sign_set_ctx_params(ctx, params)) {
    log_error("failed to set sign ctx params");
    return 0;
  }
  return 1;
}

static int vcrypto_rsa_sinit(void *vsctx, void *vrsa,
                             const OSSL_PARAM params[]) {
  log_trace("enter vcrypto_rsa_sinit");
  return vcrypto_rsa_sign_verify_init(vsctx, vrsa, params, EVP_PKEY_OP_SIGN);
}

static int vcrypto_rsa_vinit(void *vsctx, void *vrsa,
                             const OSSL_PARAM params[]) {
  log_trace("enter vcrypto_rsa_vinit");
  return vcrypto_rsa_sign_verify_init(vsctx, vrsa, params, EVP_PKEY_OP_VERIFY);
}

static int vcrypto_rsa_sign(void *vsctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize, const unsigned char *tbs,
                            size_t tbslen) {
  log_trace("enter %s", __func__);
  int ret = 0;
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;

  // 1. status check
  if (!ctx || !sig || !siglen || !tbs) {
    log_error("null ptr in passed in params");
    return 0;
  }

  // 2.create session
  if (!ctx->ctx_status_session_created) {
    ctx->session_data->key_data = VC_RSA_to_rsa_data(ctx->rsa);
    // BUG: fe create_sess should be able to accept all kinds of struct
    if (!vcrypto_fe_protocol_create_sess(ctx->session_data)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    log_trace("vcrypto_fe_protocol_create_sess success");
    ctx->ctx_status_session_created = 1;
  }

  // 3. data prepare
  if (tbslen > RSA_MAX_KEY_SIZE_BYTES) {
    log_error("inlen: %d > RSA_MAX_KEY_SIZE_BYTES: %d", tbslen,
              RSA_MAX_KEY_SIZE_BYTES);
    return 0;
  }
  struct rte_mbuf *msg_mbuf = NULL;
  struct rte_mbuf *sig_mbuf = NULL;
  struct rte_crypto_op *op = NULL;

  // 3.1 msg(to be signed)
  msg_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!msg_mbuf ||
      rte_pktmbuf_append(msg_mbuf, RSA_MAX_KEY_SIZE_BYTES) == NULL) {
    log_error("msg_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *msg_ptr = rte_pktmbuf_mtod(msg_mbuf, uint8_t *);
  memcpy(msg_ptr, tbs, tbslen);
  // 3.2 sig buffer
  sig_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!sig_mbuf ||
      rte_pktmbuf_append(sig_mbuf, RSA_MAX_KEY_SIZE_BYTES) == NULL) {
    log_error("sig_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *sig_ptr = rte_pktmbuf_mtod(sig_mbuf, uint8_t *);

  // 4. crypto op alloc
  op = rte_crypto_op_alloc(crypto_op_mempool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    log_error("crypto op alloc failed");
    goto cleanup;
  }

  // 5. fill in op
  rte_crypto_op_attach_asym_session(op, ctx->session_data->sess);
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_SIGN;
  op->asym->rsa.message.data = msg_ptr;
  op->asym->rsa.message.length = tbslen;
  op->asym->rsa.sign.data = sig_ptr;
  op->asym->rsa.sign.length = RSA_MAX_KEY_SIZE_BYTES;

  // 6. send to daemon
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    log_error("enqueue backend the crypto op failed");
    goto cleanup;
  }

  // 7. wait for response
  log_trace("waiting for response ...");
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
  if (sigsize < RSA_MAX_KEY_SIZE_BYTES) {
    log_error("sigsize: %zu < RSA_MAX_KEY_SIZE_BYTES: %d", sigsize,
              RSA_MAX_KEY_SIZE_BYTES);
    goto cleanup;
  }
  memcpy(sig, completed_op->asym->rsa.sign.data, RSA_MAX_KEY_SIZE_BYTES);
  *siglen = RSA_MAX_KEY_SIZE_BYTES;
  ret = 1;

cleanup:
  if (msg_mbuf)
    rte_pktmbuf_free(msg_mbuf);
  if (sig_mbuf)
    rte_pktmbuf_free(sig_mbuf);
  if (op)
    rte_crypto_op_free(op);
  return ret;
}

static int vcrypto_rsa_verify(void *vsctx, const unsigned char *sig,
                              size_t siglen, const unsigned char *tbs,
                              size_t tbslen) {
  log_trace("enter %s", __func__);
  int ret = 0;
  vcrypto_rsa_sign_ctx *ctx = (vcrypto_rsa_sign_ctx *)vsctx;

  // 1. status check
  if (!ctx || !sig || !siglen || !tbs) {
    log_error("null ptr in passed in params");
    return 0;
  }

  // 2.create session
  if (!ctx->ctx_status_session_created) {
    ctx->session_data->key_data = VC_RSA_to_rsa_data(ctx->rsa);
    // BUG: fe create_sess should be able to accept all kinds of struct
    if (!vcrypto_fe_protocol_create_sess(ctx->session_data)) {
      log_error("failed to create session in frontend");
      return 0;
    }
    log_trace("vcrypto_fe_protocol_create_sess success");
    ctx->ctx_status_session_created = 1;
  }

  // 3. data prepare
  if (tbslen > RSA_MAX_KEY_SIZE_BYTES) {
    log_error("inlen: %d > RSA_MAX_KEY_SIZE_BYTES: %d", tbslen,
              RSA_MAX_KEY_SIZE_BYTES);
    return 0;
  }
  struct rte_mbuf *msg_mbuf = NULL;
  struct rte_mbuf *sig_mbuf = NULL;
  struct rte_crypto_op *op = NULL;

  // 3.1 msg(to be verified)
  msg_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!msg_mbuf ||
      rte_pktmbuf_append(msg_mbuf, RSA_MAX_KEY_SIZE_BYTES) == NULL) {
    log_error("msg_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *msg_ptr = rte_pktmbuf_mtod(msg_mbuf, uint8_t *);
  memcpy(msg_ptr, tbs, tbslen);
  // 3.2 sig buffer
  sig_mbuf = rte_pktmbuf_alloc(pktmbuf_mempool);
  if (!sig_mbuf ||
      rte_pktmbuf_append(sig_mbuf, RSA_MAX_KEY_SIZE_BYTES) == NULL) {
    log_error("sig_mbuf alloc failed");
    goto cleanup;
  }
  uint8_t *sig_ptr = rte_pktmbuf_mtod(sig_mbuf, uint8_t *);
  memcpy(sig_ptr, sig, siglen);

  // 4. crypto op alloc
  op = rte_crypto_op_alloc(crypto_op_mempool, RTE_CRYPTO_OP_TYPE_ASYMMETRIC);
  if (!op) {
    log_error("crypto op alloc failed");
    goto cleanup;
  }

  // 5. fill in op
  rte_crypto_op_attach_asym_session(op, ctx->session_data->sess);
  op->asym->rsa.op_type = RTE_CRYPTO_ASYM_OP_VERIFY;
  op->asym->rsa.message.data = msg_ptr;
  op->asym->rsa.message.length = tbslen;
  op->asym->rsa.sign.data = sig_ptr;
  op->asym->rsa.sign.length = RSA_MAX_KEY_SIZE_BYTES;

  // 6. send to daemon
  if (rte_ring_enqueue(tx_ring, op) != 0) {
    log_error("enqueue backend the crypto op failed");
    goto cleanup;
  }

  // 7. wait for response
  log_trace("waiting for response ...");
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
    log_warn("crypto operation for verify is not SUCCESS");
    goto cleanup;
  } else {
    log_trace("completed_op's status is SUCCESS");
  }

  ret = 1;

cleanup:
  if (msg_mbuf)
    rte_pktmbuf_free(msg_mbuf);
  if (sig_mbuf)
    rte_pktmbuf_free(sig_mbuf);
  if (op)
    rte_crypto_op_free(op);
  return ret;
}

const OSSL_DISPATCH vcrypto_rsa_signature_functions[] = {
    {OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))vcrypto_rsa_sign_newctx},
    {OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))vcrypto_rsa_sign_freectx},
    {OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))vcrypto_rsa_sinit},
    {OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))vcrypto_rsa_vinit},
    {OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))vcrypto_rsa_sign},
    {OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))vcrypto_rsa_verify},
    // {OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
    //  (void (*)(void))vcrypto_rsa_digest_sinit},
    // {OSSL_FUNC_SIGNATURE_DIGEST_SIGN, (void (*)(void))vcrypto_rsa_digest_sign},
    // {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
    //  (void (*)(void))vcrypto_rsa_digest_vinit},
    // {OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
    //  (void (*)(void))vcrypto_rsa_digest_verify},
    {OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_sign_set_ctx_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_sign_settable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_sign_get_ctx_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
     (void (*)(void))vcrypto_rsa_gettable_ctx_params},
    {OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
     (void (*)(void))vcrypto_rsa_get_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
     (void (*)(void))vcrypto_rsa_gettable_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
     (void (*)(void))vcrypto_rsa_set_ctx_md_params},
    {OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
     (void (*)(void))vcrypto_rsa_settable_ctx_md_params},
};

#include <ctype.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/safestack.h>
#include <openssl/types.h>

#include <log.h>

#include "provider.h"
#include "rsa.h"
#include "rsa_keymgmt_utils.h"

static const char *vcrypto_rsa_mp_factor_names[] = {
    OSSL_PKEY_PARAM_RSA_FACTOR1, OSSL_PKEY_PARAM_RSA_FACTOR2, NULL};

static const char *vcrypto_rsa_mp_exp_names[] = {
    OSSL_PKEY_PARAM_RSA_EXPONENT1,
    OSSL_PKEY_PARAM_RSA_EXPONENT2,
    NULL,
};

static const char *vcrypto_rsa_mp_coeff_names[] = {
    OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
    NULL,
};

static const OSSL_ITEM vcrypto_oaeppss_name_nid_map[] = {
    {NID_sha1, OSSL_DIGEST_NAME_SHA1},
    {NID_sha224, OSSL_DIGEST_NAME_SHA2_224},
    {NID_sha256, OSSL_DIGEST_NAME_SHA2_256},
    {NID_sha384, OSSL_DIGEST_NAME_SHA2_384},
    {NID_sha512, OSSL_DIGEST_NAME_SHA2_512},
    {NID_sha512_224, OSSL_DIGEST_NAME_SHA2_512_224},
    {NID_sha512_256, OSSL_DIGEST_NAME_SHA2_512_256},
};

static int vcrypto_rsa_pss_params_30_set_defaults(
    VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params) {
  if (!rsa_pss_params) {
    log_error("null ptr in rsa_pss_params");
    return 0;
  }
  *rsa_pss_params = default_RSASSA_PSS_params;
  return 1;
}

static const char *vcrypto_rsa_mgf_nid2name(int mgf) {
  if (mgf == NID_mgf1)
    return SN_mgf1;
  log_error("unsupported mgf nid %d", mgf);
  return NULL;
}

static int
vcrypto_rsa_pss_params_30_set_hashalg(VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params,
                                      int maskgenhashalg_nid) {
  if (!rsa_pss_params) {
    log_error("null ptr rsa_pss_params");
    return 0;
  }
  rsa_pss_params->mask_gen.hash_algorithm_nid = maskgenhashalg_nid;
  return 1;
}

static int vcrypto_rsa_pss_params_30_set_maskgenhashalg(
    VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params, int maskgenhashalg_nid) {
  if (!rsa_pss_params) {
    log_error("null ptr rsa_pss_params");
    return 0;
  }
  rsa_pss_params->mask_gen.algorithm_nid = maskgenhashalg_nid;
  return 1;
}

static int
vcrypto_rsa_pss_params_30_set_saltlen(VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params,
                                      int saltlen) {
  if (!rsa_pss_params) {
    log_error("null ptr rsa_pss_params");
    return 0;
  }
  rsa_pss_params->salt_len = saltlen;
  return 1;
}

static int vcrypto_rsa_pss_params_30_maskgenalg(
    const VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params) {
  if (!rsa_pss_params)
    return default_RSASSA_PSS_params.mask_gen.algorithm_nid;
  return rsa_pss_params->mask_gen.algorithm_nid;
}

static int md_is_a(const void *md, const char *name) {
  return EVP_MD_is_a(md, name);
}

static int meth2nid(const void *meth,
                    int (*meth_is_a)(const void *meth, const char *name),
                    const OSSL_ITEM *items, size_t items_n) {
  if (meth) {
    for (size_t i = 0; i < items_n; i++) {
      if (meth_is_a(meth, items[i].ptr)) {
        return (int)items[i].id;
      }
    }
  }
  log_error("failed to lookup passed in method's nid");
  return NID_undef;
}

int vcrypto_rsa_oaeppss_md2nid(const EVP_MD *md) {
  return meth2nid(md, md_is_a, vcrypto_oaeppss_name_nid_map,
                  OSSL_NELEM(vcrypto_oaeppss_name_nid_map));
}

/// @brief Parse and set RSA-PSS parameters from OSSL_PARAM array.
///
/// This function extracts and sets the RSA-PSS parameters (hash algorithm, mask
/// generation function, mask generation hash algorithm, and salt length) from
/// the provided OSSL_PARAM array. If any parameter is present, default PSS
/// values are set first and then overridden by the provided values.
///
/// @param[out] pss_params   Pointer to VCRYPTO_RSA_PSS_PARAMS_30 structure to
/// populate.
/// @param[in,out] defaults_set Pointer to an int flag indicating if defaults
/// have been set (set to 1 if defaults are set).
/// @param[in] params        Array of OSSL_PARAM containing possible PSS
/// parameters.
/// @param[in] libctx        OpenSSL library context for fetching digest
/// algorithms.
///
/// @return 1 on success, 0 on failure.

static int
vcrypto_rsa_pss_params_30_fromdata(VCRYPTO_RSA_PSS_PARAMS_30 *pss_params,
                                   int *default_set, const OSSL_PARAM params[],
                                   OSSL_LIB_CTX *libctx) {
  const OSSL_PARAM *param_md, *param_mgf, *param_mgf1md, *param_saltlen;
  const OSSL_PARAM *param_propq;
  const char *propq = NULL;
  EVP_MD *md = NULL, *mgf1md = NULL;
  int saltlen;
  int ret = 0;

  if (pss_params == NULL) {
    log_error("null ptr in pss_params");
    return 0;
  }
  param_propq =
      OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST_PROPS);
  param_md = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_DIGEST);
  param_mgf = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MASKGENFUNC);
  param_mgf1md =
      OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_MGF1_DIGEST);
  param_saltlen =
      OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PSS_SALTLEN);

  if (param_propq != NULL) {
    if (param_propq->data_type == OSSL_PARAM_UTF8_STRING)
      propq = param_propq->data;
  }

  // if any of the param above got, we have at least some restrictions
  // start by setting default values, and let each param override by provided
  if (!*default_set && (param_md != NULL || param_mgf != NULL ||
                        param_mgf1md != NULL || param_saltlen != NULL)) {
    if (!vcrypto_rsa_pss_params_30_set_defaults(pss_params)) {
      log_error("failed to set default pss_params");
      return 0;
    }
    *default_set = 1;
  }

  if (param_mgf) {
    int default_maskgenalg_nid = vcrypto_rsa_pss_params_30_maskgenalg(NULL);
    const char *mgfname = NULL;
    if (param_mgf->data_type == OSSL_PARAM_UTF8_STRING) {
      mgfname = param_mgf->data;
    } else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mgfname)) {
      log_error("failed to get mgfname");
      return 0;
    }

    if (OPENSSL_strcasecmp(param_mgf->data, vcrypto_rsa_mgf_nid2name(
                                                default_maskgenalg_nid)) != 0) {
      log_error("mgf name compare failed!");
      return 0;
    }
  }

  // we are only intreseted in the NIDs that correspond to the MDs, so the
  // exact propquery is unimportant in the EVP_MD_fetch() calls below
  if (param_md) {
    const char *mdname = NULL;
    if (param_md->data_type == OSSL_PARAM_UTF8_STRING) {
      mdname = param_md->data;
    } else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mdname)) {
      log_error("failed to get mdname from mgf");
      goto err;
    }

    if ((md = EVP_MD_fetch(libctx, mdname, propq)) == NULL ||
        !vcrypto_rsa_pss_params_30_set_hashalg(
            pss_params, vcrypto_rsa_oaeppss_md2nid(md))) {
      log_error("failed to fetch md or set hashalg");
      goto err;
    }
  }

  if (param_mgf1md) {
    const char *mgf1mdname = NULL;
    if (param_mgf1md->data_type == OSSL_PARAM_UTF8_STRING) {
      mgf1mdname = param_mgf1md->data;
    } else if (!OSSL_PARAM_get_utf8_ptr(param_mgf, &mgf1mdname)) {
      log_error("failed to get mgf1mdname from mgf");
      goto err;
    }

    if ((mgf1md = EVP_MD_fetch(libctx, mgf1mdname, propq)) == NULL ||
        !vcrypto_rsa_pss_params_30_set_maskgenhashalg(
            pss_params, vcrypto_rsa_oaeppss_md2nid(mgf1md))) {
      log_error("failed to get mgf1md or set hashgenalg");
      goto err;
    }
  }

  if (param_saltlen) {
    if (!OSSL_PARAM_get_int(param_saltlen, &saltlen) ||
        !vcrypto_rsa_pss_params_30_set_saltlen(pss_params, saltlen)) {
      log_error("failed to get salt len or set salt len for pss_params");
      goto err;
    }
  }

  ret = 1;

err:
  EVP_MD_free(md);
  EVP_MD_free(mgf1md);
  return ret;
}

/// @brief Validates and parses RSA-PSS parameters from an OSSL_PARAM array.
///
/// This function extracts and sets RSA-PSS parameters (such as hash algorithm,
/// mask generation function, mask generation hash algorithm, and salt length)
/// from the provided OSSL_PARAM array into the given VCRYPTO_RSA_PSS_PARAMS_30
/// structure. It ensures that PSS parameters are only accepted for PSS-type RSA
/// keys, and applies default restrictions if necessary.
///
/// @param pss_params    Pointer to VCRYPTO_RSA_PSS_PARAMS_30 structure to
/// populate.
/// @param defaults_set  Pointer to an int flag indicating if defaults have been
/// set (set to 1 if defaults are set).
/// @param params        Array of OSSL_PARAM containing possible PSS parameters.
/// @param rsa_type      Integer indicating the RSA key type (e.g.,
/// RSA_FLAG_TYPE_RSASSAPSS).
/// @param libctx        OpenSSL library context for fetching digest algorithms.
///
/// @return 1 on success, 0 on failure.

int vcrypto_pss_params_fromdata(VCRYPTO_RSA_PSS_PARAMS_30 *pss_params,
                                int *default_sets, const OSSL_PARAM *params,
                                int rsa_type, OSSL_LIB_CTX *libctx) {
  if (!vcrypto_rsa_pss_params_30_fromdata(pss_params, default_sets, params,
                                          libctx)) {
    log_error("failed to set for pss_params");
    return 0;
  }

  // if is not a PSS type rsa, then this func should not be called
  if (rsa_type != RSA_FLAG_TYPE_RSASSAPSS &&
      !vcrypto_rsa_pss_params_30_is_unrestricted(pss_params)) {
    log_error("cur rsa is not PSS type, this func should not be called");
    return 0;
  }
  return 1;
}

DEFINE_STACK_OF(BIGNUM)
DEFINE_SPECIAL_STACK_OF_CONST(BIGNUM_const, BIGNUM)

/// @brief Allocates and initializes a new VCRYPTO_RSA structure with a given
/// OpenSSL library context.
///
/// This function creates a new VCRYPTO_RSA structure, initializes its fields,
/// sets up the reference count and locking, assigns the provided OpenSSL
/// library context, and sets the default RSA method and flags. If
/// initialization of the RSA method fails, it cleans up and returns NULL.
///
/// @param libctx  Pointer to the OpenSSL library context to associate with the
/// new QAT_RSA structure.
///
/// @return Pointer to the newly allocated QAT_RSA structure, or NULL on
/// failure.
VCRYPTO_RSA *vcrypto_rsa_new_with_ctx(OSSL_LIB_CTX *libctx) {
  VCRYPTO_RSA *ret = OPENSSL_zalloc(sizeof(*ret));
  if (!ret) {
    log_error("failed to alloc for VCRYPTO_RSA");
    return NULL;
  }

  // FIXME: lock

  if (!vcrypto_new_ref(&ret->referecens, 1)) {
    log_error("failed to new ref for VCRYPTO_RSA");
    OPENSSL_free(ret);
    return NULL;
  }

  ret->libctx = libctx;
  // FIXME: meth
  return ret;
}

OSSL_LIB_CTX *vcrypto_rsa_get0_libctx(VCRYPTO_RSA *r) { return r->libctx; }

static const BIGNUM *vcrypto_rsa_get0_p(const RSA *r) { return r->p; }

static const BIGNUM *vcrypto_rsa_get0_q(const RSA *r) { return r->q; }

static const BIGNUM *vcrypto_rsa_get0_dmp1(const RSA *r) { return r->dmp1; }

static const BIGNUM *vcrypto_rsa_get0_dmq1(const RSA *r) { return r->dmq1; }

static const BIGNUM *vcrypto_rsa_get0_iqmp(const RSA *r) { return r->iqmp; }

/// @brief Collects all CRT-related RSA parameters into separate stacks.
///
/// This function pushes the prime factors (p, q), exponents (dmp1, dmq1),
/// and coefficient (iqmp) from the given VCRYPTO_RSA structure into the
/// provided stacks. If the key does not have CRT parameters (i.e., p is NULL),
/// the function returns 1 without modifying the stacks.
///
/// @param r        Pointer to the VCRYPTO_RSA structure.
/// @param primes   Stack to receive the prime factors (p, q).
/// @param exps     Stack to receive the exponents (dmp1, dmq1).
/// @param coeffs   Stack to receive the coefficient (iqmp).
///
/// @return 1 on success, 0 on failure.
static int vcrypto_rsa_get0_all_params(VCRYPTO_RSA *r,
                                       STACK_OF(BIGNUM_const) * primes,
                                       STACK_OF(BIGNUM_const) * exps,
                                       STACK_OF(BIGNUM_const) * coeffs) {
  if (r == NULL) {
    log_error("null ptr in VCRYPTO_RSA");
    return 0;
  }

  // if |p| is NULL, there are no crt params
  if (vcrypto_rsa_get0_p(r) == NULL) {
    return 1;
  }

  sk_BIGNUM_const_push(primes, vcrypto_rsa_get0_p(r));
  sk_BIGNUM_const_push(primes, vcrypto_rsa_get0_q(r));
  sk_BIGNUM_const_push(exps, vcrypto_rsa_get0_dmp1(r));
  sk_BIGNUM_const_push(exps, vcrypto_rsa_get0_dmq1(r));
  sk_BIGNUM_const_push(coeffs, vcrypto_rsa_get0_iqmp(r));
  return 1;
}

/// @brief Derives and sets the CRT parameters (dmp1, dmq1, iqmp) for the given
/// QAT_RSA structure.
///
/// This function computes the CRT parameters based on the prime factors (p, q)
/// and the private exponent (d) of the RSA key. It uses a BN_CTX for efficient
/// BIGNUM operations and sets the computed parameters in the QAT_RSA structure.
/// If any required parameter is missing or an error occurs during computation,
/// it returns 0.
///
/// @param rsa Pointer to the QAT_RSA structure containing the RSA key.
/// @param ctx Pointer to a BN_CTX for BIGNUM operations.
///
/// @return 1 on success, 0 on failure.
static int derive_and_set_crt_params(VCRYPTO_RSA *rsa, BN_CTX *ctx) {
  BIGNUM *p1 = NULL, *q1 = NULL, *dmp1 = NULL, *dmq1 = NULL, *iqmp = NULL;
  int ret = 0;
  if (rsa == NULL || rsa->p == NULL || rsa->q == NULL || rsa->d == NULL) {
    log_error("null ptr in VCRYPTO_RSA");
    return 0;
  }
  BN_CTX_start(ctx);
  // allocate temporary BIGNUMS
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  dmp1 = BN_CTX_get(ctx);
  dmq1 = BN_CTX_get(ctx);
  iqmp = BN_CTX_get(ctx);
  if (iqmp == NULL) {
    log_error("failed to alloc for temp BIGNUMS");
    goto err;
  }

  // compute p-1 and q-1
  if (!BN_sub(p1, rsa->p, BN_value_one()) ||
      !BN_sub(q1, rsa->q, BN_value_one())) {
    log_error("failed to compute p-1 and q-1");
    goto err;
  }

  // Compute dP = d mod (p-1)
  if (!BN_mod(dmp1, rsa->d, p1, ctx)) {
    log_error("failed to compute dp = d mod(p-1)");
    goto err;
  }

  // Compute dQ = d mod (q-1)
  if (!BN_mod(dmq1, rsa->d, q1, ctx)) {
    log_error("failed to compute dQ = d mod(q-1)");
    goto err;
  }

  // Compute qInv = q^(-1) mod p
  if (!BN_mod_inverse(iqmp, rsa->q, rsa->p, ctx)) {
    log_error("failed to compute qInv = q^(-1) mod p");
    goto err;
  }

  // Set the CRT parameters in the RSA structure
  if (!vcrypto_rsa_set0_crt_params(rsa, dmp1, dmq1, iqmp)) {
    log_error("failed to set crt params");
    goto err;
  }

  // ownership of dmp1, dmq1, and iqmp is transferred to rsa
  dmp1 = dmq1 = iqmp = NULL;
  ret = 1;

err:
  BN_CTX_end(ctx);
  return ret;
}

/// @brief Imports an RSA private key from an OSSL_PARAM array into a QAT_RSA
/// structure.
///
/// This function extracts the RSA key components (modulus n, public exponent e,
/// private exponent d, and optionally prime factors p and q) from the provided
/// OSSL_PARAM array and sets them in the given VCRYPTO_RSA structure. If
/// private key components are included, it also derives and sets the CRT
/// parameters (dmp1, dmq1, iqmp) required for efficient RSA operations.
///
/// @param rsa             Pointer to the VCRYPTO_RSA structure to populate.
/// @param params          Array of OSSL_PARAM containing the key components.
/// @param include_private Nonzero if private key components (p, q, d, etc.)
/// should be imported.
///
/// @return 1 on success, 0 on failure.
int import_rsa_private_key(VCRYPTO_RSA *rsa, const OSSL_PARAM *params,
                           int include_private) {
  const OSSL_PARAM *param_n, *param_e, *param_d, *param_p, *param_q;
  BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL, *dmp1 = NULL,
         *dmq1 = NULL, *iqmp = NULL;
  int is_private = 0;
  BN_CTX *ctx = NULL;
  if (!rsa || !params) {
    log_error("null ptr in rsa or params");
    return 0;
  }

  // extract modules(n), public exponent(e) and private exponent(d)
  param_n = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N);
  param_e = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E);
  param_d = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D);
  if (param_n == NULL || param_e == NULL || param_d == NULL) {
    log_error("failed to get n/e/d from params");
    goto err;
  }

  if (include_private) {
    // extract prime factors (p,q)
    ctx = BN_CTX_new_ex(rsa->libctx);
    if (!ctx) {
      log_error("failed to new ctx");
      goto err;
    }
    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR1);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR2);
    if (param_p && param_q) {
      if (!OSSL_PARAM_get_BN(param_p, &p) || !OSSL_PARAM_get_BN(param_q, &q)) {
        log_error("invalid param p/q");
        goto err;
      }
    }
  }

  if (!vcrypto_rsa_set0_key(rsa, n, e, d)) {
    log_error("failed to set key");
    goto err;
  }

  // extract crt params(dmp1, dmq1, iqmp)
  is_private = (d != NULL);
  // n, e, d's ownership transfered to rsa
  n = e = d = NULL;

  if (is_private) {
    if (p && q) {
      if (!vcrypto_rsa_set0_factors(rsa, p, q)) {
        log_error("failed to set factors");
        goto err;
      }
      // p and q's ownership transfered to rsa
      p = q = NULL;

      if (!derive_and_set_crt_params(rsa, ctx)) {
        log_error("failed to derive and set crt params");
        goto err;
      }
    }
  }
  return 1;

err:
  BN_free(n);
  BN_free(e);
  BN_free(d);
  BN_free(p);
  BN_free(q);
  BN_free(dmp1);
  BN_free(dmq1);
  BN_free(iqmp);
  BN_CTX_free(ctx);
  return 0;
}

int vcrypto_rsa_pss_params_30_copy(VCRYPTO_RSA_PSS_PARAMS_30 *to,
                                   const VCRYPTO_RSA_PSS_PARAMS_30 *from) {
  memcpy(to, from, sizeof(*to));
  return 1;
}

/// @brief Sets a BIGNUM value into an OSSL_PARAM_BLD builder or OSSL_PARAM
/// array.
///
/// This helper function sets the specified BIGNUM value for a given parameter
/// key, either by pushing it into an OSSL_PARAM_BLD builder (if provided) or by
/// locating the parameter in an OSSL_PARAM array and setting its value. If
/// neither is provided, the function returns success.
///
/// @param bld    Optional OSSL_PARAM_BLD builder (may be NULL).
/// @param p      Optional OSSL_PARAM array to populate (may be NULL).
/// @param key    Name of the parameter to set.
/// @param bn     Pointer to the BIGNUM value to set.
///
/// @return 1 on success, 0 on failure.
static int vcrypto_param_build_set_bn(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                      const char *key, const BIGNUM *bn) {
  if (bld != NULL)
    return OSSL_PARAM_BLD_push_BN(bld, key, bn);

  p = OSSL_PARAM_locate(p, key);
  if (p != NULL)
    return OSSL_PARAM_set_BN(p, bn) > 0;
  return 1;
}

/// @brief Sets multiple BIGNUM values into an OSSL_PARAM_BLD or OSSL_PARAM
/// array.
///
/// This helper function iterates over a stack of BIGNUMs and a corresponding
/// array of parameter names, and sets each BIGNUM value into the provided
/// OSSL_PARAM_BLD builder or OSSL_PARAM array. If a builder is provided, values
/// are pushed into it; otherwise, the function locates the parameter in the
/// array and sets its value.
///
/// @param bld    Optional OSSL_PARAM_BLD builder (may be NULL).
/// @param params Optional OSSL_PARAM array to populate (may be NULL).
/// @param names  Array of parameter names (NULL-terminated).
/// @param stk    Stack of BIGNUM_const values to set.
///
/// @return 1 on success, 0 on failure.
static int vcrypto_param_build_set_multi_key_bn(OSSL_PARAM_BLD *bld,
                                                OSSL_PARAM *params,
                                                const char *names[],
                                                STACK_OF(BIGNUM_const) * stk) {
  int sz = sk_BIGNUM_const_num(stk);
  OSSL_PARAM *p;
  const BIGNUM *bn;

  if (bld) {
    for (int i = 0; i < sz && names[i] != NULL; i++) {
      bn = sk_BIGNUM_const_value(stk, i);
      if (bn != NULL && !OSSL_PARAM_BLD_push_BN(bld, names[i], bn)) {
        log_error("failed to push bn, name: %s", names[i]);
        return 0;
      }
    }
    return 1;
  }

  for (int i = 0; i < sz && names[i] != NULL; i++) {
    bn = sk_BIGNUM_const_value(stk, i);
    p = OSSL_PARAM_locate(params, names[i]);
    if (p != NULL && bn != NULL) {
      if (!OSSL_PARAM_set_BN(p, bn)) {
        log_error("failed to set bn");
        return 0;
      }
    }
  }
  return 1;
}

/// @brief Serializes a QAT_RSA key into an OSSL_PARAM array or builder.
///
/// This function exports the components of the given QAT_RSA structure (modulus
/// n, public exponent e, private exponent d, and optionally CRT parameters and
/// factors) into an OSSL_PARAM_BLD or OSSL_PARAM array for use with OpenSSL key
/// export or parameter passing. If include_private is nonzero, private key
/// components are included.
///
/// @param rsa            Pointer to the QAT_RSA structure to serialize.
/// @param bld            Optional OSSL_PARAM_BLD builder (may be NULL).
/// @param params         Optional OSSL_PARAM array to populate (may be NULL).
/// @param include_private Nonzero to include private key components.
///
/// @return 1 on success, 0 on failure.
int vcrypto_rsa_todata(VCRYPTO_RSA *rsa, OSSL_PARAM_BLD *bld,
                       OSSL_PARAM *params, int include_private) {
  int ret = 0;
  const BIGNUM *rsa_d = NULL, *rsa_n = NULL, *rsa_e = NULL;
  STACK_OF(BIGNUM_const) *factors = sk_BIGNUM_const_new_null();
  STACK_OF(BIGNUM_const) *exps = sk_BIGNUM_const_new_null();
  STACK_OF(BIGNUM_const) *coeffs = sk_BIGNUM_const_new_null();
  if (!rsa || !factors || !exps || !coeffs) {
    log_error("null ptr in rsa/factors/exps/coeffs");
    goto cleanup;
  }
  rsa_n = vcrypto_rsa_get0_n(rsa);
  rsa_e = vcrypto_rsa_get0_e(rsa);
  rsa_d = vcrypto_rsa_get0_d(rsa);
  vcrypto_rsa_get0_all_params(rsa, factors, exps, coeffs);

  if (!vcrypto_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_N, rsa_n) ||
      !vcrypto_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_E, rsa_e)) {
    log_error("failed to set rsa_n/e");
    goto cleanup;
  }

  // chceck private key data
  if (include_private && rsa_d != NULL) {
    if (!vcrypto_param_build_set_bn(bld, params, OSSL_PKEY_PARAM_RSA_D,
                                    rsa_d) ||
        !vcrypto_param_build_set_multi_key_bn(
            bld, params, vcrypto_rsa_mp_factor_names, factors) ||
        !vcrypto_param_build_set_multi_key_bn(bld, params,
                                              vcrypto_rsa_mp_exp_names, exps) ||
        !vcrypto_param_build_set_multi_key_bn(
            bld, params, vcrypto_rsa_mp_coeff_names, coeffs)) {
      log_error("failed to set bn");
      goto cleanup;
    }
  }
  ret = 1;

cleanup:
  sk_BIGNUM_const_free(factors);
  sk_BIGNUM_const_free(exps);
  sk_BIGNUM_const_free(coeffs);
  return ret;
}

/// @brief Callback function for RSA key generation progress reporting.
///
/// This function is called during RSA key generation to report progress to the
/// caller. It constructs an OSSL_PARAM array with the current potential prime
/// and iteration count, and invokes the user-provided callback with these
/// parameters.
///
/// @param p     Current potential prime value.
/// @param n     Current iteration count.
/// @param cb    Pointer to the BN_GENCB callback structure.
///
/// @return The return value of the user-provided callback.

int vcrypto_rsa_gencb(int p, int n, BN_GENCB *cb) {
  VCRYPTO_RSA_GEN_CTX *gctx = BN_GENCB_get_arg(cb);
  OSSL_PARAM params[] = {OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END};
  params[0] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_POTENTIAL, &p);
  params[1] = OSSL_PARAM_construct_int(OSSL_GEN_PARAM_ITERATION, &n);
  return gctx->cb(params, gctx->cbarg);
}

static const OSSL_PARAM rsa_key_types[] = {RSA_KEY_TYPES() OSSL_PARAM_END};

const OSSL_PARAM *vcrypto_rsa_imexport_types(int selection) {
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    return rsa_key_types;
  log_error("no match in supported key types with passed in selection=%d",
            selection);
  return NULL;
}

static int vcrypto_param_build_set_utf8_string(OSSL_PARAM_BLD *bld,
                                               OSSL_PARAM *p, const char *key,
                                               const char *buf) {
  if (bld)
    return OSSL_PARAM_BLD_push_utf8_string(bld, key, buf, 0);

  p = OSSL_PARAM_locate(p, key);
  if (p)
    return OSSL_PARAM_set_utf8_string(p, buf);
  return 1;
}

static int vcrypto_param_build_set_int(OSSL_PARAM_BLD *bld, OSSL_PARAM *p,
                                       const char *key, int num) {
  if (bld)
    return OSSL_PARAM_BLD_push_int(bld, key, num);

  p = OSSL_PARAM_locate(p, key);
  if (p)
    return OSSL_PARAM_set_int(p, num);
  return 1;
}

/// @brief Serializes vcrypto RSA-PSS parameters into an OSSL_PARAM array or
/// builder.
///
/// This function exports the provided VCRYPTO_RSA_PSS_PARAMS_30 structure into an
/// OSSL_PARAM_BLD or OSSL_PARAM array, suitable for OpenSSL key export or
/// parameter passing. Only parameters that differ from the default are
/// included. At least one PSS-related parameter (saltlen) is always exported to
/// ensure the key is not seen as unrestricted.
///
/// @param pss         Pointer to the VCRYPTO_RSA_PSS_PARAMS_30 structure to
/// serialize.
/// @param bld         Optional OSSL_PARAM_BLD builder (may be NULL).
/// @param params      Optional OSSL_PARAM array to populate (may be NULL).
///
/// @return 1 on success, 0 on failure.
int vcrypto_rsa_params_30_to_data(const VCRYPTO_RSA_PSS_PARAMS_30 *pss, OSSL_PARAM_BLD *bld, OSSL_PARAM *params) {
  if (!vcrypto_rsa_pss_params_30_is_unrestricted(pss)) {
    int hashalg_nid = vcrypto_rsa_pss_params_30_hashalg(pss);
    int maskgenalg_nid = vcrypto_rsa_pss_params_30_maskgenalg(pss);
    int maskgenhashalg_nid = vcrypto_rsa_pss_params_30_maskgenhashalg(pss);
    int saltlen = vcrypto_rsa_pss_params_30_saltlen(pss);
    int default_hashalg_nid = vcrypto_rsa_pss_params_30_hashalg(NULL);
    int default_maskgenalg_nid = vcrypto_rsa_pss_params_30_maskgenalg(NULL);
    int default_maskgenhashalg_nid = vcrypto_rsa_pss_params_30_maskgenhashalg(NULL);
    int default_saltlen_nid = vcrypto_rsa_pss_params_30_saltlen(NULL);
    const char* mdname = (hashalg_nid == default_hashalg_nid ? NULL : vcrypto_rsa_oaeppss_nid2name(hashalg_nid));
    const char* mgfname = (maskgenalg_nid == default_maskgenalg_nid? NULL : vcrypto_rsa_oaeppss_nid2name(maskgenalg_nid));
    const char* mgf1mdname = (maskgenhashalg_nid == default_maskgenhashalg_nid ? NULL : vcrypto_rsa_oaeppss_nid2name(maskgenhashalg_nid));
    const char* key_md = OSSL_PKEY_PARAM_RSA_DIGEST;
    const char* key_mgf = OSSL_PKEY_PARAM_RSA_MASKGENFUNC;
    const char* key_mgf1_md = OSSL_PKEY_PARAM_RSA_MGF1_DIGEST;
    const char* key_saltlen = OSSL_PKEY_PARAM_RSA_PSS_SALTLEN;

    // to ensure that the key isn't seen as unrestricted by the recipient
    // make sure that at least one PSS-related parameter is passed,
    // even if it has a default value; saltlen
    if ((mdname != NULL && !vcrypto_param_build_set_utf8_string(bld, params, key_md, mdname))
  || (mgfname != NULL && !vcrypto_param_build_set_utf8_string(bld, params, key_mgf, mgfname))
  || (mgf1mdname != NULL && !vcrypto_param_build_set_utf8_string(bld, params, key_mgf1_md, mgf1mdname)) || !vcrypto_param_build_set_int(bld, params, key_saltlen, saltlen)) {
      log_error("failed to set mdname/mgfname/mgf1mdname/saltlen");
      return 0;
    }
  }
  return 1;
}

/// @brief Generates a new RSA keypair in software and populates a VCRYPTO_RSA structure.
///
/// This function generates a new RSA keypair of the specified bit length, using the provided
/// public exponent (or 65537 if efixed is NULL), and fills in all key components in the
/// given VCRYPTO_RSA structure, including CRT parameters. The function ensures the generated
/// key meets minimum security requirements and uses secure memory for private values.
///
/// @param rsa      Pointer to the VCRYPTO_RSA structure to populate.
/// @param nbits    Number of bits for the modulus (must be >= 2048).
/// @param efixed   Optional public exponent (BIGNUM), or NULL to use 65537.
/// @param cb       Optional BN_GENCB callback for progress reporting.
///
/// @return 1 on success, 0 on failure.
int rsa_generate_swkey(VCRYPTO_RSA *rsa, int nbits, BIGNUM *efixed, BN_GENCB *cb) {
  int ret = 0;
  BN_CTX *ctx = NULL;
  BIGNUM *e = NULL, *p1 = NULL, *q1 = NULL, *lcm = NULL;

  ctx = BN_CTX_new();
  if (!ctx) {
    log_error("failed to create BN_CTX");
    return 0;
  }

  BN_CTX_start(ctx);
  p1 = BN_CTX_get(ctx);
  q1 = BN_CTX_get(ctx);
  lcm = BN_CTX_get(ctx);
  if (lcm == NULL) {
    log_error("failed to get p1/q1/lcm");
    goto cleanup;
  }

  if (efixed == NULL) {
    e = BN_new();
    if (e == NULL || !BN_set_word(e, 65537)) {
      log_error("failed to new bn, or set word 'e' to 65537");
      goto cleanup;
    }
  } else {
    e = (BIGNUM *)efixed;
  }

  rsa->p = BN_secure_new();
  rsa->q = BN_secure_new();
  if (rsa->p == NULL || rsa->q == NULL) {
    log_error("failed to new for rsa->p/q");
    goto cleanup;
  }

  if (!BN_generate_prime_ex(rsa->p, nbits / 2, 0, NULL, NULL, cb) || !BN_generate_prime_ex(rsa->q, nbits / 2, 0, NULL, NULL, cb)) {
    log_error("failed to generate prime for rsa->p/q");
    goto cleanup;
  }

  if (BN_cmp(rsa->p, rsa->q) < 0) {
    BIGNUM *tmp = rsa->p;
    rsa->p = rsa->q;
    rsa->q = tmp;
  }

  if (!BN_sub(p1, rsa->p, BN_value_one()) || !BN_sub(q1, rsa->q, BN_value_one())) {
    log_error("failed to p/q sub");
    goto cleanup;
  }

  // allocate a temp BIGNUM for GCD
  BIGNUM *gcd = BN_CTX_get(ctx);
  if (gcd == NULL) {
    log_error("failed to alloc for gcd");
    goto cleanup;
  }

  // compute GCD(p1, q1) and store in gcd
  if (!BN_gcd(gcd, p1, q1, ctx)) {
    log_error("failed to compute gcd");
    goto cleanup;
  }
  if (!BN_mul(lcm, p1, q1, ctx) || !BN_div(lcm, NULL, lcm, gcd, ctx)) {
    log_error("failed to mul or div");
    goto cleanup;
  }

  rsa->e = BN_dup(e);
  if (rsa->e == NULL) {
    log_error("rsa->e duplicate failed");
    goto cleanup;
  }

  rsa->d = BN_secure_new();
  if (rsa->d == NULL || !BN_mod_inverse(rsa->d, e, lcm, ctx)) {
    log_error("failed to new rsa->d or inverse d");
    goto cleanup;
  }

  if (BN_num_bits(rsa->d) <= (nbits >> 1)) {
    log_error("rsa->d <= nbits/2");
    goto cleanup;
  }

  rsa->n = BN_new();
  if (rsa->n == NULL || !BN_mul(rsa->n, rsa->p, rsa->q, ctx)) {
    log_error("failed to new rsa->n or mul into n");
    goto cleanup;
  }

  rsa->dmp1 = BN_secure_new();
  rsa->dmq1 = BN_secure_new();
  rsa->iqmp = BN_secure_new();
  if (rsa->dmp1 == NULL || rsa->dmq1 == NULL || rsa->iqmp == NULL) {
    log_error("failed to new rsa->dmp1/dmq1/iqmp");
    goto cleanup;
  }

  if (!BN_mod(rsa->dmp1, rsa->d, p1, ctx) || !BN_mod(rsa->dmq1, rsa->d, q1, ctx) || !BN_mod_inverse(rsa->iqmp, rsa->q, rsa->p, ctx)) {
    log_error("failed to mod into dmp1/dmq1, or failed to mod inverse into rsa->iqmp");
    goto cleanup;
  }

  ret = 1;

cleanup:
  if (ret != 1) {
    BN_free(rsa->n);
    BN_free(rsa->d);
    BN_free(rsa->dmp1);
    BN_free(rsa->dmq1);
    BN_free(rsa->iqmp);
    BN_free(rsa->p);
    BN_free(rsa->q);
  }
  if (efixed == NULL)  BN_free(e);
  BN_CTX_end(ctx);
  BN_CTX_free(ctx);
  return ret;
}

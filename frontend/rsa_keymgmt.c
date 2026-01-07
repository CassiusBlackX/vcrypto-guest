#include "log.h"
#include "provider.h"
#include "rsa.h"
#include <stdlib.h>
#include <string.h>

#include <generic/rte_pause.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>
#include <rte_mbuf.h>
#include <rte_mbuf_core.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include "rsa.h"
#include "rsa_keymgmt_utils.h"

#define VCRYPTO_RSA_POSSIBLE_SELECTIONS                                        \
  (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS)
#define RSA_MIN_MODULES_BITS 512
#define RSA_DEFAULT_MD "SHA256"
#define vcrypto_rsa_gen_basic                                                  \
  OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),                           \
      OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),                     \
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0)

#define vcrypto_rsa_gen_pss                                                    \
  OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),                 \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),       \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),        \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),        \
      OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL)

static OSSL_FUNC_keymgmt_new_fn vcrypto_rsa_keymgmt_new;
static OSSL_FUNC_keymgmt_free_fn vcrypto_rsa_keymgmt_free;
static OSSL_FUNC_keymgmt_has_fn vcrypto_rsa_keymgmt_has;
static OSSL_FUNC_keymgmt_import_fn vcrypto_rsa_keymgmt_import;
static OSSL_FUNC_keymgmt_import_types_fn vcrypto_rsa_keymgmt_import_types;
static OSSL_FUNC_keymgmt_gen_init_fn vcrypto_rsa_keymgmt_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn vcrypto_rsa_keymgmt_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn
    vcrypto_rsa_keymgmt_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn vcrypto_rsa_keymgmt_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn vcrypto_rsa_keymgmt_gen_cleanup;
static OSSL_FUNC_keymgmt_load_fn vcrypto_rsa_keymgmt_load;
static OSSL_FUNC_keymgmt_get_params_fn vcrypto_rsa_keymgmt_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn vcrypto_rsa_keymgmt_gettable_params;
static OSSL_FUNC_keymgmt_export_fn vcrypto_rsa_keymgmt_export;
static OSSL_FUNC_keymgmt_export_types_fn vcrypto_rsa_keymgmt_export_types;
static OSSL_FUNC_keymgmt_match_fn vcrypto_rsa_keymgmt_match;

#define qat_rsa_gen_basic                                                      \
  OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_BITS, NULL),                           \
      OSSL_PARAM_size_t(OSSL_PKEY_PARAM_RSA_PRIMES, NULL),                     \
      OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0)

#define qat_rsa_gen_pss                                                        \
  OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST, NULL, 0),                 \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_DIGEST_PROPS, NULL, 0),       \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MASKGENFUNC, NULL, 0),        \
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_RSA_MGF1_DIGEST, NULL, 0),        \
      OSSL_PARAM_int(OSSL_PKEY_PARAM_RSA_PSS_SALTLEN, NULL)

/**
 * @brief Allocates and initializes a new VCRYPTO_RSA structure for RSA key
 * management.
 *
 * This function creates a new VCRYPTO_RSA structure using the provided provider
 * context, initializes its fields, and sets the key type flags for a standard
 * RSA key. It returns a pointer to the new VCRYPTO_RSA object, or NULL on
 * failure.
 *
 * @param provctx  Pointer to the provider context.
 *
 * @return Pointer to the newly allocated VCRYPTO_RSA structure, or NULL on
 * failure.
 */
static void *vcrypto_rsa_keymgmt_new(void *provctx) {
  OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
  VCRYPTO_RSA *rsa = vcrypto_rsa_new_with_ctx(libctx);
  if (rsa != NULL) {
    vcrypto_rsa_clear_flags(rsa, RSA_FLAG_TYPE_MASK);
    vcrypto_rsa_set_flags(rsa, RSA_FLAG_TYPE_RSA);
  }
  return rsa;
}

/**
 * @brief Frees and cleans up a VCRYPTO_RSA key structure.
 *
 * This function releases all resources associated with a VCRYPTO_RSA structure,
 * including any allocated memory and internal key components. It should be
 * called when the key data is no longer needed to prevent memory leaks.
 *
 * @param keydata  Pointer to the VCRYPTO_RSA structure to free.
 */
static void vcrypto_rsa_keymgmt_free(void *keydata) {
  vcrypto_rsa_free(keydata);
}

/**
 * @brief Checks if the VCRYPTO_RSA key structure contains the requested key
 * components.
 *
 * This function verifies the presence of required key components in the given
 * VCRYPTO_RSA structure based on the specified selection mask. It checks for
 * the existence of modulus (n), public exponent (e), and private exponent (d)
 * as needed for keypair, public key, and private key selections. Returns 1 if
 * all requested components are present, 0 otherwise.
 *
 * @param keydata    Pointer to the VCRYPTO_RSA structure to check.
 * @param selection  Bitmask specifying which key components to check for.
 *
 * @return 1 if all requested components are present, 0 otherwise.
 */
static int vcrypto_rsa_keymgmt_has(const void *keydata, int selection) {
  log_debug("enter %s", __func__);
  const VCRYPTO_RSA *rsa = keydata;
  int ok = 1;
  if (rsa == NULL)
    return 0;
  if ((selection & VCRYPTO_RSA_POSSIBLE_SELECTIONS) == 0)
    return 1;
  // OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS are always available even if empty
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
    ok = ok && (vcrypto_rsa_get0_n(rsa) != NULL);
  if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
    ok = ok && (vcrypto_rsa_get0_e(rsa) != NULL);
  if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
    ok = ok && (vcrypto_rsa_get0_d(rsa) != NULL);
  return ok;
}

/**
 * @brief Imports RSA key components and parameters from an OSSL_PARAM array
 * into a VCRYPTO_RSA structure.
 *
 * This function populates the given VCRYPTO_RSA structure with key components
 * and parameters provided in the OSSL_PARAM array, according to the specified
 * selection mask. It handles both standard and PSS-specific parameters, and can
 * import public and private key data. The function ensures that the imported
 * parameters are consistent with the key type and applies any necessary
 * defaults for PSS keys.
 *
 * @param keydata    Pointer to the VCRYPTO_RSA structure to populate.
 * @param selection  Bitmask specifying which key components and parameters to
 * import.
 * @param params     Array of OSSL_PARAM containing the key data and parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int vcrypto_rsa_keymgmt_import(void *keydata, int selection,
                                      const OSSL_PARAM params[]) {
  VCRYPTO_RSA *rsa = keydata;
  int rsa_type;
  int ok = 1;
  int pss_defaults_set = 0;

  if (rsa == NULL)
    return 0;
  if ((selection & VCRYPTO_RSA_POSSIBLE_SELECTIONS) == 0)
    return 0;
  rsa_type = vcrypto_rsa_test_flags(rsa, RSA_FLAG_TYPE_MASK);

  if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0) {
    ok = ok && vcrypto_pss_params_fromdata(vcrypto_rsa_get0_pss_params_30(rsa),
                                           &pss_defaults_set, params, rsa_type,
                                           vcrypto_rsa_get0_libctx(rsa));
  }
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
    int include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    ok = ok && import_rsa_private_key(rsa, params, include_private);
  }
  log_debug("rsa import complete");
  return ok;
}

/**
 * @brief Retrieves the list of importable parameter types for vcrypto RSA key
 * management.
 *
 * This function returns an array of OSSL_PARAM descriptors that specify which
 * key components and parameters can be imported for the given selection mask.
 * It is used by OpenSSL to determine which parameters are supported for import
 * operations.
 *
 * @param selection  Bitmask specifying which key components and parameters are
 * being imported.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if none are
 * available.
 */
static const OSSL_PARAM *vcrypto_rsa_keymgmt_import_types(int selection) {
  log_debug("%s", __func__);
  return vcrypto_rsa_imexport_types(selection);
}

/**
 * @brief Sets RSA key generation parameters from an OSSL_PARAM array.
 *
 * This function parses and applies key generation parameters from the provided
 * OSSL_PARAM array to the VCRYPTO_RSA_GEN_CTX context. It handles modulus size,
 * number of primes, public exponent, and (for RSA-PSS keys) PSS-specific
 * parameters. The function validates parameter values and ensures minimum
 * security requirements are met.
 *
 * @param genctx  Pointer to the QAT_RSA_GEN_CTX context to configure.
 * @param params  Array of OSSL_PARAM containing the generation parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int vcrypto_rsa_keymgmt_gen_set_params(void *genctx,
                                              const OSSL_PARAM params[]) {
  log_debug("%s", __func__);
  VCRYPTO_RSA_GEN_CTX *gctx = genctx;
  const OSSL_PARAM *p;
  if (params == NULL)
    return 1;
  if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_BITS)) != NULL) {
    if (!OSSL_PARAM_get_size_t(p, &gctx->nbits))
      return 0;
    if (gctx->nbits < RSA_MIN_MODULES_BITS) {
      log_error("gctx->nbis is cmaller than RSA_MIN_MODULES_BITS: %d",
                RSA_MIN_MODULES_BITS);
      return 0;
    }
  }

  if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_PRIMES)) !=
          NULL &&
      !OSSL_PARAM_get_size_t(p, &gctx->primes))
    return 0;
  if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E)) != NULL &&
      !OSSL_PARAM_get_BN(p, &gctx->pub_exp))
    return 0;
  /* only attempt to get PSS parameters when generating an rsa-pss key */
  if (gctx->rsa_type == RSA_FLAG_TYPE_RSASSAPSS &&
      !vcrypto_pss_params_fromdata(&gctx->pss_params, &gctx->pss_defaults_set,
                                   params, gctx->rsa_type, gctx->libctx))
    return 0;
  return 1;
}

/**
 * @brief Initializes a VCRYPTO_RSA_GEN_CTX structure for RSA or RSA-PSS key
 * generation.
 *
 * This function allocates and sets up a VCRYPTO_RSA_GEN_CTX context for RSA key
 * generation, including setting the library context, default modulus size,
 * number of primes, public exponent, and RSA key type (standard or PSS). It
 * also parses and applies any additional key generation parameters provided in
 * the OSSL_PARAM array.
 *
 * @param provctx    Pointer to the provider context.
 * @param selection  Bitmask specifying which key components to generate.
 * @param rsa_type   Integer indicating the RSA key type (e.g.,
 * RSA_FLAG_TYPE_RSA or RSA_FLAG_TYPE_RSASSAPSS).
 * @param params     Array of OSSL_PARAM containing key generation parameters.
 *
 * @return Pointer to the newly allocated QAT_RSA_GEN_CTX structure, or NULL on
 * failure.
 */
static void *vcrypto_gen_init(void *provctx, int selection, int rsa_type,
                              const OSSL_PARAM params[]) {
  log_debug("%s", __func__);
  OSSL_LIB_CTX *libctx = prov_libctx_of(provctx);
  VCRYPTO_RSA_GEN_CTX *gctx = NULL;
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
    return NULL;
  if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
    gctx->libctx = libctx;
    if ((gctx->pub_exp = BN_new()) == NULL ||
        !BN_set_word(gctx->pub_exp, RSA_F4)) {
      log_error("failed to BN_new or BN_set_word");
      goto err;
    }
    gctx->nbits = 2048;
    gctx->primes = RSA_DEFAULT_PRIME_NUM;
    gctx->rsa_type = rsa_type;
  } else {
    goto err;
  }
  if (!vcrypto_rsa_keymgmt_gen_set_params(gctx, params)) {
    log_error("failed to set gen params");
    goto err;
  }
  return gctx;
err:
  if (gctx != NULL)
    BN_free(gctx->pub_exp);
  OPENSSL_free(gctx);
  return NULL;
}

static void *vcrypto_rsa_keymgmt_gen_init(void *provctx, int selection,
                                          const OSSL_PARAM params[]) {
  return vcrypto_gen_init(provctx, selection, RSA_FLAG_TYPE_RSA, params);
}

static const OSSL_PARAM *
vcrypto_rsa_keymgmt_gen_settable_params(ossl_unused void *genctx,
                                        ossl_unused void *provctx) {
  static OSSL_PARAM settable[] = {vcrypto_rsa_gen_basic, OSSL_PARAM_END};
  return settable;
}

/**
 * @brief Generates a new RSA or RSA-PSS key using the specified generation
 * context.
 *
 * This function creates a new VCRYPTO_RSA key according to the parameters set
 * in the VCRYPTO_RSA_GEN_CTX context, including modulus size, public exponent,
 * number of primes, and (for PSS keys) PSS parameters. It performs all
 * necessary checks for key type and parameter restrictions, generates the key
 * using software routines, and copies any PSS parameters to the resulting key
 * structure.
 *
 * @param genctx    Pointer to the QAT_RSA_GEN_CTX context containing generation
 * parameters.
 * @param osslcb    Optional OpenSSL callback for progress reporting (may be
 * NULL).
 * @param cbarg     Optional argument for the callback (may be NULL).
 *
 * @return Pointer to the newly generated QAT_RSA key, or NULL on failure.
 */
static void *vcrypto_rsa_keymgmt_gen(void *genctx, OSSL_CALLBACK *osslcb,
                                     void *cbarg) {
  log_debug("%s", __func__);
  VCRYPTO_RSA_GEN_CTX *gctx = genctx;
  VCRYPTO_RSA *rsa = NULL, *rsa_tmp = NULL;
  BN_GENCB *gencb = NULL;
  if (gctx == NULL)
    return NULL;
  switch (gctx->rsa_type) {
  case RSA_FLAG_TYPE_RSA:
    /* for plain rsa keys, PSS parameters must not be set */
    if (vcrypto_rsa_pss_params_30_is_unrestricted(&gctx->pss_params))
      goto err;
    break;
  case RSA_FLAG_TYPE_RSASSAPSS:
    /*
     * for plain rsa-pss keys, pss parameters may be set but don't have to, so
     * not check
     */
    break;
  default:
    return NULL;
  }
  if ((rsa_tmp = vcrypto_rsa_new_with_ctx(gctx->libctx)) == NULL) {
    log_error("failed to new rsa with ctx");
    return NULL;
  }
  gctx->cb = osslcb;
  gctx->cbarg = cbarg;
  gencb = BN_GENCB_new();
  if (gencb != NULL)
    BN_GENCB_set(gencb, vcrypto_rsa_gencb, genctx);
  if (!rsa_generate_swkey(rsa_tmp, (int)gctx->nbits, gctx->pub_exp, gencb)) {
    log_error("failed to generate sw key");
    goto err;
  }
  vcrypto_rsa_clear_flags(rsa_tmp, RSA_FLAG_TYPE_MASK);
  vcrypto_rsa_set_flags(rsa_tmp, gctx->rsa_type);
  rsa = rsa_tmp;
  rsa_tmp = NULL;

err:
  BN_GENCB_free(gencb);
  vcrypto_rsa_free(rsa_tmp);
  return NULL;
}

/**
 * @brief Frees and cleans up a VCRYPTO_RSA_GEN_CTX key generation context.
 *
 * This function releases all resources associated with a VCRYPTO_RSA_GEN_CTX
 * structure, including the public exponent BIGNUM and any allocated memory. It
 * should be called when the key generation context is no longer needed to
 * prevent memory leaks.
 *
 * @param genctx  Pointer to the VCRYPTO_RSA_GEN_CTX structure to free.
 */
static void vcrypto_rsa_keymgmt_gen_cleanup(void *genctx) {
  VCRYPTO_RSA_GEN_CTX *gctx = genctx;
  if (gctx == NULL)
    return;
  BN_clear_free(gctx->pub_exp);
  OPENSSL_free(gctx);
}

/**
 * @brief Loads a VCRYPTO_RSA key object from a reference pointer.
 *
 * This function retrieves a VCRYPTO_RSA key object from a reference pointer,
 * validating the reference size and ensuring the key type matches the expected
 * RSA type (standard or PSS). If the reference is valid, the function detaches
 * the object from the reference pointer and returns it; otherwise, it returns
 * NULL.
 *
 * @param reference     Pointer to the reference containing the VCRYPTO_RSA
 * object address.
 * @param reference_sz  Size of the reference (should match sizeof(VCRYPTO_RSA
 * *)).
 * @param rsa_type      Expected RSA key type (e.g., RSA_FLAG_TYPE_RSA or
 * RSA_FLAG_TYPE_RSASSAPSS).
 *
 * @return Pointer to the loaded VCRYPTO_RSA object, or NULL on failure.
 */
static void *common_load(const void *reference, size_t reference_sz,
                         int rsa_type) {
  VCRYPTO_RSA *rsa = NULL;
  if (reference_sz == sizeof(VCRYPTO_RSA *)) {
    rsa = *(VCRYPTO_RSA **)reference;
    if (vcrypto_rsa_test_flags(rsa, RSA_FLAG_TYPE_MASK) != rsa_type)
      return NULL;
    *(VCRYPTO_RSA **)reference = NULL;
    return rsa;
  }
  return NULL;
}

static void *vcrypto_rsa_keymgmt_load(const void *reference,
                                      size_t reference_sz) {
  return common_load(reference, reference_sz, RSA_FLAG_TYPE_RSA);
}

/**
 * @brief Retrieves key parameters from a VCRYPTO_RSA structure and populates an
 * OSSL_PARAM array.
 *
 * This function fills the provided OSSL_PARAM array with key parameters from
 * the given VCRYPTO_RSA structure, such as modulus size, security bits, maximum
 * size, and default or mandatory digest. For RSA-PSS keys, it also exports PSS
 * parameters if present. The function ensures that only valid and available
 * parameters are set in the output array.
 *
 * @param key      Pointer to the VCRYPTO_RSA structure.
 * @param params   Array of OSSL_PARAM to be populated with key parameters.
 *
 * @return 1 on success, 0 on failure.
 */
static int vcrypto_rsa_keymgmt_get_params(void *key, OSSL_PARAM params[]) {
  log_debug("%s", __func__);
  VCRYPTO_RSA *rsa = key;
  const VCRYPTO_RSA_PSS_PARAMS_30 *pss_params =
      vcrypto_rsa_get0_pss_params_30(rsa);
  int rsa_type = vcrypto_rsa_test_flags(rsa, RSA_FLAG_TYPE_MASK);
  OSSL_PARAM *p;
  int empty = vcrypto_rsa_get0_n(rsa) == NULL;
  int ret = 0;

  log_debug("n is empty: %d", empty);
  if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL) {
    if (empty || !OSSL_PARAM_set_int(p, vcrypto_rsa_bits(rsa)))
      return 0;
  }
  // FIXME: deprecated function used here
  if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL &&
      (empty || !OSSL_PARAM_set_int(p, RSA_security_bits(rsa))))
    return 0;
  if ((p = OSSL_PARAM_locate(p, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL &&
      (empty || !OSSL_PARAM_set_int(p, vcrypto_rsa_size(rsa))))
    return 0;
  /*
   * for restricted RSA-PSS keys, we ignore the default digest request
   * with RSA_OAEP keys, this may need to be amended
   */
  if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL &&
      (rsa_type != RSA_FLAG_TYPE_RSASSAPSS ||
       vcrypto_rsa_pss_params_30_is_unrestricted(pss_params))) {
    if (!OSSL_PARAM_set_utf8_string(p, RSA_DEFAULT_MD))
      return 0;
  }
  /*
   * for non-rsa-pss keys, ignore the mandatory digest request
   * with rsa-OAEP keys, this may need to be amended
   */
  if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST)) !=
          NULL &&
      rsa_type == RSA_FLAG_TYPE_RSASSAPSS &&
      !vcrypto_rsa_pss_params_30_is_unrestricted(pss_params)) {
    const char *mdname = vcrypto_rsa_oaeppss_nid2name(
        vcrypto_rsa_pss_params_30_hashalg(pss_params));
    if (mdname == NULL || !OSSL_PARAM_set_utf8_string(p, mdname))
      return 0;
  }
  log_debug("%s completed", __func__);
  ret = (rsa_type != RSA_FLAG_TYPE_RSASSAPSS ||
         vcrypto_rsa_pss_params_30_todata(pss_params, NULL, params)) &&
        vcrypto_rsa_todata(rsa, NULL, params, 1);
  return ret;
}

static const OSSL_PARAM *vcrypto_rsa_keymgmt_gettable_params(void *provctx) {
  static const OSSL_PARAM rsa_params[] = {
      OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
      OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
      OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
      RSA_KEY_TYPES() OSSL_PARAM_END};
  return rsa_params;
}

/**
 * @brief Exports RSA key components and parameters from a VCRYPTO_RSA
 * structure.
 *
 * This function serializes the key components and parameters of the given
 * VCRYPTO_RSA structure into an OSSL_PARAM array using an OSSL_PARAM_BLD
 * builder, according to the specified selection mask. It handles both standard
 * and PSS-specific parameters, and can export public and private key data. The
 * resulting parameters are passed to the provided callback.
 *
 * @param keydata        Pointer to the VCRYPTO_RSA structure to export.
 * @param selection      Bitmask specifying which key components and parameters
 * to export.
 * @param param_callback Callback function to receive the exported parameters.
 * @param cbarg          Argument to pass to the callback function.
 *
 * @return 1 on success, 0 on failure.
 */
static int vcrypto_rsa_keymgmt_export(void *keydata, int selection,
                                      OSSL_CALLBACK *param_callback,
                                      void *cbarg) {
  log_debug("%s", __func__);
  VCRYPTO_RSA *rsa = keydata;
  const VCRYPTO_RSA_PSS_PARAMS_30 *pss_params =
      vcrypto_rsa_get0_pss_params_30(rsa);
  OSSL_PARAM_BLD *tmpl;
  OSSL_PARAM *params = NULL;
  int ok = 1;

  if (rsa == NULL) {
    log_error("rsa is NULL");
    return 0;
  }
  if ((selection & VCRYPTO_RSA_POSSIBLE_SELECTIONS) == 0) {
    log_error("selection incorrent");
    return 0;
  }
  tmpl = OSSL_PARAM_BLD_new();
  if (tmpl == NULL) {
    log_error("failed to bld new");
    return 0;
  }

  if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
    ok = ok && (vcrypto_rsa_pss_params_30_is_unrestricted(pss_params) ||
                vcrypto_rsa_pss_params_30_todata(pss_params, tmpl, NULL));
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
    int include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    ok = ok && vcrypto_rsa_todata(rsa, tmpl, NULL, include_private);
  }
  if (!ok || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
    ok = 0;
    goto err;
  }
  ok = param_callback(params, cbarg);
  OSSL_PARAM_free(params);
err:
  OSSL_PARAM_BLD_free(tmpl);
  return ok;
}

/**
 * @brief Retrieves the list of exportable parameter types for VCRYPTO RSA key
 * management.
 *
 * This function returns an array of OSSL_PARAM descriptors that specify which
 * key components and parameters can be exported for the given selection mask.
 * It is used by OpenSSL to determine which parameters are supported for export
 * operations.
 *
 * @param selection  Bitmask specifying which key components and parameters are
 * being exported.
 *
 * @return Pointer to an array of OSSL_PARAM descriptors, or NULL if none are
 * available.
 */
static const OSSL_PARAM *vcrypto_rsa_keymgmt_export_types(int selection) {
  return vcrypto_rsa_imexport_types(selection);
}

/**
 * @brief Compares two VCRYPTO_RSA key structures for equality based on the
 * selection mask.
 *
 * This function checks whether the two provided VCRYPTO_RSA key structures
 * match according to the specified selection mask. It compares the public
 * exponent, modulus, and private exponent as required by the selection. The
 * function returns 1 if all selected components match, and 0 otherwise.
 *
 * @param keydata1   Pointer to the first VCRYPTO_RSA structure.
 * @param keydata2   Pointer to the second VCRYPTO_RSA structure.
 * @param selection  Bitmask specifying which key components to compare.
 *
 * @return 1 if all selected components match, 0 otherwise.
 */
static int vcrypto_rsa_keymgmt_match(const void* keydata1, const void* keydata2, int selection) {
  log_debug("%s", __func__);
  const VCRYPTO_RSA *rsa1 = keydata1;
  const VCRYPTO_RSA *rsa2 = keydata2;
  int ok = 1;

  // there is always an |e|
  ok = ok && BN_cmp(vcrypto_rsa_get0_e(rsa1), vcrypto_rsa_get0_e(rsa2)) == 0;
  if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
    int key_checked = 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
      const BIGNUM *p1 = vcrypto_rsa_get0_n(rsa1);
      const BIGNUM *p2 = vcrypto_rsa_get0_n(rsa2);
      if (p1 != NULL && p2 != NULL) {
        ok = ok && BN_cmp(p1, p2) == 0;
        key_checked = 1;
      }
    }
    if (!key_checked && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
      const BIGNUM *p1 = vcrypto_rsa_get0_d(rsa1);
      const BIGNUM *p2 = vcrypto_rsa_get0_d(rsa2);
      if (p1 != NULL && p2 != NULL) {
        ok = ok && BN_cmp(p1, p2) == 0;
        key_checked = 1;
      }
    }
    ok = ok && key_checked;
  }
  return ok;
}

const OSSL_DISPATCH vcrypto_rsa_keymgmt_functions[] = {
{OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))vcrypto_rsa_keymgmt_new},
{OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))vcrypto_rsa_keymgmt_free},
{OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))vcrypto_rsa_keymgmt_has},
{OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))vcrypto_rsa_keymgmt_import},
{OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))vcrypto_rsa_keymgmt_import_types},
{OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))vcrypto_rsa_keymgmt_gen_init},
{OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))vcrypto_rsa_keymgmt_gen_set_params},
{OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (void (*)(void))vcrypto_rsa_keymgmt_gen_settable_params},
{OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))vcrypto_rsa_keymgmt_gen},
{OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))vcrypto_rsa_keymgmt_gen_cleanup},
{OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))vcrypto_rsa_keymgmt_load},
{OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))vcrypto_rsa_keymgmt_get_params},
{OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))vcrypto_rsa_keymgmt_gettable_params},
{OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))vcrypto_rsa_keymgmt_export},
{OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))vcrypto_rsa_keymgmt_export_types},
{OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))vcrypto_rsa_keymgmt_match},
};

#ifndef VCRYPTO_GUEST_FE_RSA_KEYMGMT_UTILS_H
#define VCRYPTO_GUEST_FE_RSA_KEYMGMT_UTILS_H

#include "rsa.h"
#include <openssl/types.h>
#define RSA_KEY_TYPES() \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_N, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_E, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_D, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR1, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_FACTOR2, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT1, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_EXPONENT2, NULL, 0), \
OSSL_PARAM_BN(OSSL_PKEY_PARAM_RSA_COEFFICIENT1, NULL, 0), 

VCRYPTO_RSA *vcrypto_rsa_new_with_ctx(OSSL_LIB_CTX *libctx);
int vcrypto_pss_params_fromdata(VCRYPTO_RSA_PSS_PARAMS_30 *pss_params, int *default_sets, const OSSL_PARAM params[], int rsa_type, OSSL_LIB_CTX *libctx);
int vcrypto_rsa_todata(VCRYPTO_RSA *rsa, OSSL_PARAM_BLD *bld, OSSL_PARAM params[], int include_private);
int vcrypto_rsa_pss_params_30_todata(const VCRYPTO_RSA_PSS_PARAMS_30 *pss, OSSL_PARAM_BLD *bld, OSSL_PARAM params[]);
int vcrypto_rsa_pss_params_30_hashalg(const VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params);
const char* vcrypto_rsa_oaeppss_nid2name(int md);
int vcrypto_rsa_oaeppss_md2nid(const EVP_MD *md);
int vcrypto_rsa_pss_params_30_copy(VCRYPTO_RSA_PSS_PARAMS_30 *to, const VCRYPTO_RSA_PSS_PARAMS_30* from);
int import_rsa_private_key(VCRYPTO_RSA* rsa, const OSSL_PARAM params[], int include_private);
OSSL_LIB_CTX* vcrypto_rsa_get0_libctx(VCRYPTO_RSA* r);
VCRYPTO_RSA_PSS_PARAMS_30* vcrypto_rsa_get0_pss_params_30(VCRYPTO_RSA *r);
const char *nid2name(int meth, const OSSL_ITEM* items, size_t items_n);
int vcrypto_rsa_pss_params_30_is_unrestricted(const VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params);
int vcrypto_rsa_gen_set_params(void *genctx, const OSSL_PARAM params[]);
int vcrypto_rsa_gencb(int p, int n, BN_GENCB *cb);
int vcrypto_rsa_pss_params_30_maskgenhashalg(const VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params);
int vcrypto_rsa_pss_params_30_saltlen(const VCRYPTO_RSA_PSS_PARAMS_30 *rsa_pss_params);
int vcrypto_rsa_set0_factors(VCRYPTO_RSA* r, BIGNUM *p, BIGNUM *q);
int vcrypto_rsa_set0_crt_params(VCRYPTO_RSA* r, BIGNUM *dmp1, BIGNUM *dmq1, BIGNUM*iqmp);
const OSSL_PARAM  *vcrypto_rsa_imexport_types(int selection);
int rsa_generate_swkey(VCRYPTO_RSA* rsa, int nbits, BIGNUM *efixed, BN_GENCB *cb);

#endif // VCRYPTO_GUEST_FE_RSA_KEYMGMT_UTILS_H

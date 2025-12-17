#ifndef VCRYPTO_GUEST_FE_RSA_ENC_DEC_H
#define VCRYPTO_GUEST_FE_RSA_ENC_DEC_H

#include <stdint.h>

#include <openssl/core.h>
#include <openssl/provider.h>
#include <openssl/types.h>

#include <rte_crypto_asym.h>

#include "provider.h"

#define RSA_MAX_KEY_SIZE_BITS 2048
#define RSA_MAX_KEY_SIZE_BYTES (RSA_MAX_KEY_SIZE_BITS / 8)

typedef struct rsa_st {
  /* dummy value to adhere to OpenSSL RSA structure guidelines */
  int dummy_zero;

  OSSL_LIB_CTX *libctx;
  int32_t version;
  /* Key RSA params */
  BIGNUM *n;
  BIGNUM *e;
  BIGNUM *d;
  BIGNUM *p;
  BIGNUM *q;
  BIGNUM *dmp1;
  BIGNUM *dmq1;
  BIGNUM *iqmp;

  VCRYPTO_REF_COUNT referecens;
  int flags;
  int dirty_cnt;
} VCRYPTO_RSA;

typedef struct {
  uint8_t n[RSA_MAX_KEY_SIZE_BYTES];
  uint8_t e[RSA_MAX_KEY_SIZE_BYTES];
  uint8_t d[RSA_MAX_KEY_SIZE_BYTES];
  size_t e_len;
  uint64_t md5_val;
} rsa_data;

typedef struct vcrypto_rsa_ctx_st {
  OSSL_LIB_CTX *libctx;
  VCRYPTO_RSA *rsa;
  int pad_mode;
  int operation;
  /* OAEP message digest */
  EVP_MD *oaep_md;
  /* message digest for MGF1 */
  EVP_MD *mgf1_md;
  /* OEAP label */
  unsigned char *oaep_label;
  size_t oaep_labellen;
  /* TLS padding */
  unsigned int client_version;
  unsigned int alt_version;

  unsigned int ctx_status_inited : 1;
  unsigned int ctx_status_session_created : 1;

  rsa_data *key_data;
  struct rte_cryptodev_asym_session *sess;
} vcrypto_rsa_enc_dec_ctx;


int vcrypto_rsa_bits(const VCRYPTO_RSA *r);
int vcrypto_rsa_size(const VCRYPTO_RSA *r);
int vcrypto_rsa_up_ref(VCRYPTO_RSA *r);
void vcrypto_rsa_free(VCRYPTO_RSA *r);
int vcrypto_rsa_test_flags(const VCRYPTO_RSA *r, int flags);
void vcrypto_rsa_clear_flags(VCRYPTO_RSA *r, int flags);
void vcrypto_rsa_set_flags(VCRYPTO_RSA *r, int flags);
const BIGNUM *vcrypto_rsa_get0_n(const VCRYPTO_RSA *r);
const BIGNUM *vcrypto_rsa_get0_e(const VCRYPTO_RSA *r);
const BIGNUM *vcrypto_rsa_get0_d(const VCRYPTO_RSA *r);
int vcrypto_rsa_set0_factors(VCRYPTO_RSA *r, BIGNUM *p, BIGNUM *q);
int vcrypto_rsa_set0_crt_params(VCRYPTO_RSA *r, BIGNUM *dmp1, BIGNUM *dmq1,
                                BIGNUM *iqmp);
int vcrypto_rsa_set0_key(VCRYPTO_RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d);
rsa_data *VC_RSA_to_rsa_data(const VCRYPTO_RSA *r);

#endif // VCRYPTO_GUEST_FE_RSA_ENC_DEC_H

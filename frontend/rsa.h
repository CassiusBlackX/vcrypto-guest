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

typedef struct {
  int hash_algorithm_nid;
  struct  {
    int algorithm_nid;
    int hash_algorithm_nid;
  } mask_gen;
  int salt_len;
  int trailer_field;
} VCRYPTO_RSA_PSS_PARAMS_30;

extern const VCRYPTO_RSA_PSS_PARAMS_30 default_RSASSA_PSS_params;

typedef struct vcrypto_rsa_gen_ctx {
  OSSL_LIB_CTX *libctx;
  const char* propq;

  int rsa_type;

  size_t nbits;
  BIGNUM *pub_exp;
  size_t primes;

  /* for PSS */
  VCRYPTO_RSA_PSS_PARAMS_30 pss_params;
  int pss_defaults_set;

  /* for generatino callback  */
  OSSL_CALLBACK *cb;
  void *cbarg;
} VCRYPTO_RSA_GEN_CTX;

typedef struct rsa_st {
  /* dummy value to adhere to OpenSSL RSA structure guidelines */
  int dummy_zero;

  OSSL_LIB_CTX *libctx;
  int32_t version;
  // FIXME: is meth necessary?
  // const RSA_METHOD *meth;

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

// TODO: it is recommended to use qt type of rsa_key_data instead of exp type
typedef struct {
  uint8_t n[RSA_MAX_KEY_SIZE_BYTES];
  uint8_t e[RSA_MAX_KEY_SIZE_BYTES];
  uint8_t d[RSA_MAX_KEY_SIZE_BYTES];
  size_t e_len;
  uint64_t md5_val;
} rsa_key_data;

typedef struct {
  rsa_key_data *key_data;
  struct rte_cryptodev_asym_session *sess;
} rsa_session_data;

typedef struct {
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

  rsa_session_data *session_data;
} vcrypto_rsa_enc_dec_ctx;

typedef struct {
  OSSL_LIB_CTX *libctx;
  char *propq;
  VCRYPTO_RSA *rsa;
  int operation;
  /* unused but retained to remain compatible with openssl */
  unsigned int flag_sigalg : 1;

  /*
   * flag to determine if the hash function can be changed (1) or not(0)
   * because it's dangerous to change during a DigestSign or DigestVerify
   * operation, this flag is cleared by their init function, and set again
   * by their final function
   */
  unsigned int flag_allow_md : 1;
  unsigned int mgf1_md_set : 1;

  unsigned int flag_allow_update : 1;
  unsigned int flag_allow_final : 1;
  unsigned int flag_allow_oneshot : 1;

  /* main digest  */ 
  EVP_MD *md;
  EVP_MD_CTX *mdctx;
  int mdnid;
  char mdname[50];  /* purely informational, useless */
  
  /* RSA padding mode */
  int pad_mode;
  /* message digest for MGF1 */
  EVP_MD *mgf1_md;
  int mgf1_mdnid;
  char mgf1_mdname[50];
  /* PSS salt length */
  int saltlen;
  /* minimum salt length or -1 if no PSS param restrictin */
  int min_saltlen;
  unsigned char *sig;
  size_t siglen;

  /* OAEP message digest */
  EVP_MD *oaep_md;
  /* OEAP label */
  unsigned char *oaep_label;
  size_t oaep_labellen;
  /* TLS padding */
  unsigned int client_version;
  unsigned int alt_version;

  unsigned int ctx_status_inited : 1;
  unsigned int ctx_status_session_created : 1;

  rsa_session_data *session_data;
} vcrypto_rsa_sign_ctx;

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
rsa_key_data *VC_RSA_to_rsa_data(const VCRYPTO_RSA *r);


#endif // VCRYPTO_GUEST_FE_RSA_ENC_DEC_H

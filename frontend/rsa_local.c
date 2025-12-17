#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/types.h>

#include <log.h>
#include <xxhash.h>

#include "provider.h"
#include "rsa.h"

int vcrypto_rsa_bits(const VCRYPTO_RSA *r) { return BN_num_bits(r->n); }

int vcrypto_rsa_size(const VCRYPTO_RSA *r) { return BN_num_bytes(r->n); }

int vcrypto_rsa_up_ref(VCRYPTO_RSA *r) {
  int i = 0;
  /* A refcount less than 2 indicates an unexpected state where the object
   * may not have been properly initialized or referenced. This check
   * ensures that the object is in a valid state before proceeding. */
  if (vcrypto_up_ref(&r->referecens, &i) <= 0) {
    log_error("failed to up refcnt");
    return 0;
  }

  if (i < 2) {
    log_error("refcnt error");
    return 0;
  }
  return i > 1 ? 1 : 0;
}

void vcrypto_rsa_free(VCRYPTO_RSA *r) {
  int i;
  if (r == NULL)
    return;

  vcrypto_down_ref(&r->referecens, &i);
  if (i > 0)
    return;
  if (i < 0) {
    log_warn("refcnt error");
    return;
  }

  BN_clear_free(r->n);
  BN_clear_free(r->e);
  BN_clear_free(r->d);
  BN_clear_free(r->p);
  BN_clear_free(r->q);
  BN_clear_free(r->dmp1);
  BN_clear_free(r->dmq1);
  BN_clear_free(r->iqmp);

  OPENSSL_free(r);
}

int vcrypto_rsa_test_flags(const VCRYPTO_RSA *r, int flags) {
  return r->flags & flags;
}

void vcrypto_rsa_clear_flags(VCRYPTO_RSA *r, int flags) { r->flags &= ~flags; }

void vcrypto_rsa_set_flags(VCRYPTO_RSA *r, int flags) { r->flags |= flags; }

const BIGNUM *vcrypto_rsa_get0_n(const VCRYPTO_RSA *r) { return r->n; }

const BIGNUM *vcrypto_rsa_get0_e(const VCRYPTO_RSA *r) { return r->e; }

const BIGNUM *vcrypto_rsa_get0_d(const VCRYPTO_RSA *r) { return r->d; }

int vcrypto_rsa_set0_factors(VCRYPTO_RSA *r, BIGNUM *p, BIGNUM *q) {
  /* If the fields p and q in r are NULL, the corresponding input
   * parameters MUST be non-NULL.
   */
  if ((r->p == NULL && p == NULL) || (r->q == NULL && q == NULL))
    return 0;

  if (p != NULL) {
    BN_clear_free(r->p);
    r->p = p;
    BN_set_flags(r->p, BN_FLG_CONSTTIME);
  }
  if (q != NULL) {
    BN_clear_free(r->q);
    r->q = q;
    BN_set_flags(r->q, BN_FLG_CONSTTIME);
  }
  r->dirty_cnt++;

  return 1;
}

int vcrypto_rsa_set0_crt_params(VCRYPTO_RSA *r, BIGNUM *dmp1, BIGNUM *dmq1,
                                BIGNUM *iqmp) {
  /* If the fields dmp1, dmq1 and iqmp in r are NULL, the corresponding input
   * parameters MUST be non-NULL.
   */
  if ((r->dmp1 == NULL && dmp1 == NULL) || (r->dmq1 == NULL && dmq1 == NULL) ||
      (r->iqmp == NULL && iqmp == NULL))
    return 0;

  if (dmp1 != NULL) {
    BN_clear_free(r->dmp1);
    r->dmp1 = dmp1;
    BN_set_flags(r->dmp1, BN_FLG_CONSTTIME);
  }
  if (dmq1 != NULL) {
    BN_clear_free(r->dmq1);
    r->dmq1 = dmq1;
    BN_set_flags(r->dmq1, BN_FLG_CONSTTIME);
  }
  if (iqmp != NULL) {
    BN_clear_free(r->iqmp);
    r->iqmp = iqmp;
    BN_set_flags(r->iqmp, BN_FLG_CONSTTIME);
  }
  r->dirty_cnt++;

  return 1;
}

int vcrypto_rsa_set0_key(VCRYPTO_RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
  /* If the fields n and e in r are NULL, the corresponding input
   * parameters MUST be non-NULL for n and e.  d may be
   * left NULL (in case only the public key is used).
   */
  if ((r->n == NULL && n == NULL) || (r->e == NULL && e == NULL))
    return 0;

  if (n != NULL) {
    BN_free(r->n);
    r->n = n;
  }
  if (e != NULL) {
    BN_free(r->e);
    r->e = e;
  }
  if (d != NULL) {
    BN_clear_free(r->d);
    r->d = d;
    BN_set_flags(r->d, BN_FLG_CONSTTIME);
  }
  r->dirty_cnt++;

  return 1;
}

rsa_data* VC_RSA_to_rsa_data(const VCRYPTO_RSA* r) {
  rsa_data *data = malloc(sizeof(*data));
  if (!data) {
    log_error("failed to malloc for rsa_data");
    return NULL;
  }

  if (BN_bn2binpad(r->n, data->n, RSA_MAX_KEY_SIZE_BYTES) != RSA_MAX_KEY_SIZE_BYTES) {
    log_error("failed to convert N to binary");
    goto cleanup;
  }

  data->e_len = BN_bn2binpad(r->e, data->e, RSA_MAX_KEY_SIZE_BYTES);
  if (data->e_len <= 0) {
    log_error("failed to convert E to binary");
    goto cleanup;
  }

  if (BN_bn2binpad(r->d, data->d, RSA_MAX_KEY_SIZE_BYTES) != RSA_MAX_KEY_SIZE_BYTES) {
    log_error("failed to convert D to binary");
    goto cleanup;
  }

  data->md5_val = 0;
  data->md5_val = XXH64(data, sizeof(*data), 0);

  return data;

cleanup:
  free(data);
  return NULL;
}

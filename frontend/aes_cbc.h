#ifndef VCRYPTO_GUEST_FE_AES_CBC_H
#define VCRYPTO_GUEST_FE_AES_CBC_H

#include <rte_cryptodev.h>
#include <openssl/core_dispatch.h>

#include "cipher_common.h"

typedef struct vcrypto_aes_cbc_ctx_t {
  PROV_CIPHER_CTX base;  // must be the first member

  unsigned int ctx_status_inited : 1;
  unsigned int ctx_status_session_created : 1;

  struct rte_cryptodev_sym_session* sess;
} vcrypto_aes_cbc_ctx;

#endif  // VCRYPTO_GUEST_FE_AES_CBC_H

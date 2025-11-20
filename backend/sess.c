#include <pthread.h>
#include <rte_crypto_sym.h>
#include <stdbool.h>

#include <openssl/obj_mac.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <log.h>
#include <socket.h>
#include <stdint.h>
#include <string.h>

#include "cdev.h"
#include "sess.h"
#include "hashmap.h"

// algs that we are going to support
//TODO: currently only support
// aes-256-cbc-hmac-sha1, aes-128-cbc-hmac-sha1, aes-256-cbc, aes-128-cbc
static inline bool vcrypto_is_chained_cipher(int nid) {
  if(nid == NID_aes_256_cbc_hmac_sha1 || nid == NID_aes_128_cbc_hmac_sha1) {
    return true;
  } else {
    return false;
  }
}

static struct rte_crypto_sym_session* create_rte_crypto_sym_sess(const cipher_auth_ctrl* cipher_auth) {
  enum rte_crypto_cipher_algorithm alg_id = RTE_CRYPTO_CIPHER_NULL;
  switch (cipher_auth->alg_nid) {
    case NID_aes_128_cbc:
    case NID_aes_256_cbc:
      alg_id = RTE_CRYPTO_CIPHER_AES_CBC;
      break;
    default:
      log_error("alg_nid: %d is not supported", cipher_auth->alg_nid);
      return NULL;
  }
  enum rte_crypto_cipher_operation cipher_direction =
     (cipher_auth->direction == CIPHER_DIRECTION_ENCRYPT)?
     RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;

  struct rte_crypto_cipher_xform cipher = {
    .algo = alg_id,
    .op = cipher_direction, 
    .key.length = cipher_auth->cipher_key_len,
    .iv.length = cipher_auth->cipher_iv_len,
    .iv.offset = 0,  // BUG: what should iv.offset be?
  };
  cipher.key.data = rte_malloc("cipher.key.data", cipher_auth->cipher_key_len, 64);
  memcpy((uint8_t*)cipher.key.data, cipher_auth->cipher_key_data, cipher_auth->cipher_key_len);

  struct rte_crypto_sym_xform sym_xform = {
    .next = NULL,
    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
    .cipher = cipher,
  };
  
  struct rte_crypto_sym_session *sess = rte_cryptodev_sym_session_create(cr->cdev_id, &sym_xform, sym_crypto_session_pool);

  rte_free((uint8_t*)cipher.key.data);
  return sess;
}

void sess_resource_destroy(sess_resource *sr) {
  if (!sr) {
    log_warn("pointer sr is NULL");
    return;
  }
  rte_cryptodev_sym_session_free(cr->cdev_id, sr->sess);
  free(sr);
}

sess_resource* get_sess_resource(const cipher_auth_ctrl* cipher_auth) {
  uint64_t hash_val = cipher_auth->alg_elems_md5;
  sess_resource* sr = hash_map_get(hash_val);
  if (sr) {
    log_trace("session exists!");
  } else {
    sr = malloc(sizeof(sess_resource));
    sr->sess = create_rte_crypto_sym_sess(cipher_auth);
    sr->ref_count = 1;
    hash_map_insert(hash_val, sr);
  }
  return sr;
}

void release_sess_resource(uint64_t md5_hash) {
  hash_map_retrieve(md5_hash);
}

#include <pthread.h>
#include <rte_crypto.h>
#include <rte_crypto_asym.h>
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
#include "mempool.h"

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

static struct rte_cryptodev_asym_session* create_rte_crypto_asym_sess(const rsa_key_data *key_data) {
  // xform for private key
  struct rte_crypto_rsa_xform rsa_xform = {
    .key_type = RTE_RSA_KEY_TYPE_EXP,
    .n = {.data = (uint8_t *)key_data->n, .length = RSA_MAX_KEY_SIZE_BYTES},
    .e = {.data = (uint8_t *)key_data->e, .length = RSA_MAX_KEY_SIZE_BYTES},
    .d = {.data = (uint8_t *)key_data->d, .length = RSA_MAX_KEY_SIZE_BYTES},
    .padding.type = RTE_CRYPTO_RSA_PADDING_PKCS1_5,
  };
  struct rte_crypto_asym_xform asym_xform = {
    .next = NULL,
    .xform_type = RTE_CRYPTO_ASYM_XFORM_RSA,
    .rsa = rsa_xform,
  };
  struct rte_cryptodev_asym_session *sess = NULL;
  int ret = rte_cryptodev_asym_session_create(cr->cdev_id, &asym_xform, asym_crypto_session_pool, (void**)&sess);
  if (ret != 0 || !sess) {
    fprintf(stderr, "failed to create asym_session\n");
    return NULL;
  }
  return sess;
}

static struct rte_crypto_sym_session* create_rte_crypto_sym_sess(const PROV_CIPHER_CTX* cipher_auth) {
  log_debug("enter create_rte_crypto_sym_sess");
  enum rte_crypto_cipher_algorithm alg_id = RTE_CRYPTO_CIPHER_NULL;
  // switch (cipher_auth->alg_nid) {
  //   case NID_aes_128_cbc:
  //   case NID_aes_256_cbc:
  //     alg_id = RTE_CRYPTO_CIPHER_AES_CBC;
  //     break;
  //   default:
  //     log_error("alg_nid: %d is not supported", cipher_auth->alg_nid);
  //     return NULL;
  // }
  // BUG: default using aes_cbc alg!
  alg_id = RTE_CRYPTO_CIPHER_AES_CBC;
  enum rte_crypto_cipher_operation cipher_direction =
     (cipher_auth->enc)?
     RTE_CRYPTO_CIPHER_OP_ENCRYPT : RTE_CRYPTO_CIPHER_OP_DECRYPT;

  struct rte_crypto_cipher_xform cipher = {
    .algo = alg_id,
    .op = cipher_direction, 
    .key.length = cipher_auth->keylen,
    .iv.length = cipher_auth->ivlen,
    .iv.offset = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op),
  };
  log_debug("going to rte_malloc for cipher.key.data");
  cipher.key.data = rte_malloc("cipher.key.data", cipher_auth->keylen, 64);
  if (cipher.key.data && cipher_auth->ks) {
    log_debug("going to copy cipher_auth's key data to cipher.key.data");
    // BUG: we should copy key into here
    // but so far we just set them to 0 -> key is set to 0
    // memcpy((uint8_t*)cipher.key.data, cipher_auth->ks, cipher_auth->keylen);
    memset((uint8_t*)cipher.key.data, 0,cipher_auth->keylen);
  } else {
    log_error("failed to malloc for cipher.key.data, or cipher_auth->ks is null");
  }

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
  // rte_cryptodev_sym_session_free(cr->cdev_id, sr->sess);
  rte_cryptodev_asym_session_free(cr->cdev_id, sr->sess);
  free(sr);
}

sess_resource* get_sess_resource(const rsa_key_data* cipher_auth) {
  // uint64_t hash_val = cipher_auth->alg_elems_md5;
  uint64_t hash_val = cipher_auth->md5_val;
  sess_resource* sr = hash_map_get(hash_val);
  if (sr) {
    log_debug("session exists!");
  } else {
    log_debug("session does not exit, creating one");
    sr = (sess_resource*)malloc(sizeof(sess_resource));
    sr->sess = create_rte_crypto_asym_sess(cipher_auth);
    sr->ref_count = 1;
    hash_map_insert(hash_val, sr);
  }
  return sr;
}

void release_sess_resource(uint64_t md5_hash) {
  hash_map_retrieve(md5_hash);
}

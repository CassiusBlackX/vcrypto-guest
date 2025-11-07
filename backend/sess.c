#include <pthread.h>
#include <rte_crypto_sym.h>
#include <stdbool.h>

#include <openssl/obj_mac.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <log.h>
#include <socket.h>

#include "cdev.h"
#include "sess.h"
#include "ciphers.h"
#include "hashmap.h"

extern struct rte_mempool *sess_mp;
extern cdev_resource *cr;
pthread_mutex_t sess_lock = PTHREAD_MUTEX_INITIALIZER;

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

static struct rte_crypto_sym_session* create_sess(unsigned char* alg_elems, uint8_t cdev_id) {
  int alg_nid = ALG_ELEMS_GET_ALG_NID(alg_elems);
  int alg_direction = ALG_ELEMS_GET_ALG_DIRECTION(alg_elems);
  int verify_digest = ALG_ELEMS_GET_VERIFY_DIGEST(alg_elems);
  int cipher_key_size = ALG_ELEMS_GET_CIPHER_KEY_SIZE(alg_elems);
  int cipher_iv_size = ALG_ELEMS_GET_CIPHER_IV_SIZE(alg_elems);
  int auth_key_size = ALG_ELEMS_GET_AUTH_KEY_SIZE(alg_elems);
  log_debug("%d %d %d %d %d %d", alg_nid, alg_direction, verify_digest, cipher_key_size, cipher_iv_size, auth_key_size);

  struct rte_crypto_cipher_xform cipher = {
    .algo = RTE_CRYPTO_CIPHER_
  }
  struct rte_crypto_sym_xform cipher_xform = {
    .type = RTE_CRYPTO_SYM_XFORM_CIPHER,
    .next = NULL,
  };
  
  
  struct rte_crypto_sym_session* sess = rte_cryptodev_sym_session_create(cdev_id, , )



}

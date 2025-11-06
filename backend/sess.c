#include <pthread.h>
#include <stdbool.h>

#include <openssl/obj_mac.h>
#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <log.h>

#include "cdev.h"
#include "sess.h"
#include "util.h"

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

static struct rte_crypto_sym_session* get_sess_resource(unsigned char* alg_elems, uint8_t cdev_id) {
  .
}

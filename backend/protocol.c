#include <stdbool.h>
#include <unistd.h>

#include <rte_cryptodev.h>
#include <rte_ring.h>

#include <log.h>

#include "cdev.h"
#include "protocol.h"
#include "socket.h"
#include "sess.h"
#include "../frontend/aes_cbc.h"

extern cdev_resource* cr;

extern struct rte_ring *shared_ring;
extern struct rte_mempool* sym_crypto_session_pool;
extern struct rte_mempool* sym_crypto_op_mempool;
extern struct rte_mempool* pktmbuf_mempool;

bool vcrypto_be_protocol_engine_init(int be_connfd) {
  if (be_connfd < 0) {
    log_error("invalid be_connfd");
    return false;
  }

  bool ret = true;
  ret &= vcrypto_send(be_connfd, cr->shared_ring->name, sizeof(cr->shared_ring->name));
  ret &= vcrypto_send(be_connfd, &be_connfd, sizeof(be_connfd));
  return ret;
}

bool vcrypto_be_protocol_create_sess(int be_connfd) {
  cipher_auth_ctrl cipher_auth;
  bool ret = true;
  ret &= vcrypto_recv(be_connfd, &cipher_auth, sizeof(cipher_auth));
  sess_resource *sr =  get_sess_resource(&cipher_auth); 
  ret &= vcrypto_send(be_connfd, sr->sess, sizeof(sr->sess));
  return ret;
}

bool vcrypto_be_protocol_remove_sess(int be_connfd) {
  uint64_t hash_val;
  bool ret = vcrypto_recv(be_connfd, &hash_val, sizeof(hash_val));
  release_sess_resource(hash_val);
  return ret;
}

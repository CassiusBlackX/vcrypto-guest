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

bool vcrypto_be_protocol_engine_init(int cliend_fd) {
  if (cliend_fd < 0) {
    log_error("invalid be_connfd");
    return false;
  }

  bool ret = true;
  ret &= vcrypto_send(cliend_fd, cr->shared_ring->name, sizeof(cr->shared_ring->name));
  ret &= vcrypto_send(cliend_fd, &cliend_fd, sizeof(cliend_fd));
  return ret;
}

bool vcrypto_be_protocol_create_sess(int client_fd) {
  cipher_auth_ctrl cipher_auth;
  bool ret = true;
  ret &= vcrypto_recv(client_fd, &cipher_auth, sizeof(cipher_auth));
  sess_resource *sr =  get_sess_resource(&cipher_auth); 
  ret &= vcrypto_send(client_fd, sr->sess, sizeof(sr->sess));
  return ret;
}

bool vcrypto_be_protocol_remove_sess(int client_fd) {
  uint64_t hash_val;
  bool ret = vcrypto_recv(client_fd, &hash_val, sizeof(hash_val));
  release_sess_resource(hash_val);
  return ret;
}

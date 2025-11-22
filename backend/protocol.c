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

bool vcrypto_be_protocol_engine_init(int client_fd) {
  if (client_fd < 0) {
    log_error("invalid be_connfd");
    return false;
  }
  log_trace("vcrypto_be_protocol_engine_init");

  bool ret = true;
  ret &= vcrypto_send(client_fd, cr->tx_ring->name, sizeof(cr->tx_ring->name));
  if (ret) log_trace("sent cr->tx_ring->name: %s", cr->tx_ring->name);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
  ret &= vcrypto_send(client_fd, cr->rx_ring->name, sizeof(cr->rx_ring->name));
  if (ret) log_trace("sent cr->rx_ring->name: %s", cr->rx_ring->name);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
  ret &= vcrypto_send(client_fd, &client_fd, sizeof(client_fd));
  if (ret) log_trace("sent client_fd: %d", client_fd);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
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

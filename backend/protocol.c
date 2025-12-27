#include <stdbool.h>
#include <unistd.h>

#include <rte_cryptodev.h>
#include <rte_ring.h>

#include <log.h>

#include "cdev.h"
#include "protocol.h"
#include "socket.h"
#include "sess.h"
#include "../frontend/cipher_common.h"

bool vcrypto_be_protocol_engine_init(int client_fd) {
  if (client_fd < 0) {
    log_error("invalid be_connfd");
    return false;
  }
  log_trace("vcrypto_be_protocol_engine_init");

  bool ret = true;
  ret &= vcrypto_send(client_fd, cr->tx_ring->name, sizeof(cr->tx_ring->name));
  if (ret) log_trace("sent bytes: %d cr->tx_ring->name: %s", sizeof(cr->tx_ring->name), cr->tx_ring->name);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
  ret &= vcrypto_send(client_fd, cr->rx_ring->name, sizeof(cr->rx_ring->name));
  if (ret) log_trace("sent bytes: %d cr->rx_ring->name: %s", sizeof(cr->rx_ring->name), cr->rx_ring->name);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
  ret &= vcrypto_send(client_fd, &client_fd, sizeof(client_fd));
  if (ret) log_trace("sent client_fd: %d", client_fd);
  usleep(100);  // FIXME: sleep a little time or we will send failed!
  return ret;
}

bool vcrypto_be_protocol_create_sess(int client_fd) {
  PROV_CIPHER_CTX cipher_auth;
  bool ret = true;
  ret &= vcrypto_recv(client_fd, &cipher_auth, sizeof(cipher_auth));
  log_debug("received md5_val: %zu", cipher_auth.md5_val);
  sess_resource *sr = get_sess_resource(&cipher_auth); 
  if (!sr) {
    log_error("failed to create session");
  }
  uint64_t sess_addr = (uint64_t)(sr->sess);
  log_trace("going to send sr->sess: %p, addr: %zx", sr->sess, sess_addr);
  // ret &= vcrypto_send(client_fd, sr->sess, sizeof(typeof(sr->sess)));  // send a pointer
  ret &= vcrypto_send(client_fd, &sess_addr, sizeof(uint64_t));
  if (ret) {
    log_trace("success created session: %p and sent to frontend", sr->sess);
  }
  return ret;
}

bool vcrypto_be_protocol_remove_sess(int client_fd) {
  uint64_t hash_val;
  bool ret = vcrypto_recv(client_fd, &hash_val, sizeof(hash_val));
  release_sess_resource(hash_val);
  return ret;
}

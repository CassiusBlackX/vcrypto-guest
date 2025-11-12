#include <rte_ring.h>
#include <rte_ring_core.h>

#include <log.h>
#include <socket.h>

#include "protocol.h"
#include "aes_cbc.h"

extern struct rte_ring *shared_ring;
static int fe_connfd;
static int be_connfd;

bool vcrypto_fe_protocol_engine_init(char *socket_file_path) {
  fe_connfd = vcrypto_connect(socket_file_path);
  if (fe_connfd == -1) {
    log_error("failed to connect to vcrypto_daemon through UDS");
    return false;
  }

  bool ret = true;

  char shared_ring_name[16] = {0};
  ret &= vcrypto_recv(fe_connfd, shared_ring_name, 16);
  shared_ring = rte_ring_lookup(shared_ring_name);
  if (shared_ring == NULL) {
    log_error("failed to find the shared_ring with vcrypto_daemon");
    return false;
  }

  ret &= vcrypto_recv(fe_connfd, &be_connfd, sizeof(be_connfd));
  if (be_connfd == 0) {
    log_error("failed to get correct be_connfd in fe_engine_init");
    return false;
  }
  
  return ret;
}

bool vcrypto_fe_protocol_create_sess(vcrypto_aes_cbc_ctx *ctx) {
  enum msg_type_cmd cmd = MSG_TYPE_CREATE_SESS;
  bool ret = true;
  ret &= vcrypto_send(fe_connfd, &cmd, sizeof(cmd));
  ret &= vcrypto_send(fe_connfd, &(ctx->cipher_auth), sizeof(vcrypto_aes_cbc_ctx));
 // DEBUG: compiler thinks it is not safe to pass a pointer through UDS
  vcrypto_recv(fe_connfd, &(ctx->sess), sizeof(void*)); 
  if (ctx->sess == NULL) {
    log_error("failed to receive ctx->sess from backend");
    return false;
  }
  return ret;
}

bool vcrypto_fe_protocol_remove_sess(vcrypto_aes_cbc_ctx *ctx) {
  enum msg_type_cmd cmd = MSG_TYPE_REMOVE_SESS;
  bool ret = true;
  ret &= vcrypto_send(fe_connfd, &cmd, sizeof(cmd));
  ret &= vcrypto_send(fe_connfd, &(ctx->cipher_auth), sizeof(ctx->cipher_auth));
  return ret;
}


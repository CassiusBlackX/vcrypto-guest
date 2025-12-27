#include <rte_mempool.h>
#include <rte_ring.h>
#include <rte_ring_core.h>

#include <log.h>
#include <socket.h>
#include <defs.h>
#include <stdint.h>
#include <unistd.h>

#include "protocol.h"
#include "aes_cbc.h"

struct rte_ring *tx_ring;
struct rte_ring *rx_ring;
struct rte_mempool* sym_crypto_session_pool;
struct rte_mempool* sym_crypto_op_mempool;
struct rte_mempool* pktmbuf_mempool;
static int fe_connfd;
static int be_connfd;

bool vcrypto_fe_protocol_engine_init(char *socket_file_path) {
  fe_connfd = vcrypto_connect(socket_file_path);
  if (fe_connfd == -1) {
    log_error("failed to connect to vcrypto_daemon through UDS");
    return false;
  }

  bool ret = true;

  // be's tx is fe's rx
  // receive the rx_ring_name first
  char rx_ring_name[RTE_RING_NAMESIZE] = {0};
  ret &= vcrypto_recv(fe_connfd, rx_ring_name, RTE_RING_NAMESIZE);
  if (ret) {
    log_trace("receive from backend, tx_ring_name: %s", rx_ring_name);
  } else {
    log_error("did not receive from backend!");
  }
  rx_ring= rte_ring_lookup(rx_ring_name);
  if (rx_ring  == NULL) {
    log_error("failed to find the rx_ring: %s with vcrypto_daemon", rx_ring_name);
    return false;
  } else {
    log_trace("success found rx_ring: %s", rx_ring_name);
  }
  // receive tx_ring name
  char tx_ring_name[RTE_RING_NAMESIZE] = {0};
  ret &= vcrypto_recv(fe_connfd, tx_ring_name, RTE_RING_NAMESIZE);
  if (ret) {
    log_trace("receive from backend, tx_ring_name: %s", tx_ring_name);
  } else {
    log_error("did not receive from backend!");
  }
  tx_ring= rte_ring_lookup(tx_ring_name);
  if (tx_ring  == NULL) {
    log_error("failed to find the tx_ring: %s with vcrypto_daemon", tx_ring_name);
    return false;
  } else {
    log_trace("success found tx_ring: %s", tx_ring_name);
  }

  ret &= vcrypto_recv(fe_connfd, &be_connfd, sizeof(be_connfd));
  if (be_connfd == 0) {
    log_error("failed to get correct be_connfd in fe_engine_init");
    return false;
  } else {
    log_trace("success received be_connfd: %d", be_connfd);
  }
  
  sym_crypto_session_pool = rte_mempool_lookup(SYM_CRYPTO_SESS_MP_NAME);
  if (sym_crypto_session_pool == NULL) {
    log_error("failed to lookup sym crypto session pool");
    return false;
  } else {
    log_trace("success found sym crypto session pool: %p", sym_crypto_session_pool);
  }

  sym_crypto_op_mempool = rte_mempool_lookup(SYM_CRYPTO_OP_MP_NAME);
  if (sym_crypto_op_mempool == NULL) {
    log_error("failed to lookup sym crypto op mempool");
    return false;
  } else {
    log_trace("success found sym crypto op mempool: %p", sym_crypto_op_mempool);
  }

  pktmbuf_mempool = rte_mempool_lookup(SYM_CRYPTO_MBUF_MP_NAME);
  if (pktmbuf_mempool == NULL) {
    log_error("failed to lookup pktmbuf mempool");
    return false;
  } else {
    log_trace("success found pktmbuf mempool: %p", pktmbuf_mempool);
  }

  return ret;
}

bool vcrypto_fe_protocol_create_sess(vcrypto_aes_cbc_ctx *ctx) {
  enum msg_type_cmd cmd = MSG_TYPE_CREATE_SESS;
  bool ret = true;
  ret &= vcrypto_send(fe_connfd, &cmd, sizeof(cmd));
  log_debug("sending ctx->base to backend");
  log_debug("md5 val: %zu", ctx->base.md5_val);
  ret &= vcrypto_send(fe_connfd, &(ctx->base), sizeof(ctx->base));
  // BUG: UDS seems to deny to send a pointer val
  // using uint64_t ro receive pointer val
  // and cast it into pointer
  // this is probably wrong!
  uint64_t addr = 0;
  ret &= vcrypto_recv(fe_connfd, &addr, sizeof(void*)); 
  // ret &= vcrypto_recv(fe_connfd, &(ctx->sess), sizeof(void*)); 
  if (ret) {
    log_debug("received addr: %zx", addr);
  }
  ctx->sess = (typeof(ctx->sess))addr;
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
  ret &= vcrypto_send(fe_connfd, &(ctx->base), sizeof(ctx->base));
  return ret;
}


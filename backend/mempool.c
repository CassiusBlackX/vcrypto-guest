#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>

#include <log.h>

#include "mempool.h"
#include "cdev.h"

extern cdev_resource* cr;

struct rte_mempool* sym_crypto_session_pool;
struct rte_mempool* sym_crypto_op_mempool;
struct rte_mempool* mbuf_mempool;

bool vcrypto_be_mempool_prepare() {
  size_t session_size = rte_cryptodev_sym_get_private_session_size(cr->cdev_id);
  sym_crypto_session_pool = rte_cryptodev_sym_session_pool_create("sym_crypto_sess_mp",  SYM_SESSION_POOL_NUM_ELEMS, session_size, 0, 0/*set priv size to 0*/, rte_socket_id());
  sym_crypto_op_mempool = rte_crypto_op_pool_create("sym_crypto_op_mp", RTE_CRYPTO_OP_TYPE_SYMMETRIC, SYM_CRYPTO_OP_POOL_SIZE, 0, 0/*no priv size*/, rte_socket_id());
  mbuf_mempool = rte_pktmbuf_pool_create("sym_crypto_mbuf_mp", SYM_CRYPTO_MBUF_NUM , 0, 0, SYM_CRYPTO_MBUF_SIZE, rte_socket_id());
  if (sym_crypto_session_pool == NULL ||
      sym_crypto_op_mempool == NULL ||
      mbuf_mempool == NULL) {
    return false;
  }
  return true;
}

void vcrypto_be_mempool_cleanup() {
  rte_mempool_free(sym_crypto_session_pool);
  rte_mempool_free(sym_crypto_op_mempool);
  rte_mempool_free(mbuf_mempool);
  sym_crypto_session_pool = sym_crypto_op_mempool = mbuf_mempool = NULL;
}

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>

#include <log.h>
#include <defs.h>

#include "mempool.h"
#include "cdev.h"

struct rte_mempool* sym_crypto_session_pool;
struct rte_mempool* sym_crypto_op_mempool;
struct rte_mempool* pktmbuf_mempool;

bool vcrypto_be_mempool_prepare() {
  size_t session_size = rte_cryptodev_sym_get_private_session_size(cr->cdev_id);
  sym_crypto_session_pool = rte_cryptodev_sym_session_pool_create(SYM_CRYPTO_SESS_MP_NAME,
                                                                  SYM_SESSION_POOL_NUM_ELEMS,
                                                                  session_size,
                                                                  0, 0/*set priv size to 0*/,
                                                                  rte_socket_id());
  if(sym_crypto_session_pool == NULL) {
    log_error("sym_crypto_session_pool create failed");
    return false;
  }
  pktmbuf_mempool = rte_pktmbuf_pool_create(SYM_CRYPTO_MBUF_MP_NAME,
                                            SYM_CRYPTO_MBUF_NUM ,
                                            0, sizeof(struct rte_crypto_op),
                                            SYM_CRYPTO_MBUF_SIZE,
                                            rte_socket_id());
  if (pktmbuf_mempool == NULL) {
    log_error("pktmbuf_mempool create failed");
    return false;
  }
  sym_crypto_op_mempool = rte_crypto_op_pool_create(SYM_CRYPTO_OP_MP_NAME,
                                                    RTE_CRYPTO_OP_TYPE_SYMMETRIC,
                                                    SYM_CRYPTO_OP_POOL_SIZE,
                                                    0,
                                                    16, /* max iv length*/
                                                    rte_socket_id());
  if (sym_crypto_op_mempool == NULL) {
    log_error("sym_crypto_op_mempool create failed");
    return false;
  }
  return true;
}

void vcrypto_be_mempool_cleanup() {
  rte_mempool_free(sym_crypto_session_pool);
  log_debug("sym_crypto_session_pool freed");
  rte_mempool_free(sym_crypto_op_mempool);
  log_debug("sym_crypto_op_mempool freed");
  rte_mempool_free(pktmbuf_mempool);
  log_debug("pktmbuf_mempool freed");
  sym_crypto_session_pool = sym_crypto_op_mempool = pktmbuf_mempool = NULL;
}

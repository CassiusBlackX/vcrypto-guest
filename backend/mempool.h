#ifndef VCRYPTO_GUEST_BE_MEMPOOL_H
#define VCRYPTO_GUEST_BE_MEMPOOL_H

#include <stdbool.h>

#include <openssl/async.h>

#define SYM_SESSION_POOL_NUM_ELEMS 512
#define SYM_CRYPTO_OP_POOL_SIZE 8192
#define SYM_CRYPTO_MBUF_NUM 2048
#define SYM_CRYPTO_MBUF_SIZE 32768

bool vcrypto_be_mempool_prepare();
void vcrypto_be_mempool_cleanup();

extern struct rte_mempool* sym_crypto_session_pool;
extern struct rte_mempool* sym_crypto_op_mempool;
extern struct rte_mempool* pktmbuf_mempool;

#endif // VCRYPTO_GUEST_BE_MEMPOOL_H

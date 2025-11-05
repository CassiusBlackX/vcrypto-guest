#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_memory.h>
#include <rte_mempool.h>

#include <log.h>
#include <stdint.h>

#include "mempool.h"
#include "ciphers.h"

struct rte_mempool *sess_mp = 0;
struct rte_mempool *sess_mp_priv = 0;
struct rte_mempool *opdpipe_mp = 0;

int num_obj_mps = 2;
struct rte_mempool *obj_mps[2] = {0, 0};
uint32_t buf_sizes[2] = {2048, 16384};
uint16_t buf_offsets[2] = {0, 0};

static void obj_mp_elem_init(struct rte_mempool* mp, void *opaque_arg, void* obj, unsigned obj_idx) {
  int *obj_arr_idx = opaque_arg;
  struct rte_crypto_op *op = obj;
  struct rte_mbuf *m = (struct rte_mbuf*)((uint8_t*)obj + buf_offsets[*obj_arr_idx]);

  op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
  op->phys_addr = rte_mem_virt2
}

#include <rte_common.h>
#include <rte_crypto.h>
#include <rte_crypto_sym.h>
#include <rte_cryptodev.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_mempool.h>

#include <log.h>
#include <stdint.h>

#include "mempool.h"
#include "ciphers.h"

struct rte_mempool *sess_mp = 0;
struct rte_mempool *opdpipe_mp = 0;

struct rte_mempool *obj_mps[NUM_OBJ_MP] = {0, 0};
uint32_t buf_sizes[NUM_OBJ_MP] = {2048, 16384};
uint16_t buf_offsets[NUM_OBJ_MP] = {0, 0};

static void obj_mp_elem_init(struct rte_mempool* mp, void *opaque_arg, void* obj, unsigned obj_idx) {
  int *obj_arr_idx = opaque_arg;
  struct rte_crypto_op *op = obj;
  struct rte_mbuf *m = (struct rte_mbuf*)((uint8_t*)obj + buf_offsets[*obj_arr_idx]);

  op->type = RTE_CRYPTO_OP_TYPE_SYMMETRIC;
  op->status = RTE_CRYPTO_OP_STATUS_NOT_PROCESSED;
  op->sess_type = RTE_CRYPTO_OP_WITH_SESSION;
  op->phys_addr = rte_mem_virt2iova(obj);
  op->mempool = mp;
  op->private_data_offset = 0;  // we do not use it
  op->sym->m_src = m;
  op->sym->m_dst = 0;

  m->priv_size = 0;  // we do not use it 
  m->buf_addr = (char*)m + sizeof(struct rte_mbuf);
  m->buf_iova = rte_mem_virt2iova(m->buf_addr);
  m->buf_len = MAX_TLS_HEADER_LENGTH + buf_sizes[*obj_arr_idx] + MAX_TLS_MAC_LENGTH + MAX_TLS_PAD_LENGTH;
  m->data_len = 0;
  m->data_off = 0;
  m->pool = mp;
  m->nb_segs = 1;
  m->port = 0xff;
  rte_mbuf_refcnt_set(m, 1);
  m->next = 0;
  /*
  * the buffer is structed as follows
  *  1. tls header   --- fixed 13 bytes
  *  2. tls pure payload  ---- can only be 2048/16384 bytes
  *  3. tls-mac  --- fixed 64 bytes
  *  4. tls-pad  --- fixed 256 bytes

  *  NOTE: 
  *  iv is not in buffer, but in `rte_crypto_op`
  *  opDone/async job fd is not in buffer, in `rte_crypto_op`
  */
}

void vcrypto_be_mempool_prepare() {
  uint8_t socket_id = 0;

  // prepare session pool
  sess_mp = rte_cryptodev_sym_session_pool_create("sess_mp", SESSION_POOL_INITIAL_SIZE, 0, 0, 0, socket_id);

  // prepare rte_crypto_op
  for (size_t i = 0; i < sizeof(obj_mps) / sizeof(obj_mps[0]); i++) {
    /* 
      |rte_crypto_op|rte_crypto_sym_op|be connfd|opdone ptr(8 byte)|cipher_iv|pads|rte_mbuf|tls-all(hdr+pure_payload+mac+pad)|
      where opdone wraps fe_async_fd, num_submitted and num_progressed
      for speed or non-pipelined tls 1.0+, num_submitted/num_progressed changes between 0 and 1
    */
    uint16_t crypto_op_size = sizeof(struct rte_crypto_op) + sizeof(struct rte_crypto_sym_op);
    uint16_t extra_op_priv_size = 8;  // be opdone ptr(8 bytes)
    uint16_t crypto_op_private_size = extra_op_priv_size + 16;  // 16: CIPHER_IV_LENGTH
    uint16_t crypto_op_total_size =crypto_op_size + crypto_op_private_size;
    buf_offsets[i] = RTE_CACHE_LINE_ROUNDUP(crypto_op_total_size);

    uint32_t mbuf_size = sizeof(struct rte_mbuf) + MAX_TLS_HEADER_LENGTH + buf_sizes[i] + MAX_TLS_MAC_LENGTH + MAX_TLS_PAD_LENGTH;
    uint32_t obj_size = buf_offsets[i] + mbuf_size;

    char pool_name[16];
    snprintf(pool_name, sizeof(pool_name), "obj_mp_%zu", i);
    // for 16K packet, about 8K * 16K = 128M ram needed
    // aligned internally by rte_memzon_reserve_thread_sage
    obj_mps[i] = rte_mempool_create_empty(pool_name, OBJ_POOL_INITIAL_SIZE, obj_size, 512, 0, socket_id, 0); 

    if (obj_mps[i] == NULL) {
      log_error("cannot allocate obj_mps[%d]", i);
      exit(1);
    }
    // adopted for later scaling, can be sp & sc if single backend process
    if (rte_mempool_set_ops_byname(obj_mps[i], "ring_mp_mc", 0) != 0) {
      log_error("error setting mempool handler for obj_mps[%d]");
      exit(1);
    }
    if(rte_mempool_populate_default(obj_mps[i]) < 0) {
      log_error("error populating mempool for obj_mps[%d]", i);
      exit(1);
    }

    rte_mempool_obj_iter(obj_mps[i], obj_mp_elem_init, (void*)(&i));
  }

  // prepare opdone mp
  opdpipe_mp = rte_mempool_create_empty("opdpipe_mp", OPDPIPE_POOL_INITIAL_SIZE, sizeof(op_done_pipe_t), 512, 0, socket_id, 0);
  if (opdpipe_mp == NULL) {
    log_error("cannot allocate opdpipe_mp");
    exit(1);
  }
  if (rte_mempool_set_ops_byname(opdpipe_mp, "ring_mp_mc", 0) != 0) {
    log_error("error setting mempool handler for opdpipe_mp");
    exit(1);
  }
  if (rte_mempool_populate_default(opdpipe_mp) < 0) {
    log_error("error populating mempool for opdpipe_mp");
    exit(1);
  }
}

void vcrypto_be_mempool_cleanup() {
  for (size_t i = 0; i < sizeof(obj_mps) / sizeof(obj_mps[0]); i++) {
    rte_mempool_free(obj_mps[i]);
  }
  rte_mempool_free(opdpipe_mp);
  rte_mempool_free(sess_mp);
}

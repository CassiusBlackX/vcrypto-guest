#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <log.h>

#include <rte_cryptodev.h>
#include <rte_ring.h>

#include "cdev.h"
#include "ciphers.h"
#include "sess.h"
#include "protocol.h"
#include "mempool.h"
#include "socket.h"

extern uint32_t buf_sizes[2];
extern uint16_t buf_offsets[2];

extern cdev_resource* cr;

// rx: natural conn event
// tx: num_obj_mps(value) + obj_mp_metas(value) + opdpipe_mp_meta(value) + cr->shared_ring->name + be_connfd(value)
void vcrypto_be_protocol_engine_init(int be_connfd) {
  // mempool has been allcated in backend's main thread startup
  // cdev has been initialized in backend's main thread startup
  // share info to frontend as well
  // additionaly, share be_connfd to frontend

  // 1 share mempool info to fe
  // 1.1 prepare crypto_op mempool info
  obj_mp_meta *obj_ms = (obj_mp_meta*)calloc(NUM_OBJ_MP, sizeof(obj_mp_meta));
  for (size_t i = 0; i < NUM_OBJ_MP; i++) {
    obj_mp_meta* meta = ((obj_mp_meta*)(obj_ms + i));
    snprintf(meta->obj_mp_name, sizeof(meta->obj_mp_name), "obj_mp_%zu", i);
    meta->obj_mp_buf_size = buf_sizes[i];
    meta->obj_mp_buf_offset = buf_offsets[i];
  }
  // 1.2 prepare opdone mempool info
  opdpipe_mp_meta *opdpipe_m = (opdpipe_mp_meta*)calloc(1, sizeof(opdpipe_mp_meta));
  snprintf(opdpipe_m->opdpipe_mp_name, sizeof(opdpipe_m->opdpipe_mp_name), "opdpipe_mp");

  // 2. response mempool info
  // 2.1 response crypto_op mempool info
  int num_obj_mp = NUM_OBJ_MP;
  vcrypto_send(be_connfd, &num_obj_mp, sizeof(num_obj_mp));
  vcrypto_send(be_connfd, obj_ms, sizeof(obj_mp_meta) * num_obj_mp);
  free(obj_ms);
  // 2.2 response opdone mempool info
  vcrypto_send(be_connfd, opdpipe_m, sizeof(opdpipe_m));
  free(opdpipe_m);

  // 3. response cr->shared_ring info (name)
  vcrypto_send(be_connfd, cr->shared_ring->name, sizeof(cr->shared_ring->name));

  // 4. response be_connfd info
  vcrypto_send(be_connfd, &be_connfd, sizeof(be_connfd));
}

// rx: (msg_type +)akg)elems[SIZE_ALG_ELEMS] (value)
// tx: sess pointer

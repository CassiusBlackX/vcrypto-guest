#ifndef VCRYPTO_GUEST_FE_PROTOCOL_H
#define VCRYPTO_GUEST_FE_PROTOCOL_H

#include <stdbool.h>

#include "aes_cbc.h"
#include "rsa.h"
 
enum msg_type_cmd {
  MSG_TYPE_CREATE_SESS,
  MSG_TYPE_REMOVE_SESS,
  MSG_TYPE_CREATE_ASYNC_FD,
  MSG_TYPE_REMOVE_ASYNC_FD,
};

bool vcrypto_fe_protocol_engine_init(char *socket_file_path);
// bool vcrypto_fe_protocol_create_sess(vcrypto_aes_cbc_ctx* ctx);
bool vcrypto_fe_protocol_create_sess(rsa_session_data *ctx);
bool vcrypto_fe_protocol_remove_sess(rsa_session_data *ctx);

extern struct rte_ring *tx_ring;
extern struct rte_ring *rx_ring;
extern struct rte_mempool* sym_crypto_session_pool;
extern struct rte_mempool* crypto_op_mempool;
extern struct rte_mempool* pktmbuf_mempool;

#endif  // VCRYPTO_GUEST_FE_PROTOCOL_H

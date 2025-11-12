#ifndef VCRYPTO_GUEST_FE_PROTOCOL_H
#define VCRYPTO_GUEST_FE_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>

#include "aes_cbc.h"
 
enum msg_type_cmd {
  MSG_TYPE_CREATE_SESS,
  MSG_TYPE_REMOVE_SESS,
  MSG_TYPE_CREATE_ASYNC_FD,
  MSG_TYPE_REMOVE_ASYNC_FD,
};

bool vcrypto_fe_protocol_engine_init(char *socket_file_path);
bool vcrypto_fe_protocol_create_sess(vcrypto_aes_cbc_ctx* ctx);
bool vcrypto_fe_protocol_remove_sess(vcrypto_aes_cbc_ctx* ctx);


#endif  // VCRYPTO_GUEST_FE_PROTOCOL_H

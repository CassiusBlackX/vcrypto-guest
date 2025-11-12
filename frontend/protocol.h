#ifndef VCRYPTO_GUEST_FE_PROTOCOL_H
#define VCRYPTO_GUEST_FE_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
 
enum msg_type_cmd {
  MSG_TYPE_CREATE_SESS,
  MSG_TYPE_REMOVE_SESS,
  MSG_TYPE_CREATE_ASYNC_FD,
  MSG_TYPE_REMOVE_ASYNC_FD,
};

typedef struct {
  char obj_mp_name[16];
  uint32_t obj_mp_buf_size;
  uint16_t obj_mp_buf_offset;  
} obj_mp_meta;

typedef struct {
  char opdpipe_mp_name[16];
} opdpipe_mp_meta;

bool vcrypto_fe_protocol_engine_init(char *socket_file_path);
bool vcrypto_fe_protocol_create_sess()

#endif  // VCRYPTO_GUEST_FE_PROTOCOL_H

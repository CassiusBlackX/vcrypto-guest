#ifndef VCRYPTO_GUEST_BE_PROTOCOL_H
#define VCRYPTO_GUEST_BE_PROTOCOL_H

#include <stdint.h>

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

void vcrypto_be_protocol_engine_init(int connfd);
void vcrypto_be_protocol_create_sess(int connfd);
void vcrypto_be_protocol_remove_sess(int connfd);
void vcrypto_be_protocol_create_async_fd(int connfd, int *be_fd_to_connfd);
void vcrypto_be_protocol_remove_async_fd(int connfd, int *be_fd_to_connfd);

#endif // VCRYPTO_GUEST_BE_PROTOCOL_H

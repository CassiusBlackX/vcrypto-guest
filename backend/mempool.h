#ifndef VCRYPTO_GUEST_BE_MEMPOOL_H
#define VCRYPTO_GUEST_BE_MEMPOOL_H

#include <stdint.h>

#include <openssl/async.h>

#define SESSION_POOL_INITIAL_SIZE 8192
#define SESSION_PRIV_POOL_INITIAL_SIZE SESSION_POOL_INITIAL_SIZE
#define OBJ_POOL_INITIAL_SIZE 8192
#define OPDPIPE_POOL_INITIAL_SIZE OBJ_POOL_INITIAL_SIZE
#define MAX_TLS_HEADER_LENGTH 13
#define MAX_TLS_MAC_LENGTH 64
#define MAX_TLS_PAD_LENGTH 256

#define NUM_OBJ_MP 2

void vcrypto_be_mempool_prepare();
void vcrypto_be_mempool_cleanup();
void buf_len_to_obj_arr_idx(uint32_t buf_len);

#endif // VCRYPTO_GUEST_BE_MEMPOOL_H

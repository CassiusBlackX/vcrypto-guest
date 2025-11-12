#ifndef VCRYPTO_GUEST_BE_CIPHERS_H
#define VCRYPTO_GUEST_BE_CIPHERS_H

#include <openssl/provider.h>
#include <openssl/async.h>
#include <stdbool.h>

#define OFFSET_ALG_NID 0
#define OFFSET_VERIFY_DIGEST 4
#define OFFSET_ALG_DIRECTION 8
#define OFFSET_CIPHER_KEY_SIZE 12
#define OFFSET_CIPHER_IV_SIZE 16
#define OFFSET_AUTH_KEY_SIZE 20
#define OFFSET_CIPHER_KEY_DATA 24
#define OFFSET_AUTH_KEY_DATA 56
#define OFFSET_ALG_ELEMS_MD5 120
#define SIZE_ALG_ELEMS 136

#define ALG_ELEMS_GET_ALG_NID(p) ( *((int *)((unsigned char *)p + OFFSET_ALG_NID)) )
#define ALG_ELEMS_GET_VERIFY_DIGEST(p) ( *((int *)((unsigned char *)p + OFFSET_VERIFY_DIGEST)) )
#define ALG_ELEMS_GET_ALG_DIRECTION(p) ( *((int *)((unsigned char *)p + OFFSET_ALG_DIRECTION)) )
#define ALG_ELEMS_GET_CIPHER_KEY_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_CIPHER_KEY_SIZE)) )
#define ALG_ELEMS_GET_CIPHER_IV_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_CIPHER_IV_SIZE)) )
#define ALG_ELEMS_GET_AUTH_KEY_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_AUTH_KEY_SIZE)) )

#define ALG_ELEMS_GET_ALG_NID(p) ( *((int *)((unsigned char *)p + OFFSET_ALG_NID)) )
#define ALG_ELEMS_GET_ALG_DIRECTION(p) ( *((int *)((unsigned char *)p + OFFSET_ALG_DIRECTION)) )
#define ALG_ELEMS_GET_CIPHER_KEY_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_CIPHER_KEY_SIZE)) )
#define ALG_ELEMS_GET_CIPHER_IV_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_CIPHER_IV_SIZE)) )
#define ALG_ELEMS_GET_AUTH_KEY_SIZE(p) ( *((int *)((unsigned char *)p + OFFSET_AUTH_KEY_SIZE)) )

typedef struct op_done_t {
    volatile int flag; // set by be to show that all the pipeline ops of a do_cipher have been handled
    volatile bool verify_result;
    volatile ASYNC_JOB *job;
} op_done;

typedef struct op_done_pipe_type {
	op_done opDone;
	volatile int num_pipes;
	volatile int num_submitted;
	volatile int num_processed;
	volatile int be_async_fd;
	volatile int be_conn_fd;
} op_done_pipe;

void vcrypto_create_ciphers(void);
void vcrypto_free_ciphers(void);
int vcrypto_ciphers(const EVP_CIPHER **cipher, const int **nids, int nid);

#endif // VCRYPTO_GUEST_BE_CIPHERS_H

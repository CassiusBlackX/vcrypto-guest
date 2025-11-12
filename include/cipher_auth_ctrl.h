#ifndef VCRYPTO_GUEST_UTILS_CIPHER_AUTH_CTRL_H
#define VCRYPTO_GUEST_UTILS_CIPHER_AUTH_CTRL_H

#include <stdint.h>
#define CIPHER_DIRECTION_ENCRYPT 0
#define CIPHER_DIRECTION_DECRYPT 1

typedef struct cipher_auth_t {
  uint32_t alg_nid;
  uint32_t direction; // 0 for encrypt, 1 for decrypt
  uint32_t cipher_key_len;
  uint32_t cipher_iv_len;
  uint32_t auth_key_len;
  uint8_t cipher_key_data[32];
  uint8_t auth_key_data[64];
  uint64_t alg_elems_md5;
} cipher_auth_ctrl;

#endif // VCRYPTO_GUEST_UTILS_CIPHER_AUTH_CTRL_H

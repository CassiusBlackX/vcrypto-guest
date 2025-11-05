#ifndef VCRYPTO_GUEST_BE_CDEV_H
#define VCRYPTO_GUEST_BE_CDEV_H

#include <openssl/async.h>
#include <rte_crypto.h>
#include <rte_cryptodev.h>
#include <rte_ring.h>

#include "ciphers.h"

#define MAX_NUM_OPS_PER_BURST 64
#define SHARED_RING_INITIAL_SIZE 1024

typedef struct {
  uint8_t cdev_id;
  struct rte_ring *shared_ring;
  struct rte_crypto_op ** ops;
  int num_valid_ops;
} cdev_resource;

void vcrypto_be_cdev_resource_prepare();
void vcrypto_be_cdev_resource_cleanup();

#endif // VCRYPTO_GUEST_BE_CDEV_H

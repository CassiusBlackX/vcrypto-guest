#include <rte_cryptodev.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <log.h>

#include "cdev.h"
#include "util.h"

extern struct rte_mempool *sess_mp;

cdev_resource *cr = 0;

void vcrypto_be_cdev_resource_prepare() {
  uint8_t cdev_ids[64] = {0};
  int num_cdevs = rte_cryptodev_devices_get("crypto_virtio", cdev_ids, 64);
  if (num_cdevs <= 0) {
    log_error("no crypto dev available!");
    exit(1);
  }

  cr = (cdev_resource*)malloc(sizeof(cdev_resource));
  if (cr == 0) {
    log_error("cannot allocate cryptodev_resource");
    exit(1);
  }
  cr->cdev_id = cdev_ids[0];
  struct rte_cryptodev_info cdev_info= {0};
  rte_cryptodev_info_get(cr->cdev_id, &cdev_info);
  struct rte_cryptodev_config conf = {
    .nb_queue_pairs = 1,
    .socket_id = 0,
  };
  if (rte_cryptodev_configure(cr->cdev_id, &conf) < 0) {
    log_error("failed to configure cdev %d", cr->cdev_id);
    exit(1);
  }

  struct rte_cryptodev_qp_conf qp_conf = {
    .nb_descriptors = 2048,
    .mp_session = sess_mp,
  };

  if (rte_cryptodev_queue_pair_setup(cr->cdev_id, 0, &qp_conf, 0) < 0) {
    log_error("failed to setup queue pair on cdev %d", cr->cdev_id);
    exit(1);
  }
  if (rte_cryptodev_start(cr->cdev_id) < 0) {
    log_error("failed to start cdev %d", cr->cdev_id);
    exit(1);
  }

  char ring_name[16];
  sprintf(ring_name, "shared_ring_%d", cdev_ids[0]);

  cr->shared_ring = rte_ring_create(ring_name, SHARED_RING_INITIAL_SIZE, 0, 0);
  if (cr->shared_ring == 0) {
    log_error("cannot allocate shared_ring");
    exit(1);
  }

  cr->ops = (struct rte_crypto_op**)malloc(sizeof(struct rte_crypto_op*) * MAX_NUM_OPS_PER_BURST);
  if (cr->ops == 0) {
    log_error("cannot allocate ops");
    exit(1);
  }
  cr->num_valid_ops = 0;
}

void vcrypto_be_cdev_resource_cleanup() {
  struct rte_cryptodev_stats stats;
  rte_cryptodev_stats_get(cr->cdev_id, &stats);
  rte_cryptodev_stop(cr->cdev_id);
  log_info("vcrypto dev %d stopped", cr->cdev_id);
  free(cr->ops);
  rte_ring_free(cr->shared_ring);
  free(cr);
}

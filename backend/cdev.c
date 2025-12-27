#include <rte_cryptodev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_ring.h>

#include <log.h>
#include <rte_ring_core.h>

#include "cdev.h"
#include "mempool.h"

cdev_resource *cr = 0;

void vcrypto_be_cdev_resource_prepare() {
  uint8_t cdev_ids[64] = {0};
  log_trace("going to rte_cryptodev_devices_get");
  uint8_t num_cdevs = rte_cryptodev_devices_get("crypto_virtio", cdev_ids, 64);
  if (num_cdevs == 0) {
    log_error("no crypto dev available!, num_cdevs: %d", num_cdevs);
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
    .mp_session = sym_crypto_session_pool,
  };

  if (rte_cryptodev_queue_pair_setup(cr->cdev_id, 0, &qp_conf, 0) < 0) {
    log_error("failed to setup queue pair on cdev %d", cr->cdev_id);
    exit(1);
  }
  if (rte_cryptodev_start(cr->cdev_id) < 0) {
    log_error("failed to start cdev %d", cr->cdev_id);
    exit(1);
  }

  char tx_ring_name[16] = {0};
  snprintf(tx_ring_name, sizeof(tx_ring_name), "tx_ring_%d", cdev_ids[0]);
  cr->tx_ring = rte_ring_create(tx_ring_name, SHARED_RING_INITIAL_SIZE, rte_socket_id(), RING_F_SP_ENQ | RING_F_MC_RTS_DEQ );
  if (cr->tx_ring == 0) {
    log_error("cannot allocate tx_ring");
    exit(1);
  } else {
    log_trace("created cr->tx_ring: %s", cr->tx_ring->name);
  }
  char rx_ring_name[16] = {0};
  snprintf(rx_ring_name, sizeof(rx_ring_name), "rx_ring_%d", cdev_ids[0]);
  cr->rx_ring = rte_ring_create(rx_ring_name, SHARED_RING_INITIAL_SIZE, rte_socket_id(), RING_F_MP_RTS_ENQ | RING_F_SC_DEQ);
  if (cr->rx_ring== 0) {
    log_error("cannot allocate rx_ring");
    exit(1);
  } else {
    log_trace("created cr->rx_ring: %s", cr->rx_ring->name);
  }

  cr->ops = (struct rte_crypto_op**)malloc(sizeof(struct rte_crypto_op*) * MAX_NUM_OPS_PER_BURST);
  if (cr->ops == 0) {
    log_error("cannot allocate ops");
    exit(1);
  }
  cr->num_valid_ops = 0;

  log_trace("leaving vcrypto_be_cdev_resource_prepare");
}

void vcrypto_be_cdev_resource_cleanup() {
  struct rte_cryptodev_stats stats;
  rte_cryptodev_stats_get(cr->cdev_id, &stats);
  rte_cryptodev_stop(cr->cdev_id);
  log_info("vcrypto dev %d stopped", cr->cdev_id);
  free(cr->ops);
  rte_ring_free(cr->tx_ring);
  free(cr);
}

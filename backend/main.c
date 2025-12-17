#include <assert.h>
#include <signal.h>

#include <rte_eal.h>

#include <log.h>
#include <unistd.h>

#include "event.h"
#include "cdev.h"
#include "mempool.h"

static void SIGINT_handler(int id) {
  (void)id;  // depress unused warning
  running = 0;
}

int main(int argc, char **argv) {
  log_set_level(LOG_TRACE);
  log_info("vcrypto_daemon starting...");
  
  signal(SIGINT, SIGINT_handler);
  signal(SIGTERM, SIGINT_handler);

  int ret = rte_eal_init(argc, argv);
  assert(rte_eal_process_type() == RTE_PROC_PRIMARY && "vcrypto daemon process has to be a dpdk primary process\n");
  if (ret < 0) {
    log_error("rte_eal_init failed!, ret: %d", ret);
  } else {
    log_trace("rte_eal_init success");
  }

  log_trace("going to enter vcrypto_be_cdev_resource_prepare");
  vcrypto_be_cdev_resource_prepare();
  log_trace("going to enter vcrypto_be_mempool_prepare");
  ret &= vcrypto_be_mempool_prepare();
  int listen_fd = 0, epoll_fd = 0;
  log_trace("going to init_server");
  ret &= init_server(SOCKET_FILE_ABSOLUTE_PATH, &listen_fd, &epoll_fd);
  log_trace("init server success");
  vcrypto_be_mainloop(listen_fd, epoll_fd);

  log_info("cleaning cdev_resource");
  vcrypto_be_cdev_resource_cleanup();  

  log_info("cleaning mempool");
  vcrypto_be_mempool_cleanup();

  log_info("cleaning socket");
  close(listen_fd);
  close(epoll_fd);
  unlink(SOCKET_FILE_ABSOLUTE_PATH);

  return 0;
}

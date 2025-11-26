#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <rte_crypto.h>
#include <rte_cryptodev.h>

#include <log.h>
#include <socket.h>

#include "cdev.h"
#include "event.h"
#include "protocol.h"

volatile sig_atomic_t running = 1;

int make_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool init_server(const char *socket_path, int *out_listen_fd,
                 int *out_epoll_fd) {
  int listen_fd = -1, epoll_fd = -1;

  // delete old socket file
  unlink(socket_path);

  // create listen fd
  listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (listen_fd < 0) {
    log_error("failed to create listen_fd with err: %s", strerror(errno));
    goto cleanup;
  }

  // bind
  struct sockaddr_un addr = {
      .sun_family = AF_UNIX,
  };
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);
  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
    log_error("failed to bind socket to listen_fd with err: %s",
              strerror(errno));
    goto cleanup;
  }

  // listen
  if (listen(listen_fd, MAX_NUM_FE_PROCESSES) == -1) {
    log_error("failed to listen to listen_fd: %d, with err: %s", listen_fd,
              strerror(errno));
    goto cleanup;
  }

  // create epoll fd
  epoll_fd = epoll_create1(0);
  if (epoll_fd < 0) {
    log_error("failed to create epoll_fd with err: %s", strerror(errno));
    goto cleanup;
  }

  // register event to epoll_fd
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = listen_fd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) == -1) {
    log_error("failed to epoll_ctl listen_fd: %d to epoll_fd: %d with err: %s",
              listen_fd, epoll_fd, strerror(errno));
    goto cleanup;
  }

  *out_listen_fd = listen_fd;
  *out_epoll_fd = epoll_fd;
  return true;

cleanup:
  if (listen_fd >= 0)
    close(listen_fd);
  if (epoll_fd >= 0)
    close(epoll_fd);
  unlink(socket_path);
  return false;
}

static int handle_connect_request(int listen_fd, int epoll_fd) {
  // accept client_fd
  int client_fd = accept(listen_fd, NULL, NULL);
  if (client_fd < 0) {
    log_error("failed to accept at handle_connect_request with err: %s",
              strerror(errno));
    return -1;
  }

  // set nonblocking for client_fd
  int flags = fcntl(client_fd, F_GETFL, 0);
  if (flags == -1) {
    log_error("failed to F_GETFL for client_fd: %d with err: %s",
              strerror(errno));
    goto cleanup;
  }
  if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    log_error("failed to F_SETFL O_NONBLOCK for client_fd: %d with err: %s",
              strerror(errno));
    goto cleanup;
  }

  // register to epoll
  struct epoll_event ev = {
      .events = EPOLLIN,
      .data.fd = client_fd,
  };
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
    log_error("failed to add new client_fd: %d to epoll, with err: %s",
              strerror(errno));
    goto cleanup;
  }

  log_trace("successfully connected with client_fd: %d", client_fd);
  return client_fd;

cleanup:
  if (client_fd > 0)
    close(client_fd);
  return -1;
}

static bool handle_fe_msg(int client_fd) {
  enum msg_type_cmd cmd;
  if (!vcrypto_recv(client_fd, &cmd, sizeof(cmd))) {
    log_error("failed to receive client: %d's cmd", client_fd);
    return false;
  }
  switch (cmd) {
  case MSG_TYPE_CREATE_SESS:
    return vcrypto_be_protocol_create_sess(client_fd);
  case MSG_TYPE_REMOVE_SESS:
    return vcrypto_be_protocol_remove_sess(client_fd);
  default:
    log_fatal("Unimplemented!");
    return false;
  }
}

static const char *rte_crypto_op_err_msg(const struct rte_crypto_op *op) {
  char *status_str;
  switch (op->status) {
  case RTE_CRYPTO_OP_STATUS_NOT_PROCESSED:
    status_str = "RTE_CRYPTO_OP_STATUS_NOT_PROCESSED";
    break;
  case RTE_CRYPTO_OP_STATUS_AUTH_FAILED:
    status_str = "RTE_CRYPTO_OP_STATUS_AUTH_FAILED";
    break;
  case RTE_CRYPTO_OP_STATUS_INVALID_SESSION:
    status_str = "RTE_CRYPTO_OP_STATUS_INVALID_SESSION";
    break;
  case RTE_CRYPTO_OP_STATUS_INVALID_ARGS:
    status_str = "RTE_CRYPTO_OP_STATUS_INVALID_ARGS";
    break;
  case RTE_CRYPTO_OP_STATUS_ERROR:
    status_str = "RTE_CRYPTO_OP_STATUS_ERROR";
    break;
  default:
    log_debug("rte_crypto_op_err_msg, but no error");
    status_str = NULL;
  }
  return status_str;
}

int vcrypto_be_mainloop(int listen_fd, int epoll_fd) {
  struct epoll_event events[MAX_NUM_BE_FDS];
  bool client_fds[MAX_NUM_BE_FDS] = {0};
  // in case the expr above did not set client_fds to all 0
  memset(client_fds, 0, sizeof(client_fds) / sizeof(client_fds[0]));
  log_trace("going into mainloop");

  while (running) {
    // ctrontol plane
    int nfds = epoll_wait(epoll_fd, events, MAX_NUM_BE_FDS, -1);
    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == listen_fd) {
        // new connect
        int client_fd = handle_connect_request(listen_fd, epoll_fd);
        if (client_fd < 0) {
          log_error("failed to connect to frontend, don't know what to do");
          continue;
        }
        client_fds[client_fd] = true;
        if (vcrypto_be_protocol_engine_init(client_fd)) {
          log_info("connection handshook with client_fd: %d", client_fd);
        }
      } else if (events[i].events == EPOLLIN) {
        // frontend msg
        int client_fd = events[i].data.fd;
        if (handle_fe_msg(client_fd)) {
          log_trace("success handle msg from client: %d", client_fd);
        }
      } else if (events[i].events & (EPOLLRDHUP | EPOLLERR)) {
        // connection close
        int client_fd = events[i].data.fd;
        close(client_fd);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
        log_info("connection to client: %d is closed", client_fd);
      }
    }

    // data plane
    // dequeue from rx_ring
    struct rte_crypto_op *op = NULL;
    // FIXME: is (void*)&op below safe?
    while (cr->num_valid_ops < MAX_NUM_OPS_PER_BURST &&
           rte_ring_dequeue(cr->rx_ring, (void *)&op) == 0) {
      if (op) {
        cr->ops[cr->num_valid_ops++] = op;
      } else {
        log_debug("dequeue out a NULL ptr");
      }
    }
    if (cr->num_valid_ops > 0) {
      log_trace("dequeued [%d] ops", cr->num_valid_ops);
    }
    // enqueue into cryptodev
    if (cr->num_valid_ops > 0) {
      log_trace("dequeue %d ops from rx_ring", cr->num_valid_ops);
      int num_ops_enqueued = rte_cryptodev_enqueue_burst(
          cr->cdev_id, 0, cr->ops, cr->num_valid_ops);
      int num_ops_left = cr->num_valid_ops - num_ops_enqueued;
      if (num_ops_left > 0) {
        log_debug("not all ops enqueued into cryptodev once, moving the rest "
                  "%d to next round",
                  num_ops_left);
        memmove(cr->ops, cr->ops + num_ops_enqueued, num_ops_left);
      }
      cr->num_valid_ops = num_ops_left;
    }

    // dequeue from cryptodev
    struct rte_crypto_op *ops[MAX_NUM_OPS_PER_BURST] = {0};
    int num_ops_dequeued =
        rte_cryptodev_dequeue_burst(cr->cdev_id, 0, ops, MAX_NUM_OPS_PER_BURST);
    if (num_ops_dequeued > 0) {
      log_trace("dequeued %d ops from cryptodev", num_ops_dequeued);
    }
    for (int i = 0; i < num_ops_dequeued; i++) {
      op = ops[i];
      if (op->status != RTE_CRYPTO_OP_STATUS_SUCCESS) {
        log_error("status of op %p is %s, not success", op,
                  rte_crypto_op_err_msg(op));
        continue;
      }

      // enqueue into tx_ring
      if (rte_ring_enqueue(cr->tx_ring, op) == 0) {
        log_trace("enqueue [%d] op: %p into cr_tx_ring", i, op);
      }
    }
  }

  log_info("vcrypto_be_mainloop is closing, doing resource cleaning...");
  for (int i = 0; i < MAX_NUM_BE_FDS; i++) {
    if (client_fds[i]) {
      log_trace("closing client: %d", i);
      close(i);
      epoll_ctl(epoll_fd, EPOLL_CTL_DEL, i, NULL);
    }
  }
  log_info("all connections in vcrypto_be_mainloop is release");

  return 0;
}

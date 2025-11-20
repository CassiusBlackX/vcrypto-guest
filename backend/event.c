#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#include <unistd.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>

#include <socket.h>
#include <log.h>

#include "event.h"
#include "protocol.h"

volatile sig_atomic_t running = 1;

int make_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool init_server(const char* socket_path, int *out_listen_fd, int *out_epoll_fd) {
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
  if (bind(listen_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
    log_error("failed to bind socket to listen_fd with err: %s", strerror(errno));
    goto cleanup;
  }

  // listen
  if (listen(listen_fd, MAX_NUM_FE_PROCESSES) == -1) {
    log_error("failed to listen to listen_fd: %d, with err: %s", listen_fd, strerror(errno));
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
    log_error("failed to epoll_ctl listen_fd: %d to epoll_fd: %d with err: %s", listen_fd, epoll_fd, strerror(errno));
    goto cleanup;
  }

  *out_listen_fd = listen_fd;
  *out_epoll_fd = epoll_fd;
  return true;

cleanup:
  if (listen_fd >= 0) close(listen_fd);
  if (epoll_fd >= 0) close(epoll_fd);
  unlink(socket_path);
  return false;
}

static int handle_connect_request(int listen_fd, int epoll_fd) {
  // accept client_fd
  int client_fd = accept(listen_fd, NULL, NULL);
  if (client_fd < 0) {
    log_error("failed to accept at handle_connect_request with err: %s", strerror(errno));
    return -1;
  }

  // set nonblocking for client_fd
  int flags = fcntl(client_fd, F_GETFL, 0);
  if (flags == -1) {
    log_error("failed to F_GETFL for client_fd: %d with err: %s", strerror(errno));
    goto cleanup;
  }
  if (fcntl(client_fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    log_error("failed to F_SETFL O_NONBLOCK for client_fd: %d with err: %s", strerror(errno));
    goto cleanup;
  }

  // register to epoll
  struct epoll_event ev = {
    .events = EPOLLIN,
    .data.fd = client_fd,
  };
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) == -1) {
    log_error("failed to add new client_fd: %d to epoll, with err: %s", strerror(errno));
    goto cleanup;
  }

  log_trace("successfully connected with client_fd: %d", client_fd);
  return client_fd;

cleanup:
  if (client_fd > 0) close(client_fd);
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

int mainloop(int listen_fd, int epoll_fd) {
  struct epoll_event events[MAX_NUM_BE_FDS];
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
        if (vcrypto_be_protocol_engine_init(client_fd)) {
          log_trace("connection handshook with client_fd");
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
        
  }
}

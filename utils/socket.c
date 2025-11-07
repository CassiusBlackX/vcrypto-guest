#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>

#include <log.h>

#include "socket.h"

bool vcrypto_socket_set_non_blocking(int fd) {
  int flags = fcntl(fd, F_GETFL, NULL);
  if (flags < 0) {
    log_error("fcntl F_GETFL failed, %s", strerror(errno));
    return false;
  }
  flags |= O_NONBLOCK;
  if (fcntl(fd, F_SETFL, flags) < 0) {
    log_error("fcntl F_SETFL failed, %s", strerror(errno));
    return false;
  }
  return true;
}

int vcrypto_connect(char* socket_file_path) {
  int conn_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);
  if (conn_fd < 0) {
    log_error("failed to create socket with errno: %s", strerror(errno));
    return -1;
  }
  struct sockaddr_un be = {
    .sun_family = AF_UNIX,
  };
  // NOTE: the strlen of `socket_file_path` can be no more than 106!
  if (strlen(socket_file_path) >= sizeof(be.sun_path)) {
    log_error("the strlen of 'socket_file_path' is longer than 'sun_path' can take");
    return -1;
  }
  strncpy(be.sun_path, socket_file_path, sizeof(be.sun_path)-1);
  int len = strlen(be.sun_path) + sizeof(be.sun_family);
  if (connect(conn_fd, (struct sockaddr*)&be, len) == -1) {
    log_error("failed to connect to connfd with current 'socket_file_path'");
    return -1;
  }
  log_trace("connection established");
  return conn_fd;
}

bool vcrypto_recvmsg(int connfd, void* recv_data_buf, int recv_len, int *recv_fd, int num_fd) {
  if (num_fd != 1 && num_fd != 0) {
    log_error("vcrypto_recvmsg error, invali arg num_fd");
    return false;
  }

  struct cmsghdr *cmsghdr = 0;
  struct iovec iov[1];
  iov[0].iov_base = recv_data_buf;
  iov[0].iov_len = recv_len;
  struct msghdr msg = {
    .msg_name = 0,
    .msg_namelen = 0,
    .msg_flags = 0,
    .msg_iov = iov,
    .msg_iovlen = 1,
    .msg_control = 0,
    .msg_controllen = 0,
  };
  int loop_count = 0;
  int recv_len_partial = 0;
  while (recv_len > 0) {
    if (num_fd > 0 && loop_count == 0) {
      char recv_fd_buf[CMSG_SPACE(sizeof(int))] = {0};
      cmsghdr = (struct cmsghdr*)recv_fd_buf;
      cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
      cmsghdr->cmsg_level = SOL_SOCKET;
      cmsghdr->cmsg_type = SCM_RIGHTS;
      msg.msg_control = cmsghdr;
      msg.msg_controllen = CMSG_LEN(sizeof(int));
    } else {
      msg.msg_control = 0;
      msg.msg_controllen = 0;
    }

    recv_len_partial = recvmsg(connfd, &msg, 0);
    if (recv_len_partial < 0) {
      if (errno == EAGAIN) {
        log_info("EAGAIN in vcrypto_recvmsg!");
        continue;
      } else {
        log_error("error in vcrypto_recvmsg, with errno: %s", strerror(errno));
        return false;
      }
    }
    log_trace("recv %d bytes", recv_len_partial);
    recv_len -= recv_len_partial;
    iov[0].iov_base += recv_len_partial;
    iov[0].iov_len = recv_len;
    if (num_fd > 0 && loop_count == 0) {
      *recv_fd = *((int*)CMSG_DATA(cmsghdr));
      log_trace("recv_fd set to %d", *recv_fd);
    }

    loop_count++;
  }
  if (recv_len == 0) {
    log_trace("all msg received in vcrypto_recvmsg!");
    return true;
  } else {
    log_error("not all msg received in vcrypto_recvmsg!");
    return false;
  }
}

bool vcrypto_sendmsg(int connfd, void* send_data_buf, int send_len, int send_fd, int num_fd) {
  if (num_fd != 1 && num_fd != 0) {
    log_error("vcrypto_sendmsg error, invalid arg num_fd");
    return false;
  }

  struct cmsghdr* cmsghdr = 0;
  struct iovec iov[1];
  iov[0].iov_base = send_data_buf;
  iov[0].iov_len = 1;
  struct msghdr msg = {
    .msg_name = 0,
    .msg_namelen = 0,
    .msg_flags = 0,
    .msg_iov = iov,
    .msg_iovlen = 1,
    .msg_control = 0,
    .msg_controllen = 0,
  };
  int loop_count = 0;
  int send_len_partial = 0;
  while (send_len > 0) {
    if (num_fd > 0 && loop_count == 0) {
      char send_fd_buf[CMSG_SPACE(sizeof(int))] = {0};
      cmsghdr = (struct cmsghdr*)send_fd_buf;
      *(int*)CMSG_DATA(cmsghdr) = send_fd;
      cmsghdr->cmsg_len = CMSG_LEN(sizeof(int));
      cmsghdr->cmsg_level = SOL_SOCKET;
      cmsghdr->cmsg_type = SCM_RIGHTS;
      msg.msg_control = cmsghdr;
      msg.msg_controllen = CMSG_LEN(sizeof(int));
    } else {
      msg.msg_control = 0;
      msg.msg_controllen = 0;
    }

    send_len_partial = sendmsg(connfd, &msg, 0);
    if (send_len_partial < 0) {
      if (errno == EAGAIN) {
        log_info("EAGAIN in vcrypto_sendmsg!");
        continue;
      } else {
        log_error("error in vcrypto_sendmsg, with errno: %s", strerror(errno));
        return false;
      }
    }
    log_trace("send %d bytes", send_len_partial);
    send_len -= send_len_partial;
    iov[0].iov_base += send_len_partial;
    iov[0].iov_len = send_len;
    if (num_fd > 0 && 0 == loop_count) {
      log_trace("fd %d sent", send_fd);
    }

    loop_count++;
  }

  if (send_len == 0) {
    log_trace("all msg send in vcrypto_sendmsg!");
    return true;
  } else {
    log_error("not all msg sent in vcrypto_sendmsg!");
    return false;
  }
}

bool vcrypto_recv(int connfd, void* recv_data_buf, int recv_len) {
  int recv_len_partial = 0;
  while (recv_len > 0) {
    recv_len_partial = read(connfd, recv_data_buf, recv_len);
    if (recv_len_partial < 0) {
      if (errno == EAGAIN) {
        log_info("EAGAIN in vcrypto_recv");
        continue;
      } else {
        log_error("error in vcrypto_recv, with errno: %s", strerror(errno));
        return false;
      }
    }
    log_trace("recv %d bytes", recv_len_partial);
    recv_len -= recv_len_partial;
    recv_data_buf += recv_len_partial;  
  }

  if (recv_len == 0) {
    log_trace("all received in vcrypto_recv");
    return true;
  } else {
    log_error("not all received in vcrypto_recv");
    return false;
  }
}

bool vcrypto_send(int connfd, void* send_data_buf, int send_len) {
  int send_len_partial = 0;
  while (send_len > 0) {
    send_len_partial = write(connfd, send_data_buf, send_len);
    if (send_len_partial < 0) {
      if (errno == EAGAIN) {
        log_info("EAGAIN in vcrypto_send");
        continue;
      } else {
        log_error("error in vcrypto_send, with errno: %s", strerror(errno));
        return false;
      }
    }
    log_trace("send %d bytes", send_len_partial);
    send_len -= send_len_partial;
    send_data_buf += send_len_partial;
  }

  if (send_len == 0) {
    log_trace("all received in vcrypto_send");
    return true;
  } else {
    log_error("not all received in vcrypto_send");
    return false;
  }
}

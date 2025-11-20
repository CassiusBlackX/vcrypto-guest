#ifndef VCRYPTO_GUEST_BE_EVENT_H
#define VCRYPTO_GUEST_BE_EVENT_H

#define MAX_NUM_FE_PROCESSES 1024
#define MAX_NUM_BE_FDS 1024*1024
#define SOCKET_FILE_ABSOLUTE_PATH "/tmp/vcrypto_engine.socket"

#include <signal.h>
#include <stdbool.h>

extern volatile sig_atomic_t running;

// return true if server_init success
// else false
bool init_server(const char* socket_path, int *listen_fd, int *epoll_fd);

int vcrypto_be_mainloop(int listen_fd, int epoll_fd);
int mainloop(int listen_fd, int epoll_fd);



#endif  // VCRYPTO_GUEST_BE_EVENT_H

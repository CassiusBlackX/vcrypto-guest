#ifndef VCRYPTO_GUEST_SOCKET
#define VCRYPTO_GUEST_SOCKET

#include <stdbool.h>
#include <stdint.h>

// return true on success, else false
bool vcrypto_socket_set_non_blocking(int fd);
// return conn_fd on success
// return -1 on failure
int vcrypto_connect(char* socket_file_path);
// return true on success, else false
bool vcrypto_recvmsg(int connfd, void* recv_data_buf, int recv_len, int *recv_fd, int num_fd);
// return true on success, else false
bool vcrypto_sendmsg(int connfd, void* send_data_buf, int send_len, int send_fd, int num_fd);
// return true on success, else false
bool vcrypto_recv(int connfd, void* recv_data_buf, int recv_len);
// return true on success, else false
bool vcrypto_send(int connfd, void* send_data_buf, int send_len);


#endif // VCRYPTO_GUEST_SOCKET

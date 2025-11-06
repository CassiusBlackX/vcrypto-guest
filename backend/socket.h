#ifndef VCRYPTO_GUEST_SOCKET
#define VCRYPTO_GUEST_SOCKET

enum vcrypto_be_socket_status {
  VCRYPTO_SOCKET_OK,
  VCRYPTO_SOCKET_ERR,
};

enum vcrypto_be_socket_status vcrypto_socket_set_non_blocking(int fd);
enum vcrypto_be_socket_status vcrypto_recvmsg(int connfd, void* recv_data_buf, int recv_len, int *recv_fd, int num_fd);
enum vcrypto_be_socket_status vcrypto_sendmsg(int connfd, void* send_data_buf, int send_len, int send_fd, int num_fd);
enum vcrypto_be_socket_status vcrypto_recv(int connfd, void* recv_data_buf, int recv_len);
enum vcrypto_be_socket_status vcrypto_send(int connfd, void* send_data_buf, int send_len);


#endif // VCRYPTO_GUEST_SOCKET

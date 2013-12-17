#ifndef ROCKSOCK_SSL_PRIVATE_H
#define ROCKSOCK_SSL_PRIVATE_H

#include "rocksock.h"

const char* rocksock_ssl_strerror(rocksock *sock, int error);
int rocksock_ssl_send(rocksock* sock, char* buf, size_t sz);
int rocksock_ssl_recv(rocksock* sock, char* buf, size_t sz);
int rocksock_ssl_connect_fd(rocksock* sock);
void rocksock_ssl_free_context(rocksock *sock);
int rocksock_ssl_peek(rocksock* sock, int *result);

//RcB: DEP "rocksock_ssl.c"

#endif


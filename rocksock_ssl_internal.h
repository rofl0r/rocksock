#ifndef ROCKSOCK_SSL_PRIVATE_H
#define ROCKSOCK_SSL_PRIVATE_H

#include "rocksock.h"

const char* rocksock_ssl_strerror(rocksock *sock, int error);
int rocksock_ssl_send(rocksock* sock, char* buf, size_t sz);
int rocksock_ssl_recv(rocksock* sock, char* buf, size_t sz);
int rocksock_ssl_connect_fd(rocksock* sock);
void rocksock_ssl_free_context(rocksock *sock);
int rocksock_ssl_peek(rocksock* sock, int *result);
int rocksock_ssl_pending(rocksock *sock);

/* if you want cyassl, put both -DUSE_SSL and -DUSE_CYASSL
   in your CFLAGS.
   for openssl use -DUSE_SSL and -DUSE_OPENSSL.
 */
#ifdef USE_SSL

#ifdef USE_CYASSL
#pragma RcB2 DEP "rocksock_cyassl.c"
#elif defined(USE_OPENSSL)
#pragma RcB2 DEP "rocksock_openssl.c"
#else
#error "need to define one of USE_OPENSSL or USE_CYASSL with -DUSE_SSL"
#endif

#else
#warning "compiling without SSL support"
#pragma RcB2 DEP "rocksock_ssl.c"
#endif

#endif

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
   in your CFLAGS */

// skip the following, if USE_SSL is not given in CFLAGS
//RcB: SKIPUON "USE_SSL"

// skip openssl impl if USE_CYASSL was given.
//RcB: SKIPON "USE_CYASSL"
//RcB: DEP "rocksock_openssl.c"
//RcB: SKIPOFF "USE_CYASSL"

// skip cyassl impl if USE_CYASSL was not given.
//RcB: SKIPUON "USE_CYASSL"
//RcB: DEP "rocksock_cyassl.c"
//RcB: SKIPUOFF "USE_CYASSL"

//RcB: SKIPUOFF "USE_SSL"

#endif


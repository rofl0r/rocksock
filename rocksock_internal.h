#ifndef ROCKSOCK_INTERNAL_H
#define ROCKSOCK_INTERNAL_H

#include "rocksock.h"

typedef struct {
	struct addrinfo* hostaddr;
	struct addrinfo hostaddr_buf;
	struct sockaddr_storage hostaddr_aiaddr_buf;
} rs_resolveStorage;

extern const char* rs_errorMap[];

int rocksock_seterror(rocksock* sock, rs_errorType errortype, int error, const char* file, int line);

#endif

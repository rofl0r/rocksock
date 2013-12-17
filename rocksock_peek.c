/*
 * author: rofl0r (C) 2011-2013
 * License: LGPL 2.1+ with static linking exception
 */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <errno.h>

#include "rocksock.h"
#include "rocksock_internal.h"
#ifdef USE_SSL
#include "rocksock_ssl_internal.h"
#endif

#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

/*
   return value: error code or 0 for no error
   result will contain 0 if no data is available, 1 if data is available.
   if data is available, and a subsequent recv call returns 0 bytes read, the
   connection was terminated. */
int rocksock_peek(rocksock* sock, int *result) {
	ssize_t readv;
	if(!result)
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
	if(sock->ssl) {
#ifdef USE_SSL
		return rocksock_ssl_peek(sock, result);
#else
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NO_SSL, ROCKSOCK_FILENAME, __LINE__);
#endif
	}

	fd_set readfds;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	FD_ZERO(&readfds);
	FD_SET(sock->socket, &readfds);

	readv = select(sock->socket + 1, &readfds, 0, 0, &tv);
	if(readv < 0) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
	*result = FD_ISSET(sock->socket, &readfds);
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

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

#include "rocksock.h"
#include "rocksock_internal.h"

//TODO proper error handling
int rocksock_peek(rocksock* sock) {
	ssize_t readv;
#ifdef USE_SSL
	char buf[4];
	if(sock->ssl)
		readv = SSL_peek(sock->ssl, buf, 1);
	else
#endif

{
	fd_set readfds;

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 1;
	FD_ZERO(&readfds);
	FD_SET(sock->socket, &readfds);
	readv = select(sock->socket + 1, &readfds, NULL, NULL, &tv);
	return FD_ISSET(sock->socket, &readfds);
}

/*	readv = recvfrom(sock->socket, buf, 1, MSG_PEEK | MSG_DONTWAIT | MSG_TRUNC, NULL, NULL);
	if(readv == -1 && errno != EAGAIN) {// && errno != EWOULDBLOCK) {
#ifdef USE_SSL
		if(sock->ssl)
			ERR_print_errors_fp(stderr);
		else
#endif
		perror("peek");
	}
*/
	return readv < 0 ? -1 : !!readv;
}

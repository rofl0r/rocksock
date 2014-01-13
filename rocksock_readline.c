/*
 * author: rofl0r (C) 2011-2013
 * License: LGPL 2.1+ with static linking exception
 */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stddef.h>
#include "rocksock_internal.h"

#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

// tries to read exactly one line, until '\n', then overwrites the \n with \0
// bytesread contains the number of bytes read till \n was encountered
// (so 0 in case \n was the first char).
// returns RS_E_OUT_OF_BUFFER if the line doesnt fit into the buffer.
int rocksock_readline(rocksock* sock, char* buffer, size_t bufsize, size_t* bytesread) {
	// TODO: make more efficient by peeking into the buffer (Flag MSG_PEEK to recv), instead of reading byte by byte
	// would need a different approach for ssl though.
	if (!sock) return RS_E_NULL;
	if (!buffer || !bufsize || !bytesread)
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL,
		                         ROCKSOCK_FILENAME, __LINE__);
	char* ptr = buffer;
	size_t bytesread2 = 0;
	int ret;
	*bytesread = 0;
	while(*bytesread < bufsize) {
		ret = rocksock_recv(sock, ptr, 1, 1, &bytesread2);
		if(ret || !bytesread2) return ret;
		*bytesread += bytesread2;
		if(ptr > buffer + bufsize)
			break;
		if(*bytesread > bufsize) {
			*bytesread = bufsize;
			break;
		}
		if(*ptr == '\n') {
			*ptr = 0;
			*bytesread -= 1;
			return 0;
		}
		ptr++;
	}
	return rocksock_seterror(sock, RS_ET_OWN, RS_E_OUT_OF_BUFFER,
	                         ROCKSOCK_FILENAME, __LINE__);
}

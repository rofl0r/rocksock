#include "rocksock.h"
#include <stdio.h>

char* rocksock_strerror_detailed(rocksock *sock, char *msgbuf, size_t buflen)
{
	snprintf(msgbuf, buflen, "%s (proxy %d)", rocksock_strerror(sock), sock->lasterror.failedProxy);
	return msgbuf;
}

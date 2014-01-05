#include "rocksock.h"
#include "rocksock_internal.h"
#include <string.h>
#ifndef NO_DNS_SUPPORT
#include <netdb.h>
#endif
#ifdef USE_SSL
#include "rocksock_ssl_internal.h"
#endif

const char* rocksock_strerror(rocksock *sock) {
	int error = sock->lasterror.error;
	switch(error) {
#ifndef NO_DNS_SUPPORT
		case RS_ET_GAI:
			return gai_strerror(error);
#endif
		case RS_ET_OWN:
			if (error < RS_E_MAX_ERROR)
				return rs_errorMap[error];
			return 0;
		case RS_ET_SYS:
			return strerror(error);
#ifdef USE_SSL
		case RS_ET_SSL: {
			const char *tmp = rocksock_ssl_strerror(sock, error);
			if(!tmp) return rs_errorMap[RS_E_SSL_GENERIC];
			return tmp;
		}
#endif
		default:
			return 0;
	}
}

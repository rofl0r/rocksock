#include "rocksock.h"

enum rs_errorType rocksock_get_errortype(rocksock *sock) {
	return sock->lasterror.errortype;
}

int rocksock_get_error(rocksock *sock) {
	return sock->lasterror.error;
}


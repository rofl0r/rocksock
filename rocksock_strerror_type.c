#include "rocksock.h"
static const char rs_errortype_map[][9] = {
	[ RS_ET_OWN ]      = "rocksock",
	[ RS_ET_SYS ]      = "system",
	[ RS_ET_GAI ]      = "gai/dns",
	[ RS_ET_SSL ]      = "ssl",
};

const char* rocksock_strerror_type(rocksock *sock) {
	if(sock->lasterror.errortype < RS_ET_MAX)
		return rs_errortype_map[sock->lasterror.errortype];
	return 0;
}

#include "rocksock.h"
#include "rocksock_internal.h"
#include <string.h>
#ifndef NO_DNS_SUPPORT
#include <netdb.h>
#endif
#ifdef USE_SSL
#include "rocksock_ssl_internal.h"
#endif

#ifdef ROCKSOCK_FILENAME
static const char rs_errorMap[][3] = {
	"0" , "1" , "2" , "3" , "4" , "5" , "6" , "7",
	"8" , "9" , "10", "11", "12", "13", "14", "15",
	"16", "17", "18", "19", "20", "21", "22", "23",
	"24",
};

#else

static const char* rs_errorMap[] = {
	// RS_E_NO_ERROR,
	"no error",
	//RS_E_NULL,
	"NULL pointer passed",
	//RS_E_EXCEED_PROXY_LIMIT,
	"exceeding maximum number of proxies",
	//RS_E_NO_SSL,
	"can not establish SSL connection, since library was not compiled with USE_SSL define",
	// RS_E_NO_SOCKET
	"socket is not set up, maybe you should call connect first",
	// RS_E_HIT_TIMEOUT
	"timeout reached on operation",
	//RS_E_OUT_OF_BUFFER
	"supplied buffer is too small",
	// RS_E_SSL_GENERIC
	"generic SSL error, see STDERR",
	// RS_E_SOCKS4_NOAUTH
	"SOCKS4 authentication not implemented",
	// RS_E_SOCKS5_AUTH_EXCEEDSIZE
	"maximum length for SOCKS5 servername/password/username is 255",
	// RS_E_SOCKS4_NO_IP6
	"SOCKS4 is not compatible with IPv6",
	// RS_E_PROXY_UNEXPECTED_RESPONSE
	"the proxy sent an unexpected response",
	// RS_E_TARGETPROXY_CONNECT_FAILED
	"could not connect to target proxy",
	// RS_E_PROXY_AUTH_FAILED
	"proxy authentication failed or authd not enabled",
	//RS_E_HIT_READTIMEOUT = 14,
	"timeout reached on read operation",
	//RS_E_HIT_WRITETIMEOUT = 15,
	"timeout reached on write operation",
	//RS_E_HIT_CONNECTTIMEOUT = 16,
	"timeout reached on connect operation",
	//RS_E_PROXY_GENERAL_FAILURE = 17,
	"proxy general failure",
	//RS_E_TARGETPROXY_NET_UNREACHABLE = 18,
	"proxy-target: net unreachable",
	//RS_E_TARGETPROXY_HOST_UNREACHABLE = 19,
	"proxy-target: host unreachable",
	//RS_E_TARGETPROXY_CONN_REFUSED = 20,
	"proxy-target: connection refused",
	//RS_E_TARGETPROXY_TTL_EXPIRED = 21,
	"proxy-target: TTL expired",
	//RS_E_PROXY_COMMAND_NOT_SUPPORTED = 22,
	"proxy: command not supported",
	//RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED = 23,
	"proxy: addresstype not supported",
	//RS_E_REMOTE_DISCONNECTED = 24,
	"remote socket closed connection",
};

#endif

const char* rocksock_strerror(rocksock *sock) {
	int error = sock->lasterror.error;
	switch(sock->lasterror.errortype) {
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

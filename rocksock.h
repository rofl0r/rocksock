/*
 * author: rofl0r
 * License: LGPL 2.1+ with static linking exception
 */

#ifndef _ROCKSOCK_H_
#define _ROCKSOCK_H_

#include <stddef.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#define MAX_PROXIES 16

typedef enum {
	RS_PT_NONE = 0,
	RS_PT_SOCKS4,
	RS_PT_SOCKS5,
	RS_PT_HTTP
} rs_proxyType;

typedef enum {
	RS_ET_OWN = 0,
	RS_ET_SYS,
	RS_ET_GAI,
	RS_ET_SSL,
	RS_ET_MAX
} rs_errorType;

typedef enum {
	RS_E_NO_ERROR = 0,
	RS_E_NULL = 1,
	RS_E_EXCEED_PROXY_LIMIT = 2,
	RS_E_NO_SSL = 3,
	RS_E_NO_SOCKET = 4,
	RS_E_HIT_TIMEOUT = 5,
	RS_E_OUT_OF_BUFFER = 6,
	RS_E_SSL_GENERIC = 7,
	RS_E_SOCKS4_NOAUTH = 8,
	RS_E_SOCKS5_AUTH_EXCEEDSIZE = 9,
	RS_E_SOCKS4_NO_IP6 = 10,
	RS_E_PROXY_UNEXPECTED_RESPONSE = 11,
	RS_E_TARGETPROXY_CONNECT_FAILED = 12,
	RS_E_PROXY_AUTH_FAILED = 13,
	RS_E_HIT_READTIMEOUT = 14,
	RS_E_HIT_WRITETIMEOUT = 15,
	RS_E_HIT_CONNECTTIMEOUT = 16,
	RS_E_PROXY_GENERAL_FAILURE = 17,
	RS_E_TARGETPROXY_NET_UNREACHABLE = 18,
	RS_E_TARGETPROXY_HOST_UNREACHABLE = 19,
	RS_E_TARGETPROXY_CONN_REFUSED = 20,
	RS_E_TARGETPROXY_TTL_EXPIRED = 21,
	RS_E_PROXY_COMMAND_NOT_SUPPORTED = 22,
	RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED = 23,
	RS_E_REMOTE_DISCONNECTED = 24,
	RS_E_MAX_ERROR = 25
} rs_error;

typedef struct {
	rs_errorType errortype;
	int error;
	int line;
	const char* file;
	int failedProxy;
} rs_errorInfo;

typedef struct {
	char* host;
	unsigned short port;
} rs_hostInfo;

typedef struct {
	rs_proxyType proxytype;
	rs_hostInfo hostinfo;
	char* username;
	char* password;
} rs_proxy;

typedef struct {
	int socket;
	int connected;
	unsigned long timeout;
	rs_proxy proxies[MAX_PROXIES];
	ptrdiff_t lastproxy;
	rs_hostInfo hostinfo;
	rs_errorInfo lasterror;
	void *ssl;
	void *sslctx;
} rocksock;

#ifdef __cplusplus
extern "C" {
#endif

#if 1 /* only available if USE_SSL was activated at build time */
void rocksock_init_ssl(void);
void rocksock_free_ssl(void);
#endif

/* all rocksock functions that return int return 0 on success or an errornumber on failure */
int rocksock_init(rocksock* sock);
int rocksock_set_timeout(rocksock* sock, unsigned long timeout_millisec);
int rocksock_add_proxy(rocksock* sock, rs_proxyType proxytype, char* host, unsigned short port, char* username, char* password);
int rocksock_connect(rocksock* sock, char* host, unsigned short port, int useSSL);
int rocksock_send(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* byteswritten);
int rocksock_recv(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* bytesread);
int rocksock_readline(rocksock* sock, char* buffer, size_t bufsize, size_t* bytesread);
int rocksock_disconnect(rocksock* sock);

/* returns a string describing the last error or NULL */
const char* rocksock_strerror(rocksock *sock);
/* return a string describing in which subsytem the last error happened, or NULL */
const char* rocksock_strerror_type(rocksock *sock);

/* clears/free's/resets all internally used buffers. etc but doesn't free the rocksock itself, since it could be stack-alloced */
int rocksock_clear(rocksock* sock);
/* check if data is available for read. result will contain 1 if available, 0 if not available.
   return value 0 indicates success, everything else error. result may not be NULL */
int rocksock_peek(rocksock* sock, int *result);

/* using these two pulls in malloc from libc - only matters if you static link and dont use SSL */
/* returns a new heap alloced rocksock object which must be passed to rocksock_init later on */
rocksock* rocksock_new(void);
/* free *only* the rocksock object. typically you would call rocksock_clear first */
void rocksock_free(rocksock* s);

#ifdef __cplusplus
}
#endif

#endif

//RcB: DEP "rocksock.c"
//RcB: DEP "rocksock_add_proxy.c"
//RcB: DEP "rocksock_strerror.c"
//RcB: DEP "rocksock_strerror_type.c"
//RcB: DEP "rocksock_dynamic.c"
//RcB: DEP "rocksock_readline.c"
//RcB: DEP "rocksock_peek.c"


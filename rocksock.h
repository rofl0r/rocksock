/*
 * 
 * author: rofl0r
 * 
 * License: LGPL 2.1+ with static linking exception
 * 
 * 
 */

#ifndef _ROCKSOCK_H_
#define _ROCKSOCK_H_

#ifdef USE_SSL
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h> 
#endif

#include <stddef.h>
#include <netdb.h>

#define MAX_PROXIES 16

typedef enum {
	RS_PT_NONE = 0,
	RS_PT_SOCKS4,
	RS_PT_SOCKS5,
	RS_PT_HTTP
} rs_proxyType;

typedef enum {
	RS_ET_NO_ERROR = 0,
	RS_ET_OWN,
	RS_ET_SYS,
	RS_ET_GAI,
	RS_ET_SSL,
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
	RS_E_MAX_ERROR = 17
} rs_error;

typedef struct {
	char* errormsg;
	rs_errorType errortype;
	int error;
	int line;
	const char* file;
	int failedProxy;
} rs_errorInfo;

typedef struct {
	char* host;
	short port;
	struct addrinfo* hostaddr;
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
	size_t timeout;
	rs_proxy proxies[MAX_PROXIES];
	ptrdiff_t lastproxy;
	rs_hostInfo hostinfo;
	rs_errorInfo lasterror;
#ifdef USE_SSL
	SSL* ssl;
	SSL_CTX* sslctx;
#endif
} rocksock;

#ifdef __cplusplus
extern "C" {
#endif	

#ifdef USE_SSL
void rocksock_init_ssl(void);
void rocksock_free_ssl(void);
#endif
int rocksock_init(rocksock* sock);
int rocksock_set_timeout(rocksock* sock, size_t timeout_millisec);
int rocksock_add_proxy(rocksock* sock, rs_proxyType proxytype, char* host, short port, char* username, char* password);
int rocksock_connect(rocksock* sock, char* host, short port, int useSSL);
int rocksock_send(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* byteswritten);
int rocksock_recv(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* bytesread);
int rocksock_readline(rocksock* sock, char* buffer, size_t bufsize, size_t* bytesread);
int rocksock_disconnect(rocksock* sock);
int rocksock_free(rocksock* sock);

#ifdef __cplusplus
}
#endif

#endif

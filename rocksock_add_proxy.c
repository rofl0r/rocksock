#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <string.h>

#include "rocksock.h"
#include "rocksock_internal.h"

#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

int rocksock_add_proxy(rocksock* sock, rs_proxyType proxytype, char* host, unsigned short port, char* username, char* password) {
	rs_proxy* prx;
	if (!sock)
		return RS_E_NULL;
	if(sock->lastproxy+1 >= MAX_PROXIES)
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_EXCEED_PROXY_LIMIT, ROCKSOCK_FILENAME, __LINE__);
	if(!host)
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
	if(proxytype == RS_PT_SOCKS4 && (username || password))
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS4_NOAUTH, ROCKSOCK_FILENAME, __LINE__);
	if(proxytype == RS_PT_SOCKS5 && ((username && strlen(username) > 255) || (password && strlen(password) > 255)))
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS5_AUTH_EXCEEDSIZE, ROCKSOCK_FILENAME, __LINE__);
	sock->lastproxy++;
	prx = &sock->proxies[sock->lastproxy];
	prx->hostinfo.port = port;
	prx->proxytype = proxytype;
#ifndef NO_STRDUP
	prx->hostinfo.host = strdup(host);
	prx->username = username ? strdup(username) : NULL;
	prx->password = password ? strdup(password) : NULL;
#else
	prx->hostinfo.host = host;
	prx->username = username;
	prx->password = password;
#endif
	return rocksock_seterror(sock, RS_ET_OWN, 0, NULL, 0);
}


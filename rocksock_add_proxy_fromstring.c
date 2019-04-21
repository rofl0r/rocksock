#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <string.h>
#include <stdlib.h> /* for atoi() */

#include "rocksock.h"
#include "rocksock_internal.h"

#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

/* valid inputs:
	socks5://user:password@proxy.domain.com:port
	socks5://proxy.domain.com:port
	socks4://proxy.domain.com:port
	http://user:password@proxy.domain.com:port
	http://proxy.domain.com:port

	supplying port number is obligatory.
	user:pass@ part is optional for http and socks5.
	however, user:pass authentication is currently not implemented for http proxies.
*/
#define MKERR(S, X) rocksock_seterror(S, RS_ET_OWN, X, ROCKSOCK_FILENAME, __LINE__)
int rocksock_add_proxy_fromstring(rocksock* sock, const char *proxystring) {
	if (!sock)
		return RS_E_NULL;
	if(!sock->proxies) return MKERR(sock, RS_E_NO_PROXYSTORAGE);

	const char* p;
	rs_proxyType proxytype;
	rs_proxy* prx = &sock->proxies[sock->lastproxy+1];
	char *user_buf = prx->username;
	char *pass_buf = prx->password;
	char *host_buf = prx->hostinfo.host;
	size_t next_token = 6, ul = 0, pl = 0, hl;
	if(!proxystring[0] || !proxystring[1] || !proxystring[2] || !proxystring[3] || !proxystring[4] || !proxystring[5]) goto inv_string;
	if(*proxystring == 's') {
		switch(proxystring[5]) {
			case '5': proxytype = RS_PT_SOCKS5; break;
			case '4': proxytype = RS_PT_SOCKS4; break;
			default: goto inv_string;
		}
	} else if(*proxystring == 'h') {
		proxytype = RS_PT_HTTP;
		next_token = 4;
	} else goto inv_string;
	if(
	   proxystring[next_token++] != ':' ||
	   proxystring[next_token++] != '/' ||
	   proxystring[next_token++] != '/') goto inv_string;
	const char *at = strrchr(proxystring+next_token, '@');
	if(at) {
		if(proxytype == RS_PT_SOCKS4)
			return MKERR(sock, RS_E_SOCKS4_NOAUTH);
		p = strchr(proxystring+next_token, ':');
		if(!p || p >= at) goto inv_string;
		const char *u = proxystring+next_token;
		ul = p-u;
		p++;
		pl = at-p;
		if(proxytype == RS_PT_SOCKS5 && (ul > 255 || pl > 255))
			return MKERR(sock, RS_E_SOCKS5_AUTH_EXCEEDSIZE);
		memcpy(user_buf, u, ul);
		user_buf[ul]=0;
		memcpy(pass_buf, p, pl);
		pass_buf[pl]=0;
		next_token += 2+ul+pl;
	} else {
		user_buf[0]=0;
		pass_buf[0]=0;
	}
	const char* h = proxystring+next_token;
	p = strchr(h, ':');
	if(!p) goto inv_string;
	hl = p-h;
	if(hl > 255)
		return MKERR(sock, RS_E_HOSTNAME_TOO_LONG);
	memcpy(host_buf, h, hl);
	host_buf[hl]=0;
	sock->lastproxy++;
	prx->hostinfo.port = atoi(p+1);
	prx->proxytype = proxytype;
	return rocksock_seterror(sock, RS_ET_OWN, 0, NULL, 0);
inv_string:
	return MKERR(sock, RS_E_INVALID_PROXY_URL);
}


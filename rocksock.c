/*
 * author: rofl0r (C) 2011-2013
 * License: LGPL 2.1+ with static linking exception
 */

/*
 * recognized defines: USE_SSL, ROCKSOCK_FILENAME, NO_DNS_SUPPORT, NO_STRDUP
 */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include <netinet/in.h>

#include "rocksock.h"
#include "rocksock_internal.h"
#ifdef USE_LIBULZ
//RcB: SKIPUON "USE_LIBULZ"
#include <ulz/strlib.h>
#include <ulz/stdio-repl.h>
//RcB: SKIPUOFF "USE_LIBULZ"
#else
/* this version of ipv4fromstring was taken from libulz and tuned to be
   more pedantic than the libulz version, so it can be used for isnumericipv4()
   as well, as it strictly checks the input for correctness. */
static int ipv4fromstring(const char* ipstring, unsigned char* fourbytesptr) {
	const char* start = ipstring;
	size_t outbyte = 0;
	while(outbyte < 4) {
		if(*ipstring == '.' || !*ipstring) {
			fourbytesptr[outbyte] = 0;
			size_t b = 0;
			unsigned tmp;
			switch(ipstring - start) {
			case 3:
				tmp = (start[b++]-'0')*100;
				if(tmp > 200) return 0;
				fourbytesptr[outbyte] += tmp;
			case 2:
				fourbytesptr[outbyte] += (start[b++]-'0')*10;
			case 1:
				fourbytesptr[outbyte] += (start[b++]-'0');
				break;
			default:
				return 0;
			}
			start = ipstring + 1;
			outbyte++;
		} else {
			if(*ipstring < '0' || *ipstring > '9') return 0;
		}
		if(!*ipstring && outbyte < 4) return 0;
		ipstring++;
	}
	if(ipstring[-1]) return 0;
	return 1;
}

static int isnumericipv4(const char* ipstring) {
	unsigned char ip[4];
	return ipv4fromstring(ipstring, ip);
}
#endif

#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef USE_SSL
#include "rocksock_ssl_internal.h"
#endif

int rocksock_seterror(rocksock* sock, rs_errorType errortype, int error, const char* file, int line) {
	if (!sock) return RS_E_NULL;
	sock->lasterror.errortype = errortype;
	sock->lasterror.error = error;
	sock->lasterror.line = line;
	sock->lasterror.file = file;
	sock->lasterror.failedProxy = -1;
	switch(errortype) {
#ifndef NO_DNS_SUPPORT
		case RS_ET_GAI:
			sock->lasterror.errormsg = (char*) gai_strerror(error);
			break;
#endif
		case RS_ET_OWN:
			if (error < RS_E_MAX_ERROR)
				sock->lasterror.errormsg = (char*) rs_errorMap[error];
			else
				sock->lasterror.errormsg = NULL;
			break;
		case RS_ET_SYS:
			sock->lasterror.errormsg = strerror(error);
			break;
#ifdef USE_SSL
		case RS_ET_SSL:
			sock->lasterror.errormsg = (char*) rocksock_ssl_strerror(sock, error);
			if(!sock->lasterror.errormsg) sock->lasterror.errormsg = (char*) rs_errorMap[RS_E_SSL_GENERIC];
			break;
#endif
		default:
			sock->lasterror.errormsg = NULL;
			break;
	}
	return error;
}
//#define NO_DNS_SUPPORT
static int rocksock_resolve_host(rocksock* sock, rs_hostInfo* hostinfo, rs_resolveStorage* result) {
	if (!sock) return RS_E_NULL;
	if (!hostinfo || !hostinfo->host || !hostinfo->port) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);;

	result->hostaddr = &(result->hostaddr_buf);

#ifndef NO_DNS_SUPPORT
	struct addrinfo hints = {.ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM, .ai_flags = AI_ADDRCONFIG};
	int ret;
	struct addrinfo *best, *save;
	ret = getaddrinfo(hostinfo->host, NULL, &hints, &save);
	if(!ret) {
		best = save;
		while(best->ai_addr->sa_family == AF_INET6 && best->ai_next) best = best->ai_next;
		*result->hostaddr = *best;
		result->hostaddr->ai_addr = (struct sockaddr*) &(result->hostaddr_aiaddr_buf);
		result->hostaddr->ai_next = 0;
		*result->hostaddr->ai_addr = *best->ai_addr;

		if(result->hostaddr->ai_addr->sa_family == AF_INET)
			((struct sockaddr_in*) result->hostaddr->ai_addr)->sin_port = htons(hostinfo->port);
		else
			((struct sockaddr_in6*) result->hostaddr->ai_addr)->sin6_port = htons(hostinfo->port);
		freeaddrinfo(save);
		return 0;
	} else
		return rocksock_seterror(sock, RS_ET_GAI, ret, ROCKSOCK_FILENAME, __LINE__);
#else
	result->hostaddr->ai_addr = (struct sockaddr*) &(result->hostaddr_aiaddr_buf);

	((struct sockaddr_in*) result->hostaddr->ai_addr)->sin_port = htons(hostinfo->port);
	((struct sockaddr_in*) result->hostaddr->ai_addr)->sin_family = AF_INET;
	result->hostaddr->ai_addr->sa_family = AF_INET;
	result->hostaddr->ai_addrlen = sizeof(struct sockaddr_in);
	ipv4fromstring(hostinfo->host, (unsigned char*) &((struct sockaddr_in*) result->hostaddr->ai_addr)->sin_addr);

	return 0;
#endif
}

int rocksock_set_timeout(rocksock* sock, unsigned long timeout_millisec) {
	if (!sock) return RS_E_NULL;
	sock->timeout = timeout_millisec;
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_init(rocksock* sock) {
	if (!sock) return RS_E_NULL;
	memset(sock, 0, sizeof(rocksock));
	sock->lastproxy = -1;
	sock->timeout = 60*1000;
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

static struct timeval* make_timeval(struct timeval* tv, unsigned long timeout) {
	if(!tv) return NULL;
	tv->tv_sec = timeout / 1000;
	tv->tv_usec = 1000 * (timeout % 1000);
	return tv;
}

static int do_connect(rocksock* sock, rs_resolveStorage* hostinfo, unsigned long timeout) {
	int flags, ret;
	fd_set wset;
	struct timeval tv;
	int optval;
	socklen_t optlen = sizeof(optval);

	sock->socket = socket(hostinfo->hostaddr->ai_family, SOCK_STREAM, 0);
	if(sock->socket == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);

	/* the socket has to be made non-blocking temporarily so we can enforce a connect timeout */
	flags = fcntl(sock->socket, F_GETFL);
	if(flags == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);

	if(fcntl(sock->socket, F_SETFL, flags | O_NONBLOCK) == -1) return errno;

	ret = connect(sock->socket, hostinfo->hostaddr->ai_addr, hostinfo->hostaddr->ai_addrlen);
	if(ret == -1) {
		ret = errno;
		if (!(ret == EINPROGRESS || ret == EWOULDBLOCK)) return rocksock_seterror(sock, RS_ET_SYS, ret, ROCKSOCK_FILENAME, __LINE__);
	}

	if(fcntl(sock->socket, F_SETFL, flags) == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);

	FD_ZERO(&wset);
	FD_SET(sock->socket, &wset);

	ret = select(sock->socket+1, NULL, &wset, NULL, timeout ? make_timeval(&tv, timeout) : NULL);

	if(ret == 1 && FD_ISSET(sock->socket, &wset)) {
		ret = getsockopt(sock->socket, SOL_SOCKET, SO_ERROR, &optval,&optlen);
		if(ret == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
		else if(optval) return rocksock_seterror(sock, RS_ET_SYS, optval, ROCKSOCK_FILENAME, __LINE__);
		return 0;
	} else if(ret == 0) return rocksock_seterror(sock, RS_ET_OWN, RS_E_HIT_CONNECTTIMEOUT, ROCKSOCK_FILENAME, __LINE__);

	return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
}

static int rocksock_setup_socks4_header(rocksock* sock, int is4a, char* buffer, size_t bufsize, rs_proxy* proxy, size_t* bytesused) {
	int ret;
	buffer[0] = 4;
	buffer[1] = 1;
	buffer[2] = proxy->hostinfo.port / 256;
	buffer[3] = proxy->hostinfo.port % 256;

	if(is4a) {
		buffer[4] = 0;
		buffer[5] = 0;
		buffer[6] = 0;
		buffer[7] = 1;
	} else {
		rs_resolveStorage stor;
		ret = rocksock_resolve_host(sock, &proxy->hostinfo, &stor);
		if(ret) return ret;
		if(stor.hostaddr->ai_family != AF_INET)
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS4_NO_IP6, ROCKSOCK_FILENAME, __LINE__);
		buffer[4] = ((char*) &(((struct sockaddr_in*) stor.hostaddr->ai_addr)->sin_addr.s_addr))[0];
		buffer[5] = ((char*) &(((struct sockaddr_in*) stor.hostaddr->ai_addr)->sin_addr.s_addr))[1];
		buffer[6] = ((char*) &(((struct sockaddr_in*) stor.hostaddr->ai_addr)->sin_addr.s_addr))[2];
		buffer[7] = ((char*) &(((struct sockaddr_in*) stor.hostaddr->ai_addr)->sin_addr.s_addr))[3];
	}
	buffer[8] = 0;
	*bytesused = 9;
	if(is4a) *bytesused += strlen(strncpy(buffer + *bytesused, proxy->hostinfo.host, bufsize - *bytesused))+1;

	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_connect(rocksock* sock, char* host, unsigned short port, int useSSL) {
	ptrdiff_t px;
	int ret, trysocksv4a;
	rs_hostInfo* connector;
	rs_proxy dummy;
	rs_proxy* targetproxy;
	char socksdata[768];
	char* p;
	size_t socksused = 0, bytes;
	if (!sock) return RS_E_NULL;
	if (!host || !port)
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
#ifndef USE_SSL
	if (useSSL) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NO_SSL, ROCKSOCK_FILENAME, __LINE__);
#endif
#ifdef NO_STRDUP
	sock->hostinfo.host = host;
#else
	sock->hostinfo.host = strdup(host);
#endif
	sock->hostinfo.port = port;

	if(sock->lastproxy >= 0)
		connector = &sock->proxies[0].hostinfo;
	else
		connector = &sock->hostinfo;

	rs_resolveStorage stor;

	ret = rocksock_resolve_host(sock, connector, &stor);
	if(ret) {
		check_proxy0_failure:
		if(sock->lastproxy >= 0) sock->lasterror.failedProxy = 0;
		return ret;
	}

	ret = do_connect(sock, &stor, sock->timeout);
	if(ret) goto check_proxy0_failure;

	if(sock->lastproxy >= 0) {
		dummy.hostinfo = sock->hostinfo;
		dummy.password = NULL;
		dummy.username = NULL;
		dummy.proxytype = RS_PT_NONE;
		for(px = 0; px <= sock->lastproxy; px++) {
			if(px == sock->lastproxy)
				targetproxy = &dummy;
			else
				targetproxy = &sock->proxies[px + 1];
			// send socks connection data
			switch(sock->proxies[px].proxytype) {
				case RS_PT_SOCKS4:
					trysocksv4a = 1;
					trysocks4:
					ret = rocksock_setup_socks4_header(sock, trysocksv4a, socksdata, sizeof(socksdata), targetproxy, &socksused);
					if(ret) {
						proxyfailure:
						sock->lasterror.failedProxy = px;
						return ret;
					}
					ret = rocksock_send(sock, socksdata, socksused, 0, &bytes);
					if(ret) goto proxyfailure;
					ret = rocksock_recv(sock, socksdata, 8, 8, &bytes);
					if(ret) goto proxyfailure;
					if(bytes < 8 || socksdata[0] != 0) {
						ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
						goto proxyfailure;
					}
					switch(socksdata[1]) {
						case 0x5a:
							break;
						case 0x5b:
							if(trysocksv4a) {
								trysocksv4a = 0;
								goto trysocks4;
							}
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_CONNECT_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 0x5c: case 0x5d:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						default:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					break;
				case RS_PT_SOCKS5:
					p = socksdata;
					*p++ = 5;
					if(sock->proxies[px].username && sock->proxies[px].password) {
						*p++ = 2;
						*p++ = 0;
						*p++ = 2;
					} else {
						*p++ = 1;
						*p++ = 0;
					}
					bytes = p - socksdata;
					ret = rocksock_send(sock, socksdata, bytes, bytes, &bytes);
					if(ret) goto proxyfailure;
					ret = rocksock_recv(sock, socksdata, 2, 2, &bytes);
					if(ret) goto proxyfailure;
					if(bytes < 2 || socksdata[0] != 5) {
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					if(socksdata[1] == '\xff') {
						ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
						goto proxyfailure;
					} else if (socksdata[1] == 2) {
						if( sock->proxies[px].username &&  sock->proxies[px].password &&
						   *sock->proxies[px].username && *sock->proxies[px].password) {
							/*
							+----+------+----------+------+----------+
							|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
							+----+------+----------+------+----------+
							| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
							+----+------+----------+------+----------+
							*/
							p = socksdata;
							*p++ = 1;
							bytes = strlen(sock->proxies[px].username) & 0xFF;
							*p++ = bytes;
							memcpy(p, sock->proxies[px].username, bytes);
							p += bytes;
							bytes = strlen(sock->proxies[px].password) & 0xFF;
							*p++ = bytes;
							memcpy(p, sock->proxies[px].password, bytes);
							p += bytes;
							bytes = p - socksdata;
							ret = rocksock_send(sock, socksdata, bytes, bytes, &bytes);
							if(ret) goto proxyfailure;
							ret = rocksock_recv(sock, socksdata, 2, 2, &bytes);
							if(ret) goto proxyfailure;
							if(bytes < 2) {
									ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
									goto proxyfailure;
							} else if(socksdata[1] != 0) {
								ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
								goto proxyfailure;
							}
						} else {
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						}
					}
					p = socksdata;
					*p++ = 5;
					*p++ = 1;
					*p++ = 0;
					if(isnumericipv4(targetproxy->hostinfo.host)) {
						*p++ = 1; // ipv4 method
						bytes = 4;
						ipv4fromstring(targetproxy->hostinfo.host, (unsigned char*) p);
					} else {
						*p++ = 3; //hostname method, requires the server to do dns lookups.
						bytes = strlen(targetproxy->hostinfo.host);
						if(bytes > 255)
							return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS5_AUTH_EXCEEDSIZE, ROCKSOCK_FILENAME, __LINE__);
						*p++ = bytes;
						memcpy(p, targetproxy->hostinfo.host, bytes);
					}
					p+=bytes;
					*p++ = targetproxy->hostinfo.port / 256;
					*p++ = targetproxy->hostinfo.port % 256;
					bytes = p - socksdata;
					ret = rocksock_send(sock, socksdata, bytes, bytes, &bytes);
					if(ret) goto proxyfailure;
					ret = rocksock_recv(sock, socksdata, sizeof(socksdata), sizeof(socksdata), &bytes);
					if(ret) goto proxyfailure;
					if(bytes < 2) {
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					switch(socksdata[1]) {
						case 0:
							break;
						case 1:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_GENERAL_FAILURE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 2:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 3:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_NET_UNREACHABLE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 4:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_HOST_UNREACHABLE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 5:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_CONN_REFUSED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 6:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_TTL_EXPIRED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 7:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_COMMAND_NOT_SUPPORTED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 8:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_ADDRESSTYPE_NOT_SUPPORTED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						default:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					break;
				case RS_PT_HTTP:
					bytes = snprintf(socksdata, sizeof(socksdata), "CONNECT %s:%d HTTP/1.1\r\n\r\n", targetproxy->hostinfo.host, targetproxy->hostinfo.port);
					ret = rocksock_send(sock, socksdata, bytes, bytes, &bytes);
					if(ret) goto proxyfailure;
					ret = rocksock_recv(sock, socksdata, sizeof(socksdata), sizeof(socksdata), &bytes);
					if(ret) goto proxyfailure;
					if(bytes < 12) {
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_UNEXPECTED_RESPONSE, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					if(socksdata[9] != '2') {
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_CONNECT_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
					}
					break;
				default:
					break;
			}
		}
	}
#ifdef USE_SSL
	if(useSSL) {
		ret = rocksock_ssl_connect_fd(sock);
		if(ret) return ret;
	}
#endif
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

typedef enum  {
	RS_OT_SEND = 0,
	RS_OT_READ
} rs_operationType;

static int rocksock_operation(rocksock* sock, rs_operationType operation, char* buffer, size_t bufsize, size_t chunksize, size_t* bytes) {
	if (!sock) return RS_E_NULL;
	if (!buffer || !bytes || (!bufsize && operation == RS_OT_READ)) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
	*bytes = 0;
	struct timeval tv;
	fd_set fd;
	fd_set* rfd = NULL;
	fd_set* wfd = NULL;
	int ret = 0;
	size_t bytesleft = bufsize ? bufsize : strlen(buffer);
	size_t byteswanted;
	char* bufptr = buffer;

	if (!sock->socket) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NO_SOCKET, ROCKSOCK_FILENAME, __LINE__);
	if(operation == RS_OT_SEND) wfd = &fd;
	else rfd = &fd;

	if(sock->timeout) {
		if(operation == RS_OT_SEND)
			ret = setsockopt(sock->socket, SOL_SOCKET, SO_SNDTIMEO, (void*) make_timeval(&tv, sock->timeout), sizeof(tv));
		else
			ret = setsockopt(sock->socket, SOL_SOCKET, SO_RCVTIMEO, (void*) make_timeval(&tv, sock->timeout), sizeof(tv));
	}

	if (ret == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);

	while(bytesleft) {
		byteswanted = (chunksize && chunksize < bytesleft) ? chunksize : bytesleft;
#ifdef USE_SSL
		if (sock->ssl) {
			if(operation == RS_OT_SEND)
				ret = rocksock_ssl_send(sock, bufptr, byteswanted);
			else
				ret = rocksock_ssl_recv(sock, bufptr, byteswanted);

		} else {
#endif
		/* enforce the timeout by using select() before doing the actual recv/send */
		FD_SET(sock->socket, &fd);
		ret=select(sock->socket+1, rfd, wfd, NULL, sock->timeout ? make_timeval(&tv, sock->timeout) : NULL);
		if(!FD_ISSET(sock->socket, &fd)) rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__); // temp test
		if(ret == -1) {
			//printf("h: %s, skt: %d, to: %d:%d\n", sock->hostinfo.host, sock->socket, tv.tv_sec, tv.tv_usec);
			return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
		}
		else if(!ret) return rocksock_seterror(sock, RS_ET_OWN, RS_OT_READ ? RS_E_HIT_READTIMEOUT : RS_E_HIT_WRITETIMEOUT, ROCKSOCK_FILENAME, __LINE__);

		if(operation == RS_OT_SEND)
			ret = send(sock->socket, bufptr, byteswanted, MSG_NOSIGNAL);
		else
			ret = recv(sock->socket, bufptr, byteswanted, 0);

#ifdef USE_SSL
		}
#endif

		if(!ret) // The return value will be 0 when the peer has performed an orderly shutdown.
			//return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
			break;
		else if(ret == -1) {
			ret = errno;
			if(ret == EWOULDBLOCK || ret == EINPROGRESS) return rocksock_seterror(sock, RS_ET_OWN, RS_OT_READ ? RS_E_HIT_READTIMEOUT : RS_E_HIT_WRITETIMEOUT, ROCKSOCK_FILENAME, __LINE__);
			return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
		}

		bytesleft -= ret;
		bufptr += ret;
		*bytes += ret;
		if(operation == RS_OT_READ && (size_t) ret < byteswanted) break;
	}
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_send(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* byteswritten) {
	return rocksock_operation(sock, RS_OT_SEND, buffer, bufsize, chunksize, byteswritten);
}

int rocksock_recv(rocksock* sock, char* buffer, size_t bufsize, size_t chunksize, size_t* bytesread) {
	return rocksock_operation(sock, RS_OT_READ, buffer, bufsize, chunksize, bytesread);
}

int rocksock_disconnect(rocksock* sock) {
	if (!sock) return RS_E_NULL;
#ifdef USE_SSL
	rocksock_ssl_free_context(sock);
#endif
	if(sock->socket) close(sock->socket);
	sock->socket = 0;
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_clear(rocksock* sock) {
	if (!sock) return RS_E_NULL;
	ptrdiff_t i;
	if(sock->lastproxy >= 0) {
		for (i=0;i<=sock->lastproxy;i++) {
#ifndef NO_STRDUP
			if(sock->proxies[i].username)
				free(sock->proxies[i].username);
			if(sock->proxies[i].password)
				free(sock->proxies[i].password);
			if(sock->proxies[i].hostinfo.host)
				free(sock->proxies[i].hostinfo.host);
#endif
			sock->proxies[i].username = NULL;
			sock->proxies[i].password = NULL;
			sock->proxies[i].hostinfo.host = NULL;
		}
	}
#ifndef NO_STRDUP
	if(sock->hostinfo.host)
		free(sock->hostinfo.host);
#endif
	sock->hostinfo.host = NULL;

	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}


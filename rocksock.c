/*
 * 
 * author: rofl0r
 * 
 * License: LGPL 2.1+ with static linking exception
 * 
 * 
 */

#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include "rocksock.h"

#ifdef ROCKSOCK_FILENAME
static const char* rs_errorMap[] = {
	"0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16"
};

#else
#define ROCKSOCK_FILENAME __FILE__

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

};

#endif

#ifdef USE_SSL
	
void rocksock_init_ssl(void) {
	SSL_library_init();
	SSL_load_error_strings();
	SSLeay_add_ssl_algorithms();
}

void rocksock_free_ssl(void) {
	// TODO: there are still 3 memblocks allocated from SSL_library_init (88 bytes)
	ERR_remove_state(0);
	ERR_free_strings();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
}

#endif

int rocksock_seterror(rocksock* sock, rs_errorType errortype, int error, const char* file, int line) {
	if (!sock) return RS_E_NULL;
	sock->lasterror.errortype = errortype;
	sock->lasterror.error = error;
	sock->lasterror.line = line;
	sock->lasterror.file = file;
	sock->lasterror.failedProxy = -1;
	switch(errortype) {
		case RS_ET_GAI:
			sock->lasterror.errormsg = (char*) gai_strerror(error);
			break;
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
			sock->lasterror.errormsg = (char*) ERR_reason_error_string(SSL_get_error(sock->ssl, error));
			break;
#endif			
		default:
			sock->lasterror.errormsg = NULL;
			break;
	}
	return error;
}

int rocksock_resolve_host(rocksock* sock, rs_hostInfo* hostinfo) {
	struct addrinfo hints;
	int ret;
	if (!sock) return RS_E_NULL;
	if (!hostinfo || !hostinfo->host || !hostinfo->port) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	ret = getaddrinfo(hostinfo->host, NULL, &hints, &hostinfo->hostaddr);
	if(!ret) {
		if(hostinfo->hostaddr->ai_addr->sa_family == PF_INET)
			((struct sockaddr_in*) hostinfo->hostaddr->ai_addr)->sin_port = htons(hostinfo->port);
		else
			((struct sockaddr_in6*) hostinfo->hostaddr->ai_addr)->sin6_port = htons(hostinfo->port);
		return 0;
	} else
		return rocksock_seterror(sock, RS_ET_GAI, ret, ROCKSOCK_FILENAME, __LINE__);
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
#ifdef USE_SSL
	sock->ssl = NULL;
#endif	
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_add_proxy(rocksock* sock, rs_proxyType proxytype, char* host, unsigned short port, char* username, char* password) {
	rs_proxy* prx;
	if (!sock) return RS_E_NULL;
	if(sock->lastproxy+1 >= MAX_PROXIES) return rocksock_seterror(sock, RS_ET_OWN, RS_E_EXCEED_PROXY_LIMIT, ROCKSOCK_FILENAME, __LINE__);
	if(!host) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
	if(proxytype == RS_PT_SOCKS4 && (username || password)) rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS4_NOAUTH, ROCKSOCK_FILENAME, __LINE__);
	if(proxytype == RS_PT_SOCKS5 && ((username && strlen(username) > 255) || (password && strlen(password) > 255)))
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS5_AUTH_EXCEEDSIZE, ROCKSOCK_FILENAME, __LINE__);
	sock->lastproxy++;
	prx = &sock->proxies[sock->lastproxy];
	prx->hostinfo.port = port;
	prx->proxytype = proxytype;
	prx->hostinfo.host = strdup(host);
	prx->username = username ? strdup(username) : NULL;
	prx->password = password ? strdup(password) : NULL;
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

struct timeval* make_timeval(struct timeval* tv, unsigned long timeout) {
	if(!tv) return NULL;
	tv->tv_sec = timeout / 1000; 
	tv->tv_usec = 1000 * (timeout % 1000); 	
	return tv;
}

int do_connect(rocksock* sock, rs_hostInfo* hostinfo, unsigned long timeout) {
	int flags, ret;
	fd_set wset; 
	struct timeval tv; 
	int optval; 
	socklen_t optlen = sizeof(optval); 

	sock->socket = socket(PF_INET, SOCK_STREAM, 0);
	if(sock->socket == -1) return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
	
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

int rocksock_setup_socks4_header(rocksock* sock, int is4a, char* buffer, size_t bufsize, rs_proxy* proxy, size_t* bytesused) {
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
		ret = rocksock_resolve_host(sock, &proxy->hostinfo);
		if(ret) return ret;
		if(proxy->hostinfo.hostaddr->ai_family != PF_INET)
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS4_NO_IP6, ROCKSOCK_FILENAME, __LINE__);
		buffer[4] = ((char*) &(((struct sockaddr_in*) proxy->hostinfo.hostaddr->ai_addr)->sin_addr.s_addr))[0];
		buffer[5] = ((char*) &(((struct sockaddr_in*) proxy->hostinfo.hostaddr->ai_addr)->sin_addr.s_addr))[1];
		buffer[6] = ((char*) &(((struct sockaddr_in*) proxy->hostinfo.hostaddr->ai_addr)->sin_addr.s_addr))[2];
		buffer[7] = ((char*) &(((struct sockaddr_in*) proxy->hostinfo.hostaddr->ai_addr)->sin_addr.s_addr))[3];
	}
	buffer[8] = 0;
	*bytesused = 9;
	if(is4a) *bytesused += strlen(strncpy(buffer + *bytesused, proxy->hostinfo.host, bufsize - *bytesused))+1;
		
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_connect(rocksock* sock, char* host, unsigned short port, int useSSL) {
	ptrdiff_t i;
	int ret, trysocksv4a;
	rs_hostInfo* connector;
	rs_proxy dummy;
	rs_proxy* targetproxy;
	char socksdata[768];
	char* p;
	size_t socksused, bytes;
	if (!sock) return RS_E_NULL;
	if (!host || !port) 
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);
#ifndef USE_SSL
	if (useSSL) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NO_SSL, ROCKSOCK_FILENAME, __LINE__);
#endif	
	sock->hostinfo.host = strdup(host);
	sock->hostinfo.port = port;
	
	if(sock->lastproxy >= 0) 
		connector = &sock->proxies[0].hostinfo;
	else
		connector = &sock->hostinfo;
		
	ret = rocksock_resolve_host(sock, connector);
	if(ret) {
		check_proxy0_failure:
		if(sock->lastproxy >= 0) sock->lasterror.failedProxy = 0;
		return ret;
	}
	
	ret = do_connect(sock, connector, sock->timeout);
	if(ret) goto check_proxy0_failure;
		
	if(sock->lastproxy >= 0) {
		dummy.hostinfo = sock->hostinfo;
		dummy.password = NULL;
		dummy.username = NULL;
		dummy.proxytype = RS_PT_NONE;
		for(i=1;i<=sock->lastproxy+1;i++) {
			if(i > sock->lastproxy)
				targetproxy = &dummy;
			else 
				targetproxy = &sock->proxies[i];
			// send socks connection data
			switch(sock->proxies[i-1].proxytype) {
				case RS_PT_SOCKS4:
					trysocksv4a = 1;
					trysocks4:
					ret = rocksock_setup_socks4_header(sock, trysocksv4a, socksdata, sizeof(socksdata), targetproxy, &socksused);
					if(ret) {
						proxyfailure:
						sock->lasterror.failedProxy = i - 1;
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
					if(sock->proxies[i-1].username && sock->proxies[i-1].password) {
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
						if(sock->proxies[i-1].username && sock->proxies[i-1].password) {
							p = socksdata;
							*p++ = 1;
							bytes = strlen(sock->proxies[i-1].username);
							*p++ = (char) bytes;
							memcpy(p, sock->proxies[i-1].username, bytes);
							p+=bytes;
							bytes = strlen(sock->proxies[i-1].password);
							memcpy(p, sock->proxies[i-1].password, bytes);
							p+=bytes;
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
					*p++ = 3;
					bytes = strlen(targetproxy->hostinfo.host);
					if(bytes > 255)
						return rocksock_seterror(sock, RS_ET_OWN, RS_E_SOCKS5_AUTH_EXCEEDSIZE, ROCKSOCK_FILENAME, __LINE__);
					*p++ = (char) bytes;
					memcpy(p, targetproxy->hostinfo.host, bytes);
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
						case 2:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_PROXY_AUTH_FAILED, ROCKSOCK_FILENAME, __LINE__);
							goto proxyfailure;
						case 3: case 4: case 5: case 6:
							ret = rocksock_seterror(sock, RS_ET_OWN, RS_E_TARGETPROXY_CONNECT_FAILED, ROCKSOCK_FILENAME, __LINE__);
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
		sock->sslctx = SSL_CTX_new(SSLv23_client_method());
		if (!sock->sslctx) {
			ERR_print_errors_fp(stderr);
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_SSL_GENERIC, ROCKSOCK_FILENAME, __LINE__);
		}
		sock->ssl = SSL_new(sock->sslctx);
		if (!sock->ssl) {
			ERR_print_errors_fp(stderr);
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_SSL_GENERIC, ROCKSOCK_FILENAME, __LINE__);
		}
		SSL_set_fd(sock->ssl, sock->socket);
		ret = SSL_connect(sock->ssl);
		if(ret != 1) {
			ERR_print_errors_fp(stderr);
			//printf("%dxxx\n", SSL_get_error(sock->ssl, ret));
			return rocksock_seterror(sock, RS_ET_SSL, ret, ROCKSOCK_FILENAME, __LINE__);
		}
	}
#endif
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

typedef enum  {
	RS_OT_SEND = 0,
	RS_OT_READ
} rs_operationType;

int rocksock_operation(rocksock* sock, rs_operationType operation, char* buffer, size_t bufsize, size_t chunksize, size_t* bytes) {
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
#ifdef USE_SSL
	unsigned long sslerr, sslretryerr;
	sslretryerr = operation == RS_OT_SEND ? SSL_ERROR_WANT_WRITE : SSL_ERROR_WANT_READ;
#endif
	
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
		FD_SET(sock->socket, &fd);
		ret=select(sock->socket+1, rfd, wfd, NULL, sock->timeout ? make_timeval(&tv, sock->timeout) : NULL);
		if(!FD_ISSET(sock->socket, &fd)) rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__); // temp test
		if(ret == -1) {
			//printf("h: %s, skt: %d, to: %d:%d\n", sock->hostinfo.host, sock->socket, tv.tv_sec, tv.tv_usec);
			return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
		}	
		else if(!ret) return rocksock_seterror(sock, RS_ET_OWN, RS_OT_READ ? RS_E_HIT_READTIMEOUT : RS_E_HIT_WRITETIMEOUT, ROCKSOCK_FILENAME, __LINE__);
		byteswanted = chunksize && chunksize < bytesleft ? chunksize : bytesleft;
#ifdef USE_SSL		
		if (sock->ssl) {
			ssl_try_again:
			if(operation == RS_OT_SEND)
				ret = SSL_write(sock->ssl, bufptr, byteswanted);
			else 
				ret = SSL_read(sock->ssl, bufptr, byteswanted);
			if(ret <= 0) {
				sslerr = SSL_get_error(sock->ssl, ret);
				if(sslerr == sslretryerr) goto ssl_try_again;
			}
			goto ssl_done;
			
		} else
#endif		
		if(operation == RS_OT_SEND) 
			ret = send(sock->socket, bufptr, byteswanted, 0);
		else
			ret = recv(sock->socket, bufptr, byteswanted, 0);
		
		if(!ret) // The return value will be 0 when the peer has performed an orderly shutdown.
			//return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
			break;
		else if(ret == -1) {
			ret = errno;
			if(ret == EWOULDBLOCK || ret == EINPROGRESS) return rocksock_seterror(sock, RS_ET_OWN, RS_OT_READ ? RS_E_HIT_READTIMEOUT : RS_E_HIT_WRITETIMEOUT, ROCKSOCK_FILENAME, __LINE__);
			return rocksock_seterror(sock, RS_ET_SYS, errno, ROCKSOCK_FILENAME, __LINE__);
		}	
#ifdef USE_SSL
		ssl_done:
#endif		
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

// tries to read exactly one line, until '\n', then appends a '\0'
int rocksock_readline(rocksock* sock, char* buffer, size_t bufsize, size_t* bytesread) {
	// TODO: make more efficient by peeking into the buffer (Flag MSG_PEEK to recv), instead of reading byte by byte
	// would need a different approach for ssl though.
	if (!sock) return RS_E_NULL;
	if (!buffer || !bufsize || !bytesread) return rocksock_seterror(sock, RS_ET_OWN, RS_E_NULL, ROCKSOCK_FILENAME, __LINE__);	
	char* ptr = buffer;
	size_t bytesread2 = 0;
	int ret;
	*bytesread = 0;
	while(*bytesread < bufsize) {
		ret = rocksock_recv(sock, ptr, 1, 1, &bytesread2);
		if(ret) return ret;
		*bytesread += bytesread2;
		if(ptr > buffer + bufsize)
			break;
		if(*bytesread > bufsize) {
			*bytesread = bufsize;
			break;
		}
		if(*ptr == '\n') {
			if(*bytesread < bufsize) {
				buffer[*bytesread] = '\0';
				return 0;
			} else 
				break;
		}
		ptr++;
	}
	return rocksock_seterror(sock, RS_ET_OWN, RS_E_OUT_OF_BUFFER, ROCKSOCK_FILENAME, __LINE__);
}

int rocksock_disconnect(rocksock* sock) {
	if (!sock) return RS_E_NULL;
#ifdef USE_SSL
	if(sock->ssl) {
		SSL_shutdown(sock->ssl);
		SSL_free(sock->ssl);
		SSL_CTX_free(sock->sslctx);
		sock->ssl = NULL;
	}
#endif
	if(sock->socket) close(sock->socket);
	sock->socket = 0;
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

int rocksock_free(rocksock* sock) {
	if (!sock) return RS_E_NULL;
	ptrdiff_t i;
	if(sock->lastproxy >= 0) {
		for (i=0;i<=sock->lastproxy;i++) {
			if(sock->proxies[i].username)
				free(sock->proxies[i].username);
			sock->proxies[i].username = NULL;
			if(sock->proxies[i].password)
				free(sock->proxies[i].password);
			sock->proxies[i].password = NULL;
			if(sock->proxies[i].hostinfo.host)
				free(sock->proxies[i].hostinfo.host);
			sock->proxies[i].hostinfo.host = NULL;
			if(sock->proxies[i].hostinfo.hostaddr)
				freeaddrinfo(sock->proxies[i].hostinfo.hostaddr);
			sock->proxies[i].hostinfo.hostaddr = NULL;
		}
	}
	if(sock->hostinfo.host)
		free(sock->hostinfo.host);
	sock->hostinfo.host = NULL;
	if(sock->hostinfo.hostaddr)
		freeaddrinfo(sock->hostinfo.hostaddr);
	sock->hostinfo.hostaddr = NULL;
		
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}


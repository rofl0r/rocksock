/*
 * author: rofl0r (C) 2011 - 2013
 * License: LGPL 2.1+ with static linking exception
 */

#include "rocksock_ssl_internal.h"
#include "rocksock_internal.h"

#include <cyassl/ssl.h>


#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

//RcB: LINK "-lcyassl"

void rocksock_init_ssl(void) {
	CyaSSL_Init();
	//CyaSSL_Debugging_ON(); /* cyassl needs to be compiled with --enable-debug */
}

void rocksock_free_ssl(void) {
	CyaSSL_Cleanup();
}

const char* rocksock_ssl_strerror(rocksock *sock, int error) {
	int err = CyaSSL_get_error(sock->ssl, 0);
	return CyaSSL_ERR_reason_error_string(err);
}

int rocksock_ssl_send(rocksock* sock, char* buf, size_t sz) {
	int ret;
	do  ret = CyaSSL_write(sock->ssl, buf, sz);
	while (ret <= 0 && CyaSSL_get_error(sock->ssl, ret) == SSL_ERROR_WANT_WRITE);
	return ret;
}

int rocksock_ssl_recv(rocksock* sock, char* buf, size_t sz) {
	int ret;
	do  ret = CyaSSL_read(sock->ssl, buf, sz);
	while (ret <= 0 && CyaSSL_get_error(sock->ssl, ret) == SSL_ERROR_WANT_READ);
	return ret;
}

int rocksock_ssl_connect_fd(rocksock* sock) {
	sock->sslctx = CyaSSL_CTX_new(CyaSSLv23_client_method());
	if (!sock->sslctx) {
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_SSL_GENERIC, ROCKSOCK_FILENAME, __LINE__);
	}

	/* FIXME cyassl needs explicit passing of certificates
	   however the location may vary by system.
	   until resolved, certificate checks are disabled */
	CyaSSL_CTX_set_verify(sock->sslctx, SSL_VERIFY_NONE, 0);

	sock->ssl = CyaSSL_new(sock->sslctx);
	if (!sock->ssl) {
		return rocksock_seterror(sock, RS_ET_OWN, RS_E_SSL_GENERIC, ROCKSOCK_FILENAME, __LINE__);
	}

	CyaSSL_set_fd(sock->ssl, sock->socket);
	//CyaSSL_set_using_nonblock(sock->ssl, 0);

	int ret = CyaSSL_connect(sock->ssl);
	if(ret != SSL_SUCCESS) {
		return rocksock_seterror(sock, RS_ET_SSL, ret, ROCKSOCK_FILENAME, __LINE__);
	}
	return 0;
}

void rocksock_ssl_free_context(rocksock *sock) {
        if(sock->ssl) {
                CyaSSL_shutdown(sock->ssl);
                CyaSSL_free(sock->ssl);
                CyaSSL_CTX_free(sock->sslctx);
                sock->ssl = 0;
        }
}

int rocksock_ssl_pending(rocksock *sock) {
	return CyaSSL_pending(sock->ssl);
}

int rocksock_ssl_peek(rocksock* sock, int *result) {
        int ret;
        char buf[4];
	again:
	ret = CyaSSL_peek(sock->ssl, buf, 1);
	if(ret >= 0) *result = 1;
	/* when SSL_peek returns 0, it means a disconnect.
	   there's no way to get "peek was successful, no error, but also no data"
	   and that means that it must block until data is there or an error happened.
	   we have to return 1 in that case as well so the subsequent read returns 0,
	   which is the proper way to detect a disconnect. */
	else {
		ret = CyaSSL_get_error(sock->ssl, 0);
		if(ret == SSL_ERROR_WANT_READ) goto again;
		return rocksock_seterror(sock, RS_ET_SSL, ret, ROCKSOCK_FILENAME, __LINE__);
	}
	return rocksock_seterror(sock, RS_ET_NO_ERROR, 0, NULL, 0);
}

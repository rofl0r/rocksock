/*
 * author: rofl0r (C) 2011 - 2013
 * License: LGPL 2.1+ with static linking exception
 */

#include "rocksock_ssl_internal.h"
#include "rocksock_internal.h"

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


#ifndef ROCKSOCK_FILENAME
#define ROCKSOCK_FILENAME __FILE__
#endif

//RcB: LINK "-lssl -lcrypto -lz"

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

const char* rocksock_ssl_strerror(rocksock *sock, int error) {
	return ERR_reason_error_string(error);
}

#include <errno.h>
int rocksock_ssl_send(rocksock* sock, char* buf, size_t sz) {
        int ret = SSL_write(sock->ssl, buf, sz);
        if (ret < 0 && SSL_get_error(sock->ssl, ret) == SSL_ERROR_WANT_WRITE) errno = EWOULDBLOCK;
        return ret;
}

int rocksock_ssl_recv(rocksock* sock, char* buf, size_t sz) {
	int ret = SSL_read(sock->ssl, buf, sz);
	if (ret < 0 && SSL_get_error(sock->ssl, ret) == SSL_ERROR_WANT_READ) errno = EWOULDBLOCK;
	return ret;
}

int rocksock_ssl_connect_fd(rocksock* sock) {
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
	int ret = SSL_connect(sock->ssl);
	if(ret != 1) {
		if((ret = SSL_get_error(sock->ssl, ret)) == SSL_ERROR_WANT_READ)
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_HIT_CONNECTTIMEOUT, ROCKSOCK_FILENAME, __LINE__);
		//ERR_print_errors_fp(stderr);
		//printf("%dxxx\n", SSL_get_error(sock->ssl, ret));
		return rocksock_seterror(sock, RS_ET_SSL, ret, ROCKSOCK_FILENAME, __LINE__);
	}
	return 0;
}

void rocksock_ssl_free_context(rocksock *sock) {
        if(sock->ssl) {
                SSL_shutdown(sock->ssl);
                SSL_free(sock->ssl);
                SSL_CTX_free(sock->sslctx);
                sock->ssl = 0;
        }
}

int rocksock_ssl_pending(rocksock *sock) {
	return SSL_pending(sock->ssl);
}

int rocksock_ssl_peek(rocksock* sock, int *result) {
        char buf[4];
	int ret;
	again:
	ret = SSL_peek(sock->ssl, buf, 1);
	if(ret >= 0) *result = 1;
	else {
		ret = SSL_get_error(sock->ssl, ret);
		if(ret == SSL_ERROR_WANT_READ)
			return rocksock_seterror(sock, RS_ET_OWN, RS_E_HIT_READTIMEOUT, ROCKSOCK_FILENAME, __LINE__); //goto again;
		return rocksock_seterror(sock, RS_ET_SSL, ret, ROCKSOCK_FILENAME, __LINE__);
        }
	return rocksock_seterror(sock, RS_ET_OWN, 0, NULL, 0);
}


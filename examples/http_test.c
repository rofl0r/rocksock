// gcc -Wall -g rocksock.c rocksock_test2.c -o rocksock_test2
/*
 * author: rofl0r
 *
 * License: LGPL 2.1+ with static linking exception
 */
#include <stdio.h>
#include <stdlib.h>
#include "../rocksock.h"

#define chk(X, ACTION) if(X) { rocksock_error_dprintf(2, psock); ACTION; }
#define checkerr chk(ret, exit(2))

static int usage(const char *a0) {
	dprintf(2,
	"usage: %s host port [proxy1] [proxy2] ... [proxy16]\n"
	"makes a HTTP connection to host on port. if port ends with s,\n"
	"SSL will be used. supports up to 16 chained proxies.\n"
	"proxies will be chained in the order as they appear.\n\n"
	"supported proxy syntax:\n"
	"http://proxy.com:port - HTTP proxy like squid or tinyproxy\n"
	"socks4://proxy.com:port - SOCKS4 proxy like tor\n"
	"socks5://proxy.com:port - SOCKS5 proxy like rocksocks5\n"
	"socks5://user:pass@proxy.com:port - SOCKS5 proxy with auth\n\n"
	"example: %s googe.com 80 http://localhost:8888\n"
	"example: %s googe.com 443s socks4://localhost:9050\n", a0, a0, a0);
	return 1;
}

int main(int argc, char** argv) {
	rocksock sock;
	rocksock* psock = &sock;
	int ret, i;
	char inbuf[1024];
	size_t bytesread;
	size_t chunksize = 512;

	if(argc < 3) return usage(argv[0]);

	rocksock_init_ssl();

	rs_proxy proxies[16];
	rocksock_init(psock, proxies);
	rocksock_set_timeout(psock, 10000);
	for (i = 3; i < argc; i++) chk(rocksock_add_proxy_fromstring(psock, argv[i]), return usage(argv[0]));
	unsigned port = atoi(argv[2]);
	int useSSL = 0;
	char *p = argv[2]; while(*p) p++;
	if(p[-1] == 's') useSSL = 1;

	ret = rocksock_connect(psock, argv[1], port, useSSL);

	checkerr;
	ret = rocksock_send(psock, "GET / HTTP/1.0\r\n\r\n", 0, 0, &bytesread);

	checkerr;
	do {
		puts("loop");
		ret = rocksock_recv(psock, inbuf, sizeof(inbuf)-1, chunksize, &bytesread);
		checkerr;
		if(bytesread) {
			inbuf[bytesread] = '\0';
			puts(inbuf);
		}
		printf("bytesread %zu\n", bytesread);
	} while (bytesread == chunksize);
	do {

		ret = rocksock_recv(psock, inbuf, sizeof(inbuf)-1, chunksize, &bytesread);
		checkerr;
		if(bytesread) {
			inbuf[bytesread] = '\0';
			puts(inbuf);
		}
		printf("bytesread %zu\n", bytesread);
	} while (bytesread);
	rocksock_disconnect(psock);
	rocksock_clear(psock);
	rocksock_free_ssl();
	return 0;
}

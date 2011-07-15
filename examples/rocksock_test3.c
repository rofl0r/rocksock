// gcc -Wall -g rocksock.c rocksock_test2.c -o rocksock_test2

/*
 * 
 * author: rofl0r
 * 
 * License: LGPL 2.1+ with static linking exception
 * 
 * 
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../rocksock.h"
//RcB: DEP "../rocksock.c"

#define checkerr if(ret) { \
		if(sock.lasterror.failedProxy != -1) printf("failing proxy: %d\n", sock.lasterror.failedProxy); \
		printf("%s:%d - error #%d: %s from %s:%d\n", __FILE__, __LINE__, sock.lasterror.error, sock.lasterror.errormsg, sock.lasterror.file, sock.lasterror.line); \
		exit(2); \
	}

int main(int argc, char** argv) {
	rocksock sock;
	rocksock* psock = &sock;
	int ret;
	char inbuf[1024];
	size_t bytesread;
	size_t chunksize = 512;
	
	if(argc < 2) {
		puts("need ip or dns name of a ftpserver as argv1");
		exit(1);
	}
#ifdef USE_SSL
	rocksock_init_ssl();
#endif	

	rocksock_init(psock);
	rocksock_set_timeout(psock, 10000);
	//ret = rocksock_connect(psock, "b12.wimbli.com", 80, 0);
	rocksock_add_proxy(psock, RS_PT_SOCKS4, "127.0.0.1", 9050, NULL, NULL);
	//rocksock_add_proxy(psock, RS_PT_SOCKS5, "127.0.0.1", 31337, NULL, NULL);
	//rocksock_add_proxy(psock, RS_PT_SOCKS5, "98.216.80.12", 5639, NULL, NULL);
	
	
	ret = rocksock_connect(psock, argv[1], 
#ifndef USE_SSL
		21, 0
#else
		443, 1
#endif		
		);
	checkerr;
	do {
		ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
		checkerr;
		if(bytesread) puts(inbuf);
	} while (bytesread && memcmp(inbuf, "220 ", 4));
	
	ret = rocksock_send(psock, inbuf, snprintf(inbuf, sizeof(inbuf), "USER ftp\r\n"), 0, &bytesread);
	checkerr;
	puts(inbuf);
	
	do {
		ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
		checkerr;
		if(bytesread) puts(inbuf);
	} while (bytesread && memcmp(inbuf, "331 ", 4));
	
	ret = rocksock_send(psock, inbuf, snprintf(inbuf, sizeof(inbuf), "PASS none\r\n"), 0, &bytesread);
	checkerr;
	puts(inbuf);
	
	do {
		ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
		checkerr;
		if(bytesread) puts(inbuf);
	} while (bytesread && memcmp(inbuf, "230 ", 4));
	
	ret = rocksock_send(psock, inbuf, snprintf(inbuf, sizeof(inbuf), "PASV\r\n"), 0, &bytesread);
	checkerr;
	puts(inbuf);

	do {
		ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
		checkerr;
		if(bytesread) puts(inbuf);
	} while (bytesread && memcmp(inbuf, "230 ", 4));		
	
	ret = rocksock_send(psock, inbuf, snprintf(inbuf, sizeof(inbuf), "LIST\r\n"), 0, &bytesread);
	checkerr;
	puts(inbuf);

	do {
		ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
		checkerr;
		if(bytesread) puts(inbuf);
	} while (bytesread && memcmp(inbuf, "230 ", 4));	
	
	ret = rocksock_readline(psock, inbuf, sizeof(inbuf)-1, &bytesread);
	checkerr;
	if(bytesread) puts(inbuf);
	
	rocksock_disconnect(psock);
	rocksock_free(psock);
#ifdef USE_SSL
	rocksock_free_ssl();
#endif		
	return 0;
}
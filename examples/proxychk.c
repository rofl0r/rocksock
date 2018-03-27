/*
 *
 * author: rofl0r
 *
 * License: LGPL 2.1+ with static linking exception
 *
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include "../rocksock.h"

static int timeout;
static char chk_host[512];
static int chk_host_port;

static int scanHost(char* baseproxy, char* scanproxy) {
	rocksock skt;
	rocksock* soc = &skt;
	int ret;

	rs_proxy proxies[2];

	rocksock_init(soc, proxies);
	rocksock_set_timeout(soc, timeout);
	if(baseproxy)
		if(rocksock_add_proxy_fromstring(soc, baseproxy))
			return -1;
	if(rocksock_add_proxy_fromstring(soc, scanproxy))
		return -1;

	if (!rocksock_connect(soc, chk_host, chk_host_port, 0)){
		ret = 0; /* success */
	} else {
		//printf("%s\n", soc->lasterror.errormsg);
		ret = -1;
	}

	rocksock_disconnect(soc);
	rocksock_clear(soc);

	return ret;
}

static int usage(const char *argv0) {
	dprintf(2,
		"proxy checker.\n"
		"%s options\n"
		"[-b type://[user:pass@]base_proxy_ip:port]\n"
		"[-t type]\n"
		"[-c check_ip:port]\n"
		"[-T timeout_in_millisec]\n"
		"\n"
		"read [type://]ips:port from STDIN\n"
		"if type is given, all ip:port tuples from STDIN won't need a prefix\n"
		"if base proxy is given, it will be used as first proxy\n"
		"timeout defaults to 1500.\n"
		"checkip:port defaults to cnn.com:80\n"
		"for every proxy that works, its address will be echoed to stdout\n"
		"exit code is 0 when last proxy worked\n\n"
		"example: echo 127.0.0.1:9050 | %s -t socks4 -T 2000\n"
		"example: echo socks5://user:pass@127.0.0.1:1080 | %s\n"
		"\nyou may want to use JOBFLOW or GNU parallel for speedy parallel checks\n"
		, argv0, argv0, argv0);
	return 1;
}

int main(int argc, char** argv) {
	int c;
	char *typestring = 0;
	char *baseproxy = 0;
	char *checkurl = "cnn.com:80";
	timeout = 1500;

	while ((c  = getopt(argc, argv, "c:T:b:t:")) != -1) {
		switch(c) {
			case 'c':
				checkurl = optarg;
				break;
			case 'T':
				timeout = atoi(optarg);
				break;
			case 't':
				if(!strcmp(optarg, "socks4")) ;
				else if(!strcmp(optarg, "socks5")) ;
				else if(!strcmp(optarg, "http")) ;
				else {
					dprintf(2, "invalid proxy type\n");
					return 1;
				}
				typestring = optarg;
				break;
			case 'b':
				baseproxy = optarg;
				break;
			default:
				return usage(argv[0]);
		}
	}

	{
		char *p = strchr(checkurl, ':');
		if(!p) return usage(argv[0]);

		size_t l = p-checkurl;
		strncpy(chk_host, checkurl, l);
		chk_host[l] = 0;
		chk_host_port = atoi(++p);
	}

	char buf[1024];
	int ret = 0;
	while(fgets(buf, sizeof buf, stdin)) {
		char nb[1024+10], *p;
		if((p  = strrchr(buf, '\n')))
			*p = 0;
		if(*buf == 0 || *buf == '#') continue;
		snprintf(nb, sizeof nb, "%s%s%s",
			typestring ? typestring : "",
			typestring ? "://" : "",
			buf);
		if(0 == (ret = scanHost(baseproxy, nb)))
			printf("%s\n", nb);

	}
	return ret;
}

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
#include "../../lib/include/stringlist.h"

static int timeout;
static char chk_host[512];
static int chk_host_port;
static int debug = 1;

#define DPRINTF(fmt, args...) if(debug) do { dprintf(2,fmt, ## args); } while(0)

static int scanHost(stringlist* chain, char* scanproxy, size_t max, rs_errorInfo *e_info) {
	rocksock skt;
	rocksock* soc = &skt;
	int ret;

	rs_proxy proxies[stringlist_getsize(chain)+1];

	rocksock_init(soc, proxies);
	rocksock_set_timeout(soc, timeout);

	DPRINTF("====== checking %s (timeout: %d)\n", scanproxy, timeout);

	size_t i, top = max == -1 ? stringlist_getsize(chain) : max;
	char *candidate;
	for(i = 0; i < top; i++) {
//	stringlist_foreach(chain, candidate) {
		candidate = stringlist_get(chain, i);
		DPRINTF("> %s\n", candidate);
		if(rocksock_add_proxy_fromstring(soc, candidate))
			return -1;
	}

	if(rocksock_add_proxy_fromstring(soc, scanproxy))
		return -1;

	if (!rocksock_connect(soc, chk_host, chk_host_port, 0)){
		DPRINTF("SUCCESS\n");
		ret = 0; /* success */
	} else {
		char ebuf[256];
		DPRINTF("%s\n", rocksock_strerror_detailed(soc, ebuf, sizeof ebuf));
		*e_info = soc->lasterror;
		ret = -1;
	}

	rocksock_disconnect(soc);
	rocksock_clear(soc);

	return ret;
}

static int usage(const char *argv0) {
	dprintf(2,
		"proxy checker/chain generator.\n\n"

		"%s [options] chain-length\n"
		"[-c check_ip:port]\n"
		"[-T global timeout_in_millisec]\n"
		"[-t per-proxy additional timeout_in_millisec]\n"
		"[-l fixedlist.txt]\n"
		"\n"

		"generates a working proxychain.\n"
		"every proxy that works will be added to the chain, and connects will only\n"
		"be done through the existing chain.\n"
		"if the desired chain length is reached, the chain will be printed to stdout.\n"
		"the list of proxies is passed on stdin in type://ip:port format, where type\n"
		"can be one of socks4|socks5|http\n"
		"the optional list added with -l contains proxies that will be added w/o check\n"
		"\n"

		"timeout defaults to 1500.\n"
		"checkip:port defaults to cnn.com:80\n"

		,argv0, argv0, argv0);
	return 1;
}

int main(int argc, char** argv) {
	int c;
	char *typestring = 0;
	char *baseproxy = 0;
	char *load_list = 0;
	char *checkurl = "cnn.com:80";
	int base_timeout = 1500;
	int per_proxy_timeout = 0;

	while ((c  = getopt(argc, argv, "c:T:t:l:")) != -1) {
		switch(c) {
			case 'c':
				checkurl = optarg;
				break;
			case 'T':
				base_timeout = atoi(optarg);
				break;
			case 't':
				per_proxy_timeout = atoi(optarg);
				break;
			case 'l':
				load_list = optarg;
				break;
			default:
				return usage(argv[0]);
		}
	}

	if (optind >= argc) {
		dprintf(2, "error: chain length missing\n");
		return usage(argv[0]);
	}

	int n_proxies = atoi(argv[optind]);

	{
		char *p = strchr(checkurl, ':');
		if(!p) return usage(argv[0]);

		size_t l = p-checkurl;
		strncpy(chk_host, checkurl, l);
		chk_host[l] = 0;
		chk_host_port = atoi(++p);
	}


	stringlist *chain = stringlist_new(n_proxies);

	char buf[1024];
	if(load_list) {
		FILE *f = fopen(load_list, "r");
		while(fgets(buf, sizeof buf, f)) {
			char *p;
			if((p = strrchr(buf, '\n'))) *p = 0;
			if(*buf == 0 || *buf == '#') continue;
			stringlist_add_dup(chain, buf);
		}
	}

	int ret = 0;
	while(stringlist_getsize(chain) < n_proxies) {
		if(!fgets(buf, sizeof buf, stdin))
			return 1;
		char *p;
		if((p = strrchr(buf, '\n'))) *p = 0;
		if(*buf == 0 || *buf == '#') continue;

		size_t i;
		for(i=0; i < stringlist_getsize(chain); i++) {
			char *entry = stringlist_get(chain, i);
			if (!strcmp(entry, buf)) goto next;
		}

		timeout = base_timeout + (per_proxy_timeout * stringlist_getsize(chain));
		rs_errorInfo last_err;
		if(0 == (ret = scanHost(chain, buf, -1, &last_err)))
			stringlist_add_dup(chain, buf);
		else {
			if(last_err.errortype == RS_ET_OWN &&
			   (last_err.error == RS_E_REMOTE_DISCONNECTED ||
			    last_err.error == RS_E_TARGETPROXY_CONN_REFUSED) &&
			   last_err.failedProxy != -1 && stringlist_getsize(chain) > 0
			) {
				int fp = last_err.failedProxy, fails = 0;
				for(i=0; i<3; i++) {
					ret = scanHost(chain, buf, fp, &last_err);
					if(!ret || last_err.failedProxy != fp) break;
					fails++;
				}
				if(fails > 2) {
					dprintf(2, "proxy: %d stopped working, removing\n", fp);
					stringlist_delete(chain, fp);
				}
			}
		}
next:;
	}
	char *px;
	stringlist_foreach(chain, px) {
		printf("%s\n", px);
	}
	return ret;
}

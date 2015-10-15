// use rcb to compile: rcb portscanner.c

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
#include "../rocksock.h"

//RcB: LINK "-lpthread"

typedef struct {
	char host[16];
	int port;
	int status;
} threaddata;

static int done = 0;
static pthread_mutex_t mutex;

static void* scanHost(void* arg) {
	threaddata* d = arg;
	rocksock skt;
	rocksock* soc = &skt;
	rocksock_init(soc);
	rocksock_set_timeout(soc, 1500);

	if (!rocksock_connect(soc, d->host, d->port, 0)){
		d->status = 1;
	} else {
		//printf("%s\n", soc->lasterror.errormsg);
		d->status = 0;
	}

	rocksock_disconnect(soc);
	rocksock_clear(soc);

	pthread_mutex_lock(&mutex);
	done++;
	pthread_mutex_unlock(&mutex);
	return 0;
}

int running(pthread_t* t, int max) {
	int res = 0, i = 0;
	for (; i <= max; i++) {
		if (t[i]) res++;
	}
	return res;
}

int joinThreads(pthread_t* threads, int max) {
	void* exitstate;
	int i = 0;
	for(;i<max;i++) {
		if (threads[i]) {
			if (!pthread_join(threads[i], &exitstate)) {
				threads[i] = 0;
				free(exitstate);
			}
		}
	}
	return 0;
}

int scanRange(const char *ip, int port, int max_threads) {

	int maxthreads = max_threads > 254 ? 254 : max_threads;
	pthread_t threads[255] = {0};
	threaddata data[255] = {0};

	pthread_attr_t attr;
	size_t stack;
	pthread_attr_init(&attr);
	pthread_attr_getstacksize(&attr, &stack);
	stack = 32768;
	pthread_attr_setstacksize(&attr, stack);

	pthread_mutex_init(&mutex, NULL);

	volatile int x = 1;
	while(done < 254) {
		while(x < 255 && running((pthread_t*) threads, x) < maxthreads) {
			threaddata* d = &data[x];
			snprintf(d->host, sizeof(d->host), "%s.%d", ip, x);
			d->port = port;
			d->status = -1;
			if (!pthread_create(&threads[x], &attr, scanHost, &data[x])) {
				x++;
			}
			else {
				break;
			}
		}
		joinThreads(threads, x);
	}

	joinThreads(threads, x);

	pthread_attr_destroy(&attr);

	int i = 0;
	for (; i < 255; i++) {
		if (data[i].status > 0) dprintf(1, "%s\n", data[i].host);
	}

	pthread_mutex_destroy(&mutex);
	return 0;
}

int main(int argc, char** argv) {
	if (argc < 4) {
		dprintf(2, "multithreaded subnet portscanner\n"
		           "inv. syntax\n"
		           "%s 127.0.0 22 16\n"
		           "subnetA port maxthreads\n", argv[0]);
		exit(1);
	}

	int port = atoi(argv[2]);
	char* ip = argv[1];
	int maxthreads = atoi(argv[3]);

	scanRange(ip, port, maxthreads);
	return 0;
}

// g++ -Wall -g rocksock.c rocksock_test.cpp -o rocksock_test -lpthread

/*
 * 
 * author: rofl0r
 * 
 * License: LGPL 2.1+ with static linking exception
 * 
 * 
 */

#include <iostream>
#include <sstream>

extern "C" {
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include "rocksock.h"
}
int msleep(long millisecs) {
	struct timespec req, rem;
	req.tv_sec = millisecs / 1000;
	req.tv_nsec = (millisecs % 1000) * 1000 * 1000;
	int ret;
	while((ret = nanosleep(&req, &rem)) == -1 && errno == EINTR) req = rem;
	return ret;	
}

using namespace std;

typedef struct {
	char host[16];
	int port;
	int status;
} threaddata;

int done = 0;
pthread_mutex_t mutex;

void* scanHost(void* arg) {
	threaddata* d = (threaddata*) arg;
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
	rocksock_free(soc);

	pthread_mutex_lock(&mutex);
	done++;
	pthread_mutex_unlock(&mutex);
	return NULL;
}


std::string intToString(int i)
{
    std::stringstream ss;
    std::string s;
    ss << i;
    s = ss.str();

    return s;
}


int running(pthread_t* t, int max) {
	int res = 0;
	for (int i = 0; i <= max; i++) {
		if (t[i]) res++;
	}
	return res;
}

int joinThreads(pthread_t* threads, int max) {
	void* exitstate;

	for(int i=0;i<max;i++) {
		if (threads[i]) {
			if (!pthread_join(threads[i], &exitstate)) {
				threads[i] = 0;
				free(exitstate);
			}
		}
	}
	return 0;
}

int scanRange(std::string ip, int port, int max_threads) {

	int maxthreads = max_threads > 254 ? 254 : max_threads;
	pthread_t threads[255];
	memset(threads, 0, sizeof(threads));
	threaddata data[255];
	memset(data, 0, sizeof(data));

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
			string myhost = ip + "." + intToString(x) ;
			threaddata* d = &data[x];
			strcpy(d->host, myhost.c_str());
			d->port = port;
			d->status = -1;
			if (!pthread_create(&threads[x], &attr, scanHost, &data[x])) {
				x++;
			}
			else {
				break;
			}
		}
		joinThreads((pthread_t*) threads, x);
	}

	joinThreads((pthread_t*) threads, x);

	pthread_attr_destroy(&attr);

	for (int i = 0; i < 255; i++) {
		if (data[i].status > 0) cout << data[i].host << endl;
	}
	
	pthread_mutex_destroy(&mutex);
	return 0;
}

int main(int argc, char** argv) {
	if (argc < 4) {
		cout << "multithreaded subnet portscanner" << endl;
		cout << "inv. syntax" << endl;
		cout << argv[0] << " 127.0.0 22 16" << endl;
		cout << "subnetA port maxthreads" << endl;
		exit(1);
	}

	int port = atoi(argv[2]);
	string ip = argv[1];
	int maxthreads = atoi(argv[3]);

	scanRange(ip, port, maxthreads);
	return 0;
}

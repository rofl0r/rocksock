/*
 * 
 * author: rofl0r
 * 
 * License: LGPL 2.1+ with static linking exception
 * 
 * 
 */


#ifndef _ROCKSOCKSERVER_H_
#define _ROCKSOCKSERVER_H_

#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>

typedef struct {
	fd_set master;
	int listensocket;
	int maxfd;
	int numfds;
	void* userdata;
	long sleeptime_us;
} rocksockserver;

void rocksockserver_set_sleeptime(rocksockserver* srv, long microsecs);
int rocksockserver_disconnect_client(rocksockserver* srv, int client);
int rocksockserver_init(rocksockserver* srv, char* listenip, short port, void* userdata);
int rocksockserver_loop(rocksockserver* srv, char* buf, size_t bufsize,
			int (*on_clientconnect) (void* userdata, struct sockaddr_storage* clientaddr, int fd), 
			int (*on_clientread) (void* userdata, int fd, size_t nread),
			int (*on_clientwantsdata) (void* userdata, int fd),
			int (*on_clientdisconnect) (void* userdata, int fd)
);
#endif


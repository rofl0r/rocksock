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

#if (! defined(USER_MAX_FD)) || (USER_MAX_FD > FD_SETSIZE)
#undef USER_MAX_FD
#define USER_MAX_FD FD_SETSIZE
#endif

typedef struct {
	fd_set master;
	int listensocket;
	int maxfd;
	int numfds;
	int signalfd;
	void* userdata;
	long sleeptime_us;
} rocksockserver;

void rocksockserver_set_sleeptime(rocksockserver* srv, long microsecs);
int rocksockserver_disconnect_client(rocksockserver* srv, int client);
int rocksockserver_init(rocksockserver* srv, const char* listenip, unsigned short port, void* userdata);
void rocksockserver_watch_fd(rocksockserver* srv, int newfd);
void rocksockserver_set_signalfd(rocksockserver* srv, int signalfd);
int rocksockserver_loop(rocksockserver* srv,
			char* buf, size_t bufsize,
			int (*on_clientconnect) (void* userdata, struct sockaddr_storage* clientaddr, int fd), 
			int (*on_clientread) (void* userdata, int fd, size_t nread),
			int (*on_clientwantsdata) (void* userdata, int fd),
			int (*on_clientdisconnect) (void* userdata, int fd)
);

#endif

//RcB: DEP "rocksockserver*.c"


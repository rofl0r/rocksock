/* the polite echo server. requires you to send a HELO, afterwards
   mimics a traditional echo server */

#include "../rocksockserver.h"
#include "../../lib/include/sblist.h"
#include <string.h>

//RcB: CFLAGS "-std=c99"

enum cstate {
	cs_null = 0,
	cs_error,
	cs_said_hello,
	cs_idle,
	cs_msg,
};

typedef struct client {
	int fd;
	enum cstate state;
	char msg[128];
} client;

typedef struct server_state {
	rocksockserver srv;
	sblist *clients;
} server;

struct client *client_from_fd(sblist *clients, int fd) {
	struct client* c;
	sblist_iter(clients, c) {
		if(c->fd == fd) return c;
	}
	return 0;
}

static void disconnect_client(server* s, int fd) {
	struct client *c;
	sblist_iter_counter(s->clients, i, c) {
		if(c->fd == fd) {
			sblist_delete(s->clients, i);
			break;
		}
	}
	rocksockserver_disconnect_client(&s->srv, fd);
}

static int on_cdisconnect (void* userdata, int fd) {
	server* s = userdata;
	disconnect_client(s, fd);
	return 0;
}

static int on_cconnect (void* userdata, struct sockaddr_storage* clientaddr, int fd) {
	server* s = userdata;
	struct client c = {.fd = fd };
	if(!sblist_add(s->clients, &c)) {
		disconnect_client(s, fd);
		return -1;
	}
	return 0;
}

static void read_command(server *s, client *c, int fd) {
	ssize_t nbytes;
	if(c->state == cs_null) {
		if(5 != (nbytes = recv(fd, c->msg, 5, 0)) ||
		   memcmp(c->msg, "HELO\n", 5)) {
			c->state = cs_error;
		} else c->state = cs_said_hello;
	} else if (c->state == cs_idle) {
		nbytes = recv(fd, c->msg, sizeof(c->msg)-1, 0);
		if (nbytes == 0) on_cdisconnect(s, fd);
		else if(nbytes < 1) c->state = cs_error;
		else {
			c->msg[nbytes] = 0;
			c->state = cs_msg;
		}
	}
}

static int on_cread (void* userdata, int fd, size_t dummy) {
	server* s = userdata;
	struct client *c;
	if(!(c = client_from_fd(s->clients, fd))) return -1;
	read_command(s, c, fd);
	return 0;
}
#define SL(X) X, sizeof(X)-1
static int on_cwantsdata (void* userdata, int fd) {
	server* s = userdata;
	struct client *c;
	if(!(c = client_from_fd(s->clients, fd))) return -1;
	switch(c->state) {
		case cs_said_hello:
			send(fd, SL("HELO. you may now say something.\n"), MSG_NOSIGNAL);
			c->state = cs_idle;
		case cs_idle:
		case cs_null:
			break;
		case cs_error:
			send(fd, SL("error: need to send HELO first\n"), MSG_NOSIGNAL);
			disconnect_client(s, fd);
			break;
		case cs_msg:
			send(fd, c->msg, strlen(c->msg), MSG_NOSIGNAL);
			c->state = cs_idle;
			break;
	}
	return 0;
}

int main() {
	server sv, *s = &sv;
	s->clients = sblist_new(sizeof(struct client), 32);
	const int port = 9999;
	const char* listenip = "0.0.0.0";
	if(rocksockserver_init(&s->srv, listenip, port, (void*) s)) return -1;
	if(rocksockserver_loop(&s->srv, NULL, 0,
	                       &on_cconnect, &on_cread,
	                       &on_cwantsdata, &on_cdisconnect)) return -2;
	return 0;
}

#include "rocksockserver.h"
// pass the reading end of a pipe
void rocksockserver_set_signalfd(rocksockserver* srv, int signalfd) {
	srv->signalfd = signalfd;
	rocksockserver_watch_fd(srv, signalfd);
}

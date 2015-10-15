#include "rocksockserver.h"
void rocksockserver_set_perrorfunc(rocksockserver* srv, perror_func perr) {
	srv->perr = perr;
}


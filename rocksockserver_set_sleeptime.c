#include "rocksockserver.h"

void rocksockserver_set_sleeptime(rocksockserver* srv, long microsecs) {
	srv->sleeptime_us = microsecs;
}

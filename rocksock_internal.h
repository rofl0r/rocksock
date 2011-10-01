#ifndef ROCKSOCK_INTERNAL_H
#define ROCKSOCK_INTERNAL_H

#include "rocksock.h"
extern const char* rs_errorMap[];

int rocksock_seterror(rocksock* sock, rs_errorType errortype, int error, const char* file, int line);

#endif

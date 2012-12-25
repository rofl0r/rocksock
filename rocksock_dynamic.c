#include <string.h>
#include <stdlib.h>
#include "rocksock.h"


rocksock* rocksock_new(void) {
	rocksock* result = calloc(1, sizeof(rocksock));
	return result;
}

void rocksock_free(rocksock* s) {
	if(s) free(s);
}


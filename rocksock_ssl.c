#include "rocksock_ssl_internal.h"

/* SSL no-op implementation in case rocksock was built without ssl support.
   provided so examples/user programs don't need to put ifdefs around their
   usage. */
#ifndef USE_SSL
void rocksock_init_ssl(void) {}
void rocksock_free_ssl(void) {}
#endif

rocksock socket library (C) rofl0r
==================================

rocksock is a powerful (mostly) blocking networking library
written in C.
it was designed for small size, robustness, simplicity,
static linking and fine-grained error reporting and
configurability.
programming in a blocking way is much simpler, but can lead to
near infinite bloking. rocksock addresses this by providing
timeouts so the app doesn't get into this completely blocked
state and can react properly on any exceptional condition.
making the app fit for SSL only requires enabling one flag, and
SOCKS/HTTP proxy support is built-in as well.

- easy to use
- supports timeout
- supports SSL (optional, currently using openssl or cyassl backend)
- supports chaining of socks4/4a/5 proxies a la proxychains.
  the maximum number of proxies can be configured at compiletime.
  using a single proxy works as well, of course.
- no global state (except for ssl init routines)
- error reporting mechanism, showing the exact type
- supports DNS resolving (can be turned off for smaller size)
- does not use malloc, and in the DNS-less profile, does not use
  any libc functions that could call it.
  (malloc typically adds at least 20KB to the binary size if
  statically linked).
  of course once you build it with ssl support, ssl will definitely
  make use of malloc().
  you need to add NO_STRDUP and NO_DNS_SUPPORT to your CFLAGS
  so nothing that can call malloc gets pulled in, if you want a 
  minimal static binary (in that case you have to pass ipv4
  addresses in dotted notation).
- optionally uses [libulz](https://github.com/rofl0r/libulz), 
  a lightweight C library, featuring things like
  a snprintf replacement which doesnt include code for float
  handling.
  this can make a statically linked binary a couple dozen KB
  smaller if no particularly bloated libc internals are being
  used in other parts of linked-in code.
  so if you use any SSL implementation, you won't gain anything
  by using libulz.

build:

  for a "default" build, for example for a distribution, just
  use ./configure && make as usual.

advanced/customized build using RcB:

  write your app, include the rocksock header using
  a relative pathname, and then use the build tool 
  [rcb](https://github.com/rofl0r/rcb) on your main
  C file, supplying all config options as CFLAGS. rcb will then
  automatically find all required translation units and throw them
  at once at the compiler, giving perfect opportunities for link-time
  optimization.

typical tree structure:
```
myapp/
rocksock/
lib/ (libulz)
```

myapp/main.c:
```c
/* tiny program to see if a specific port on a specific host
   is open for usage in shellscripts or similar. */
#include "../rocksock/rocksock.h"
#include <stdio.h>
#include <stdlib.h>

static void usage(void) {
        dprintf(2, "usage: prog ip port\n");
        exit(1);
}

int main(int argc, char** argv) {
        if(argc != 3) usage();
        rocksock s;
        rocksock_init(&s);
        rocksock_set_timeout(&s, 5000);
        int ret = rocksock_connect(&s, argv[1], atoi(argv[2]), 0);
        rocksock_clear(&s);
        return ret;
}
```

```sh
$ cd myapp
$ CFLAGS="-DUSE_SSL -flto -O3 -s -static" rcb main.c
```


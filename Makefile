#
# Makefile for proxychains (requires GNU make), stolen from musl
#
# Use config.mak to override any of the following variables.
# Do not make changes here.
#
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
includedir = $(prefix)/include
libdir = $(prefix)/lib

SRCS = $(sort $(wildcard *.c))
OBJS = $(SRCS:.c=.o)
LOBJS = $(OBJS:.o=.lo)
SONAME = librocksock.so
ANAME = librocksock.a

#EX_SRCS = $(sort $(wildcard examples/*.c))
EX_SRCS = examples/http_test.c examples/rocksock_test3.c
EX_PROGS = $(EX_SRCS:.c=.out)

CFLAGS  += -Wall -std=c99 -D_GNU_SOURCE -pipe 
INC     = 
PIC     = -fPIC -shared
AR      = $(CROSS_COMPILE)ar
RANLIB  = $(CROSS_COMPILE)ranlib
ALL_LIBS = $(ANAME)
ALL_INCLUDES = rocksock.h

-include config.mak

examples: $(ALL_LIBS) $(EX_PROGS)
	

all: $(ALL_LIBS)

install: $(ALL_LIBS:lib%=$(DESTDIR)$(libdir)/lib%) $(ALL_INCLUDES:%=$(DESTDIR)$(includedir)/%)

$(DESTDIR)$(libdir)/%: $(ALL_LIBS)
	install -D -m 644 $< $@

$(DESTDIR)$(lincludedir)/%: $(ALL_INCLUDES)
	install -D -m 644 $< $@

$(SONAME): $(LOBJS)
	$(CC) $(PIC) -Wl,-soname=$(SONAME) -o $(SONAME) $(LOBJS) $(LDFLAGS)

$(ANAME): $(OBJS)
	rm -f $@
	$(AR) rc $@ $(OBJS)
	$(RANLIB) $@

clean:
	rm -f $(OBJS)
	rm -f $(LOBJS)
	rm -f $(EX_PROGS)

%.o: %.c config.mak
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -c -o $@ $<

%.lo: %.c config.mak
	$(CC) $(CPPFLAGS) $(CFLAGS) $(PIC) $(INC) -c -o $@ $<

examples/micserver.out: LDFLAGS+=-lasound

%.out: %.c $(ANAME)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(INC) -o $@ $< -L. -lrocksock $(LDFLAGS)


.PHONY: all clean install

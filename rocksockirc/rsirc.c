#include "../rocksock.h"
#include "rsirc.h"
#include <stdio.h>
#ifdef USE_LIBULZ
#include <ulz/stdio-repl.h>
#endif
#include <stdarg.h>
#include <assert.h>

#define chk(x) if((ret = x)) return ret
#define sendl(x) rsirc_sendline(r, x)

int rsirc_init(struct rsirc *r, struct rocksock *s) {
	r->s = s;
	return 0;
}

int rsirc_sendline(struct rsirc *r, const char *line) {
	char buf[512];
	size_t written;
	// FIXME loop over this when strlen(line) > 510
	dprintf(2, "wrote %zu bytes\n", snprintf(buf, sizeof(buf), "%s\r\n", line));
	return rocksock_send(r->s, buf, 0, 0, &written);
}

int rsirc_sendlinef(struct rsirc *r, const char* fmt, ...) {
	va_list ap;
	va_start(ap, fmt);
	char buf[512];
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	return sendl(buf);
}

int rsirc_privmsg(struct rsirc *r, const char *chan, const char *msg) {
        char buf[512];
        snprintf(buf, sizeof buf, "PRIVMSG %s :%s", chan, msg);
        return sendl(buf);
}

int rsirc_privmsgf(struct rsirc *r, const char *dest, const char *fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        char buf[512];
        vsnprintf(buf, sizeof buf, fmt, ap);
        va_end(ap);
        return rsirc_privmsg(r, dest, buf);
}

int rsirc_handshake(struct rsirc *r, const char* host, const char* nick, const char* user) {
	char cmdbuf[512];
	int ret;
	snprintf(cmdbuf, sizeof(cmdbuf), "NICK %s", nick);
	chk(sendl(cmdbuf));
	snprintf(cmdbuf, sizeof(cmdbuf), "USER %s %s %s :%s", user, user, host, nick);
	chk(sendl(cmdbuf));
        return 0;
}

int rsirc_process(struct rsirc *r, char linebuf[512], size_t *rcvd) {
	int ret, has_data = 0;
	*rcvd = 0;
	chk(rocksock_peek(r->s, &has_data));
	if(has_data) {
		chk(rocksock_readline(r->s, linebuf, 512, rcvd));
		assert(*rcvd < 512);
		if(*rcvd != 0) {
			assert(*rcvd >= 1);
			assert(linebuf[(*rcvd) - 1] == '\r');
			linebuf[(*rcvd) - 1] = 0;
		}
	}
	return 0;
}

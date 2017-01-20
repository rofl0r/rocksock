#include "../rocksock.h"

typedef struct rsirc {
	struct rocksock *s;
} rsirc;

int rsirc_init(struct rsirc *r, struct rocksock *s);
int rsirc_handshake(struct rsirc *r, const char* host, const char* nick, const char* user);
int rsirc_sendline(struct rsirc *r, const char *line);
int rsirc_sendlinef(struct rsirc *r, const char* fmt, ...);
int rsirc_privmsg(struct rsirc *r, const char *chan, const char *msg);
int rsirc_privmsgf(struct rsirc *r, const char *dest, const char *fmt, ...);
int rsirc_process(struct rsirc *r, char linebuf[512], size_t *rcvd);

#if 0
enum rsirc_event {
	RSI_EVENT_NONE = 0,
	RSI_EVENT_UNKNOWN,
	RSI_EVENT_SYS_MSG,
	RSI_EVENT_MOTD_START,
	RSI_EVENT_MOTD_LINE,
	RSI_EVENT_MOTD_FINISH,
	RSI_EVENT_JOIN,
	RSI_EVENT_CHAN_TOPIC,
	RSI_EVENT_CHAN_TOPIC_SETTER,
	RSI_EVENT_NAMES_LINE,
	RSI_EVENT_NAMES_END,
	RSI_EVENT_NOTICE,
	RSI_EVENT_PRIVMSG,
};
#endif

//RcB: DEP "rsirc.c"


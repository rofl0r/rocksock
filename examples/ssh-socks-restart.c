/*
	SSH proxy "daemon" (C) 2011-2016 rofl0r.
	licensed under the MIT license.

	starts ssh client with parameters taken from a config file, then
	assures the connection is alive by doing cyclic connection checks
	using the SOCKS proxy port requested from the SSH server.
	if the connection is found dead, the ssh process is killed and
	a new connection established.
	the SOCKS proxy functionality is required and the server must be
	configured to allow it.
	additionally we require key-based authentication without user
	interaction (i.e. ssh keys without password).

	the config file has the following form:

[default]
# parameters that apply to all configurations
SOCKSIF=127.0.0.1:8080

[server1]
KEY=/path/to/my_rsa_key
LOGIN=user@server1.mynet.com

[server2]
KEY=/path/to/my_ed25519_key
LOGIN=joe@server2.mynet.com
PORT=222
EXTRA=-R 0.0.0.0:2222:127.0.0.1:22 -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null

	"EXTRA" is a field that allows you to specify additional
	stuff to append to the ssh commandline.

	(The example above creates a reverse tunnel to localhost's ssh port
	and binds it on the remote server on port 2222.
	Additionally it enables quiet mode and turns off known_hosts questions
	and checks. this is critical if this runs on a remote host you have
	no physical access to and rely on this program to work and not ask
	questions if something in your setup changed.)

	the program is started with the name of the config file and a
	configuration item,
	i.e. ./ssh-socks-restart my.conf server1

[testhosts]
google.com:443
4.68.80.110:80
msn.com
15.48.80.55
cnn.com
18.9.49.46:80
38.100.128.10:80

	testhosts section contains a list of host:port tuples to connect to
	to check if the socks connection is still up. i put some raw ips there
	as well to mitigate problems with DNS.

*/
#include "../rocksock.h"
#include <sys/wait.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>

static int cfg_gotosection(FILE *f, const char* section, char *buf, size_t bufsize) {
	size_t s = strlen(section);
	while(fgets(buf, bufsize, f)) {
		if(buf[0] == '[' && bufsize > s+2 && buf[1+s] == ']' && !strncmp(buf+1,section,s))
			return 1;
	}
	return 0;
}

static char* cfg_getstr(FILE *f, const char* section, const char *key, char*  buf, size_t bufsize) {
	fseek(f, 0, SEEK_SET);
	if(!cfg_gotosection(f, section, buf, bufsize)) return 0;
	size_t l = strlen(key);
	while(fgets(buf, bufsize, f)) {
		if(!strncmp(buf, key, l) && buf[l] == '=') {
			size_t x = l;
			while(buf[++x] != '\n');
			buf[x] = 0;
			memmove(buf, buf + l + 1, x - l);
			return buf;
		} else if(buf[0] == '[') break;
	}
	*buf = 0;
	return 0;
}

/* returns the number of elements in the list, 0 if none found, and
   a the *negative* count of the elements read so far if the buf
   was too small to read the entire section, or more than
   100 elements would have been there. */
static int cfg_getsection(FILE *f, const char* section, unsigned list_indices[static 100], char* buf, size_t bufsize) {
	fseek(f, 0, SEEK_SET);
	if(!cfg_gotosection(f, section, buf, bufsize)) return 0;
	char *p = buf;
	size_t left = bufsize;
	unsigned elems = 0;
	while(fgets(p, left, f)) {
		char *q = strrchr(p, '\n');
		if(!q) return -elems;
		*q = 0;
		if(p != q) {
			list_indices[elems++]=p-buf;
			if(p[0] == '[' && q[-1] == ']') return elems;
			if(elems == 100) return -elems;
		}
		q++;
		left -= q - p;
		p = q;
	}
	return elems;
}

static char *try_cfg_getstr(FILE *f, const char* section, const char *key, char*  buf, size_t bufsize) {
	char *p;
	if((p = cfg_getstr(f, section, key, buf, bufsize))) return p;
	else return cfg_getstr(f, "default", key, buf, bufsize);
}

struct testhosts_info {
	char buf[4096];
	unsigned count;
	unsigned indices[100];
};
static int read_config(const char* fn, char *section, char* key, char* login, char* port, char* socksif, char* extra, struct testhosts_info* testhosts) {
	printf("reading config...\n");
	FILE* f;
	if(!(f = fopen(fn, "r"))) {
		printf("error: config file %s not found\n", fn);
		return 0;
	}
	int err = 0;
	if(getenv("SOCKSIF")) strcpy(socksif, getenv("SOCKSIF"));
	else if(!try_cfg_getstr(f, section, "SOCKSIF", socksif, 128)) err++;
	if(!try_cfg_getstr(f, section, "KEY", key, 128)) err++;
	if(!try_cfg_getstr(f, section, "LOGIN", login, 128)) err++;
	if(err) {
		printf("error: SOCKSIF, KEY or LOGIN line missing in config\n");
		fclose(f);
		return 0;
	}
	if(!try_cfg_getstr(f, section, "PORT", port, 128)) strcpy(port, "22");
	try_cfg_getstr(f, section, "EXTRA", extra, 1024);
	testhosts->count = abs(cfg_getsection(f, "testhosts", testhosts->indices, testhosts->buf, sizeof testhosts->buf));

	fclose(f);
	return 1;
}

static char** build_argv(char* key, char* login, char* port, char* socksif, char* extra) {
	size_t e_items = 0, el = 0;
	char *p = extra;
	if(*p) e_items++;
	while(*p) {
		if(*p == ' ') e_items++;
		p++;
		el++;
	}
	size_t asz = (1+1+2+2+2+1+e_items+1)*sizeof(char*);
	char **res = malloc(asz+el+1);
	if(!res) return 0;
	char *ecopy = ((char*)(void*)res)+asz;
	memcpy(ecopy, extra, el+1);
	char **ret = res;
	*(res++)="ssh";
	*(res++)=login;
	*(res++)="-i";
	*(res++)=key;
	*(res++)="-p";
	*(res++)=port;
	*(res++)="-D";
	*(res++)=socksif;
	*(res++)="-N";
	p = ecopy;
	char *s = ecopy;
	while(*p) {
		if(*p == ' ') {
			*p = 0;
			*(res++)=s;
			s=p+1;
		}
		p++;
	}
	if(s < p) *(res++)=s;
	*res=0;
	return ret;
}

static int syntax(char* argv0) {
	printf("usage: %s configfile sectionname\n"
	       "establishes ssh connection with connectivity supervision.\n"
	       "read comment in source code for more info.\n", argv0);
	return 1;
}

#define PROCWAIT_SEC 10
#define TIMEOUT_SEC 20

static pid_t child = 0;

void sighandler(int sig) {
	if(child) {
		int foo;
		kill(child, sig);
		waitpid(child, &foo, 0);
	}
	_exit(1);
}

int main(int argc, char**argv) {
	if(argc != 3) return syntax(argv[0]);
	int fails = 0;
	signal(SIGTERM, sighandler);
	signal(SIGINT, sighandler);
	while(1) {
		char key[128], login[128], port[128], socksif[128], extra[1024];
		struct testhosts_info testhosts;
		if(!read_config(argv[1], argv[2], key, login, port, socksif, extra, &testhosts)) {
			dprintf(2, "error processing config\n");
			return 1;
		}
		dprintf(2, "starting process...");
		if(!(child = fork())) {
			char**nargs=build_argv(key, login, port, socksif, extra);
			if(!nargs) {
				dprintf(2, "out of memory, retrying later...\n");
				e_cont:
				sleep(PROCWAIT_SEC);
				continue;
			}
			if(execvp("ssh", nargs)) {
				perror("exec");
				free(nargs);
				goto e_cont;
			}
		}
		dprintf(2, "%d\n", (int) child);
		sleep(PROCWAIT_SEC);

		int connected = 0;
		while(1) {
			int ret, loc;
			ret = waitpid(child, &loc, WNOHANG);
			dprintf(2, "got waitpid result %d, stat %d\n", ret, loc);
			if(ret == child) {
				dprintf(2, "child == ret, break\n");
				break;
			}
			sleep(connected ? PROCWAIT_SEC : 2);
			rocksock rs, *r = &rs;
			rs_proxy proxies[1];
			rocksock_init(r, proxies);
			//rocksock_set_timeout(r, (TIMEOUT_SEC / (fails+1)) * 1000);
			rocksock_set_timeout(r, (TIMEOUT_SEC / 1) * 1000);
			char socksbuf[128];
			strcpy(socksbuf, socksif);
			char *p = strchr(socksbuf, ':');
			*p = 0;
			rocksock_add_proxy(r, RS_PT_SOCKS5, socksbuf, atoi(p+1), 0, 0);
			static unsigned srvno = 0;
			if(srvno >= testhosts.count) {
				if(!srvno) {
					dprintf(2, "error: testhosts section missing or no testhosts specified\n");
					return 1;
				}
				srvno = 0;
			}

			char hostnamebuf[524], *port;
			snprintf(hostnamebuf, sizeof hostnamebuf, "%s", testhosts.buf+testhosts.indices[srvno++]);
			port = strchr(hostnamebuf, ':');
			if(!port) port = "80";
			else *(port++) = 0;
			dprintf(2, "connecting to %s...\n", hostnamebuf);
			ret = rocksock_connect(r, hostnamebuf, atoi(port), 0);
			rocksock_disconnect(r);
			rocksock_clear(r);
			if(ret) {
				fails++;
				dprintf(2, "fail %d\n", fails);
				if(!connected || fails > 3) {
					dprintf(2, "connection failed, killing %d\n", (int) child);
					kill(child, SIGKILL);
					ret = waitpid(child, &loc, 0);
					child = 0;
					fails = 0;
					break;
				}
			} else {
				dprintf(2, "success.\n");
				fails = 0;
				connected = 1;
			}
			sleep(TIMEOUT_SEC / (fails+1));
		}
		sleep(1);
	}
}


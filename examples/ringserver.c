/* example of a simple server that plays a wave file using aplay when
   someone connects. */

#include "../rocksockserver.h"
#include <sys/wait.h>
#include <unistd.h>

int on_clientconnect (void* userdata, struct sockaddr_storage* clientaddr, int fd) {
	rocksockserver *s = userdata;
	rocksockserver_disconnect_client(s, fd);
	pid_t pid = fork();
	if(!pid) execl("/bin/sh", "/bin/sh", "-c", "aplay /root/ring.wav", (char*) 0);
	else waitpid(pid, 0, 0);
	return 0;
}

int main() {
	int port = 9999;
	char* listenip = "0.0.0.0";
	rocksockserver s;
	if(rocksockserver_init(&s, listenip, port, &s)) return -1;
	if(rocksockserver_loop(&s, NULL, 0, &on_clientconnect, 0, 0, 0)) return -2;
	return 0;
}

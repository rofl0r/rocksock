/*
 * author: rofl0r
 *
 * License: LGPL 2.1+ with static linking exception

 * soundplay server: waits for a client to connect,
 * then passes stream received to audio hardware.
 * designed to stream microphone input from one computer to
 * the other.
 */

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <alsa/asoundlib.h>
#include <pthread.h>

#include "micbuffer.h"

#include "../rocksockserver.h"


//RcB: CFLAGS "-std=c99 -D_GNU_SOURCE -DVERBOSE"
//RcB: LINK "-lasound -lpthread"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define MICSERVER_NUMBUFFERS 20

#ifdef VERBOSE
#define DPRINTF(fd, ...) dprintf(fd, __VA_ARGS__)
#else
#define DPRINTF(fd, ...)
#endif

typedef struct client {
	int fd;
	unsigned char wave[MICSERVER_NUMBUFFERS][MIC_BUFFER_SIZE];
	unsigned long long samples_recvd;
	unsigned long long samples_consumed;
	snd_pcm_t *playback_handle;
	pthread_mutex_t mtx;
	pthread_t thr;
	int terminate;
} client;

typedef struct server_state {
	rocksockserver srv;
	const char* audiodevice;
} server;

static struct progstate {
	server s;
	client client;
} p;

static void disconnect_client(server* s, int fd) {
	if(p.client.fd == fd) {
		struct client* c = &p.client;
		c->terminate = -1;
		pthread_join(c->thr, 0);
		snd_pcm_close(c->playback_handle);
		c->fd = -1;
	}
	rocksockserver_disconnect_client(&s->srv, fd);
}

static int on_cdisconnect (void* userdata, int fd) {
	server* s = userdata;
	disconnect_client(s, fd);
	return 0;
}

static const char* getstatus_string(snd_pcm_state_t status) {
	switch (status) {
		case SND_PCM_STATE_PAUSED:
			return "SND_PCM_STATE_PAUSED";
		case SND_PCM_STATE_SETUP:
			return "SND_PCM_STATE_SETUP";
		case SND_PCM_STATE_PREPARED:
			return "SND_PCM_STATE_PREPARED";
		case SND_PCM_STATE_SUSPENDED:
			return "SND_PCM_STATE_SUSPENDED";
		case SND_PCM_STATE_DISCONNECTED:
			return "SND_PCM_STATE_DISCONNECTED";
		case SND_PCM_STATE_XRUN:
			return "SND_PCM_STATE_XRUN";
		case SND_PCM_STATE_DRAINING:
			return "SND_PCM_STATE_DRAINING";
		case SND_PCM_STATE_RUNNING:
			return "SND_PCM_STATE_RUNNING";
		default:
			return "UNKNOWN";
	}
}

static void chk(const int err, const char* msg) {
	if(err < 0) {
		dprintf(2, msg, snd_strerror(err));
		exit(1);
	}
}

static snd_pcm_t* init_playback_device(const char* devname) {
	snd_pcm_t *playback_handle;
	snd_pcm_hw_params_t *hw_params;
	chk(snd_pcm_open(&playback_handle, devname, SND_PCM_STREAM_PLAYBACK,0), "cannot open audio device (%s)\n");
	chk(snd_pcm_hw_params_malloc(&hw_params), "cannot allocate hardware parameter structure (%s)\n");
	chk(snd_pcm_hw_params_any(playback_handle, hw_params), "cannot initialize hardware parameter structure (%s)\n");
	chk(snd_pcm_hw_params_set_access(playback_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED), "cannot set access type (%s)\n");
	chk(snd_pcm_hw_params_set_format(playback_handle, hw_params, FORMAT), "cannot set sample format (%s)\n");
	unsigned rate = BITRATE;
	chk(snd_pcm_hw_params_set_rate_near(playback_handle, hw_params, &rate, 0), "cannot set sample rate (%s)\n");
	chk(snd_pcm_hw_params_set_channels(playback_handle, hw_params, NUMCHANNELS),"cannot set channel count (%s)\n");
	chk(snd_pcm_hw_params(playback_handle, hw_params), "cannot set parameters (%s)\n");
	snd_pcm_hw_params_free(hw_params);
	chk(snd_pcm_prepare(playback_handle), "cannot prepare audio interface for use (%s)\n");
	return playback_handle;
}

static unsigned long long get_recvd(client *c) {
	unsigned long long l;
	pthread_mutex_lock(&c->mtx);
	l = c->samples_recvd;
	pthread_mutex_unlock(&c->mtx);
	return l;
}

static void play(snd_pcm_t *playback_handle, const unsigned char* buf, size_t s) {
	int ret = snd_pcm_writei(playback_handle, buf, s);
	if (ret<0) {
		DPRINTF(2, "write to audio interface failed (%s)\n", snd_strerror(ret));
		snd_pcm_state_t state = snd_pcm_state(playback_handle);
                DPRINTF(2, "%s\n", getstatus_string(state));
                if(state == SND_PCM_STATE_XRUN) snd_pcm_recover(playback_handle, ret, 1);
	}
}

static void *c_thread(void *userdata) {
	client *c = userdata;
	while(!c->terminate) {
		if(get_recvd(c) - c->samples_consumed >= ARRAY_SIZE(c->wave)/2) {
			do {
				unsigned x = c->samples_consumed % ARRAY_SIZE(c->wave);
				DPRINTF(2, "playing samplebuf %u\n", x);
				play(c->playback_handle, c->wave[x], sizeof(c->wave[0]));
				c->samples_consumed++;
			} while(get_recvd(c) - c->samples_consumed > 0);
		}
		usleep(1);
	}
	return 0;
}

static int on_cconnect (void* userdata, struct sockaddr_storage* clientaddr, int fd) {
	(void) clientaddr;
	server* s = userdata;
	if(p.client.fd != -1) {
		disconnect_client(s, fd);
		return -1;
	}
	struct client* c = &p.client;
	c->fd = fd;
	c->terminate = 0;
	c->playback_handle = init_playback_device(s->audiodevice);
	pthread_mutex_init(&c->mtx, 0);
	pthread_create(&c->thr, 0, c_thread, c);
	return 0;
}

static int on_cread (void* userdata, int fd, size_t dummy) {
	(void) dummy;
	server* s = userdata;
	struct client *c = &p.client;
	unsigned x = c->samples_recvd % ARRAY_SIZE(c->wave);
	DPRINTF(2, "receiving samplebuf %u\n", x);
	if(sizeof(c->wave[0]) != recv(fd, c->wave[x], sizeof(c->wave[0]), 0)) {
		disconnect_client(s, fd);
		return 0;
	}
	pthread_mutex_lock(&c->mtx);
	c->samples_recvd++;
	pthread_mutex_unlock(&c->mtx);
	return 0;
}

static int on_cwantsdata (void* userdata, int fd) {
	server* s = userdata;
	return 0;
}

int main(int argc, char** argv) {
	server *s = &p.s;
	p.client.fd = -1;
	s->audiodevice = argc > 1 ? argv[1] : "default";
	const int port = 9999;
	const char* listenip = "0.0.0.0";
	if(rocksockserver_init(&s->srv, listenip, port, (void*) s)) return -1;
	rocksockserver_set_sleeptime(&s->srv, BITRATE);
	if(rocksockserver_loop(&s->srv, NULL, 0,
	                       &on_cconnect, &on_cread,
	                       &on_cwantsdata, &on_cdisconnect)) return -2;
	return 0;
}

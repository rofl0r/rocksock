/*
 * author: rofl0r
 *
 * License: LGPL 2.1+ with static linking exception

 * streams microphone input to a server
 * use arecord -L to see available alsa device names

 */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <alsa/asoundlib.h>

#include "micbuffer.h"

#include "../rocksock.h"

//RcB: CFLAGS "-std=c99 -D_GNU_SOURCE -Wall"
//RcB: LINK "-lasound"

#define chks(X, ACTION) if(X) { rocksock_error_dprintf(2, psock); ACTION; }
#define checkerr() chks(ret, exit(2))

static void chk(const int err, const char* msg) {
	if(err < 0) {
		fprintf(stderr, msg, snd_strerror(err));
		exit(1);
	}
}

static snd_pcm_t* init_record_device(const char* devname) {
	snd_pcm_t *capture_handle;
	snd_pcm_hw_params_t *hw_params;
	chk(snd_pcm_open(&capture_handle, devname, SND_PCM_STREAM_CAPTURE, 0), "cannot open audio device (%s)\n");
	chk(snd_pcm_hw_params_malloc(&hw_params), "cannot allocate hardware parameter structure (%s)\n");
	chk(snd_pcm_hw_params_any(capture_handle, hw_params), "cannot initialize hardware parameter structure (%s)\n");
	chk(snd_pcm_hw_params_set_access(capture_handle, hw_params, SND_PCM_ACCESS_RW_INTERLEAVED),"cannot set access type (%s)\n");
	chk(snd_pcm_hw_params_set_format(capture_handle, hw_params, FORMAT),"cannot set sample format (%s)\n");
	unsigned rate = BITRATE;
	chk(snd_pcm_hw_params_set_rate_near(capture_handle, hw_params, &rate,0),"cannot set sample rate (%s)\n");
	chk(snd_pcm_hw_params_set_channels(capture_handle, hw_params, NUMCHANNELS),"cannot set channel count (%s)\n");
	chk(snd_pcm_hw_params(capture_handle, hw_params),"cannot set parameters (%s)\n");
	snd_pcm_hw_params_free(hw_params);
	chk(snd_pcm_prepare(capture_handle),"cannot prepare audio interface for use (%s)\n");
	return capture_handle;
}

static int interrupted;
static void sigint(int dummy) {
	(void) dummy;
	interrupted = 1;
}

int main(int argc, char** argv) {
	rocksock sock;
	rocksock* psock = &sock;
	int ret;
	unsigned char inbuf[MIC_BUFFER_SIZE];
	size_t bytesread;

	if(argc < 3) {
		puts("need ip or dns name of server as argv1 and alsa devicename as argv2");
		return 1;
	}

	rocksock_init(psock, NULL);
	rocksock_set_timeout(psock, 10000);

	ret = rocksock_connect(psock, argv[1], 9999, 0);
	checkerr();

	snd_pcm_t *capture_handle = init_record_device(argv[2]);
	signal(SIGINT, sigint);
	while(!interrupted) {
		chk(snd_pcm_readi(capture_handle, inbuf, sizeof inbuf), "read from audio interface failed (%s)\n");
		ret = rocksock_send(psock, (void*)inbuf, sizeof inbuf, sizeof inbuf, &bytesread);
		checkerr();
	}
	snd_pcm_close(capture_handle);
	rocksock_disconnect(psock);
	rocksock_clear(psock);
	return 0;
}

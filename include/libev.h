#ifndef __LIBEV_H__
#define __LIBEV_H__

#include <ev.h>
#include <stdint.h>
#include <stdbool.h>

#include "sbuf.h"

enum libev_ret {
	LIBEV_RET_OK,
	LIBEV_RET_ERROR,
};

struct libev_conn;
typedef enum libev_ret (*libev_cb_t)(struct libev_conn *cn);

struct libev_conn {
	void *ctx;
	struct ev_io w;
	struct ev_cleanup gc;

	libev_cb_t read_cb;
	libev_cb_t write_cb;
	libev_cb_t destroy_cb;

	struct sbuf rbuf;
	struct sbuf wbuf;
};

void libev_run();
int libev_initialize();

void libev_send(struct libev_conn *cn, const void *data, size_t size);
enum libev_ret libev_connect_to(struct libev_conn *cn, uint16_t port,
				uint32_t host, libev_cb_t cb);

#endif

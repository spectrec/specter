#ifndef __LIBEV_H__
#define __LIBEV_H__

#include <ev.h>
#include <stdint.h>
#include <stdbool.h>

#include "sbuf.h"

enum libev_ret {
	LIBEV_RET_OK = 0,
	LIBEV_RET_ERROR = 1,
	LIBEV_RET_CLOSE_CONN = 1,
};

enum libev_timer_ret {
	LIBEV_TIMER_RET_CONT,
	LIBEV_TIMER_RET_STOP,
};

struct libev_conn;
typedef enum libev_ret (*libev_cb_t)(struct libev_conn *cn);

struct libev_timer;
typedef enum libev_timer_ret (*libev_timer_cb_t)(struct libev_timer *t, void *ctx);

struct libev_timer {
	struct ev_timer t;
	struct ev_cleanup gc;

	float interval;
	float delay;

	libev_timer_cb_t cb;
	void *ctx;
};

struct libev_conn {
	void *ctx;
	struct ev_io w;
	struct ev_timer t;
	struct ev_timer dt; // delay
	struct ev_cleanup gc;

	libev_cb_t read_cb;
	libev_cb_t timeout_cb;
	libev_cb_t destroy_cb;
	union {
		libev_cb_t write_cb;
		libev_cb_t accept_cb;
	};

	struct sbuf rbuf;
	struct sbuf wbuf;
};

void libev_run();
void libev_stop();
int libev_initialize();

int libev_socket_error_occurred(int fd);

struct libev_conn *libev_create_conn(void);
void libev_cleanup_conn(struct libev_conn *cn);

struct libev_conn *libev_accept(struct libev_conn *cn);
void libev_send(struct libev_conn *cn, const void *data, size_t size);
enum libev_ret libev_bind_listen_tcp_socket(uint16_t port, uint32_t addr,
					    libev_cb_t listen_parser);
enum libev_ret libev_connect_to(struct libev_conn *cn, uint16_t port,
				uint32_t host, libev_cb_t cb,
				float timeout, libev_cb_t timeout_cb);

struct libev_timer *libev_timer_create(float interval, float delay,
				       libev_timer_cb_t cb, void *ctx);
void libev_timer_destroy(struct libev_timer *t);
void libev_timer_start(struct libev_timer *t);
void libev_timer_stop(struct libev_timer *t);

void libev_conn_on_read(struct libev_conn *cn);
void libev_conn_off_read(struct libev_conn *cn);
void libev_conn_on_write(struct libev_conn *cn);
void libev_conn_off_write(struct libev_conn *cn);
void libev_conn_off_timer(struct libev_conn *cn);

#endif

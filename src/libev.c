#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "log.h"
#include "pack.h"
#include "sbuf.h"
#include "libev.h"
#include "config.h"
#include "specter.h"

#define LIBEV_CONN(_w, _n) (struct libev_conn *)(((char *)_w) - offsetof(struct libev_conn, _n));

static struct ev_loop *__loop;

__attribute__((destructor))
static void libev_cleanup(void)
{
	ev_loop_destroy(__loop);
}

int libev_socket_error_occurred(int fd)
{
	int error;
	socklen_t optlen = sizeof(error);

	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &optlen) != 0) {
		log_e("getsockopt failed: %s", strerror(errno));

		return 1;
	}
	if (error != 0) {
		log_e("connection failed: %s", strerror(error));

		return 1;
	}

	return 0;
}

static int libev_set_socket_nonblock(int fd)
{
	assert(fd != -1);

	int flags = fcntl(fd, F_GETFL);
	if (flags < 0) {
		log_e("can't get socket flags: %s", strerror(errno));
		return -1;
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
		log_e("can't set socket nonblocking: %s", strerror(errno));
		return -1;
	}

	return 0;
}

#define DEFAULT_READ_LEN 4096
static void libev_read_cb(EV_P_ ev_io *w, int revent)
{
	struct libev_conn *lc = LIBEV_CONN(w, w);
	bool new_data = false, close_connection = false;

	(void)loop;
	(void)revent;

	do {
		char buf[DEFAULT_READ_LEN + 1] = {0};
		ssize_t ret = recv(w->fd, buf, sizeof(buf) - 1, 0);

		if (ret < 0) {
			if (errno == EAGAIN)
				break;

			log_e("[%d] recv error: %s", w->fd, strerror(errno));
			libev_cleanup_conn(lc);

			return;
		}

		if (ret == 0) {
			close_connection = true;
			break;
		}

		sbuf_append(&lc->rbuf, buf, ret);
		new_data = true;
	} while (1);

	if (lc->read_cb != NULL && new_data == true &&
	    lc->read_cb(lc) != LIBEV_RET_OK)
		close_connection = true;

	if (close_connection == true)
		libev_cleanup_conn(lc);
}

static void libev_write_cb(EV_P_ ev_io *w, int revent)
{
	struct libev_conn *lc = LIBEV_CONN(w, w);

	(void)loop;
	(void)revent;

	if (lc->wbuf.size != 0) {
		ssize_t ret = send(w->fd, lc->wbuf.data, lc->wbuf.size, 0);
		if (ret < 0) {
			log_e("send error: %s", strerror(errno));
			libev_cleanup_conn(lc);

			return;
		}

		if (ret == 0 && lc->wbuf.size != 0)
			log_w("nothing was sent by [%d], try again", lc->w.fd);

		sbuf_shrink(&lc->wbuf, ret);
	}

	if (lc->wbuf.size == 0) {
		libev_conn_off_write(lc);
		ev_timer_stop(EV_A_ &lc->dt);
	} else if ((w->events & EV_WRITE) == 0)
		// It may be possible, if called from `libev_send()'
		libev_conn_on_write(lc);

	if (lc->write_cb != NULL && lc->write_cb(lc) != LIBEV_RET_OK)
		libev_cleanup_conn(lc);
}

static void libev_cb(EV_P_ ev_io *w, int revent)
{
	if ((revent & EV_READ) != 0)
		libev_read_cb(EV_A_ w, revent);
	else if ((revent & EV_WRITE) != 0)
		libev_write_cb(EV_A_ w, revent);
}

static void libev_signal_cb(EV_P_ ev_signal *w, int revents)
{
	(void)revents;

	switch (w->signum) {
	case SIGPIPE:
		log_w("received SIGPIPE");
		return;

	case SIGINT:
	case SIGTERM:
	case SIGQUIT:
		log_w("received signal `%d': exiting...", w->signum);
		ev_break(loop, EVBREAK_ALL);

		return;
	default:
		log_e("unknown signal received, num: `%d'", w->signum);
	}
}

static void libev_cleanup_cb(EV_P_ ev_cleanup *gc)
{
	struct libev_conn *lc = LIBEV_CONN(gc, gc);

	(void)loop;

	libev_cleanup_conn(lc);
}

static void libev_accept_cb(EV_P_ ev_io *w, int events)
{
	struct libev_conn *cn = LIBEV_CONN(w, w);

	(void)loop;
	(void)events;

	if (cn->accept_cb(cn) != LIBEV_RET_OK)
		libev_cleanup_conn(cn);
}

static void libev_timeout_cb(EV_P_ ev_timer *t)
{
	struct libev_conn *lc = LIBEV_CONN(t, t);

	(void)loop;

	if (lc->timeout_cb == NULL)
		log_w("timeout on connect [%d]", lc->w.fd);

	if (lc->timeout_cb == NULL ||
	    lc->timeout_cb(lc) != LIBEV_RET_OK)
		libev_cleanup_conn(lc);
}

static void libev_add_events(struct libev_conn *cn, int events)
{
	if ((cn->w.events & events) == events)
		return;

	ev_io_stop(__loop, &cn->w);
	ev_io_set(&cn->w, cn->w.fd, cn->w.events | events);
	ev_io_start(__loop, &cn->w);
}

static void libev_del_events(struct libev_conn *cn, int events)
{
	if ((cn->w.events & events) == 0)
		return;

	ev_io_stop(__loop, &cn->w);
	ev_io_set(&cn->w, cn->w.fd, cn->w.events & (~events));
	ev_io_start(__loop, &cn->w);
}

void libev_conn_on_read(struct libev_conn *cn)
{
	libev_add_events(cn, EV_READ);
}

void libev_conn_off_read(struct libev_conn *cn)
{
	libev_del_events(cn, EV_READ);
}

void libev_conn_on_write(struct libev_conn *cn)
{
	libev_add_events(cn, EV_WRITE);
}

void libev_conn_off_write(struct libev_conn *cn)
{
	libev_del_events(cn, EV_WRITE);
}

void libev_conn_off_timer(struct libev_conn *cn)
{
	ev_timer_stop(__loop, &cn->t);
}

struct libev_conn *libev_accept(struct libev_conn *listen_cn)
{
	int client_fd;
	struct libev_conn *cn;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	client_fd = accept(listen_cn->w.fd, (struct sockaddr *)&sa, &sa_len);
	if (client_fd < 0) {
		log_e("can't accept new client: %s", strerror(errno));

		return NULL;
	}

	if (libev_set_socket_nonblock(client_fd) != 0) {
		(void)close(client_fd);

		return NULL;
	}

	cn = libev_create_conn();
	ev_io_init(&cn->w, libev_cb, client_fd, EV_NONE);
	ev_io_start(__loop, &cn->w);

	log_d("accept new client [%d]", client_fd);

	return cn;
}

#define LISTEN_QUEUE_SIZE 16
enum libev_ret libev_bind_listen_tcp_socket(uint16_t port, uint32_t addr,
					    libev_cb_t listen_parser)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		log_e("can't create socket: %s", strerror(errno));

		return -1;
	}

	long reuse_addr = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse_addr, sizeof(reuse_addr)) != 0) {
		log_e("can't setsockopt: %s", strerror(errno));
		(void)close(fd);

		return -1;
	}

	if (libev_set_socket_nonblock(fd) != 0) {
		(void)close(fd);

		return -1;
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));

	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(addr);

	if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		log_e("bind error: %s", strerror(errno));
		(void)close(fd);

		return -1;
	}

	if (listen(fd, LISTEN_QUEUE_SIZE) != 0) {
		log_e("listen error: %s", strerror(errno));
		(void)close(fd);

		return -1;
	}

	struct libev_conn *cn = libev_create_conn();
	ev_io_init(&cn->w, libev_accept_cb, fd, EV_READ);
	ev_io_start(__loop, &cn->w);
	cn->accept_cb = listen_parser;

	return 0;
}

static void libev_conn_delay_timer_cb(EV_P_ ev_timer *t)
{
	struct libev_conn *cn = LIBEV_CONN(t, dt);

	if (cn->wbuf.size != 0)
		libev_write_cb(EV_A_ &cn->w, EV_WRITE);
}

struct libev_conn *libev_create_conn(void)
{
	struct libev_conn *cn;

	assert(__loop != NULL);

	cn = calloc(1, sizeof(*cn));
	assert(cn != NULL);

	sbuf_init(&cn->rbuf);
	sbuf_init(&cn->wbuf);

	ev_cleanup_init(&cn->gc, libev_cleanup_cb);
	ev_cleanup_start(__loop, &cn->gc);

	ev_timer_init(&cn->dt, libev_conn_delay_timer_cb, 0, 0);

	return cn;
}

void libev_cleanup_conn(struct libev_conn *lc)
{
	lc->read_cb = NULL;
	lc->write_cb = NULL;

	(void)close(lc->w.fd);
	log_d("conn [%d] closed", lc->w.fd);

	ev_io_stop(__loop, &lc->w);
	ev_timer_stop(__loop, &lc->t);
	ev_timer_stop(__loop, &lc->dt);
	ev_cleanup_stop(__loop, &lc->gc);

	if (lc->ctx != NULL) {
		assert(lc->destroy_cb != NULL);
		lc->destroy_cb(lc);

		assert(lc->ctx == NULL);
	}

	sbuf_delete(&lc->rbuf);
	sbuf_delete(&lc->wbuf);

	free(lc);
}

// XXX: `port' and `host' should have network byte order
enum libev_ret libev_connect_to(struct libev_conn *cn, uint16_t port,
				uint32_t host, libev_cb_t cb,
				float timeout, libev_cb_t timeout_cb)
{
	struct sockaddr_in sa;
	int fd;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		log_e("can't create socket: %s", strerror(errno));
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	ev_io_init(&cn->w, libev_cb, fd, EV_WRITE);
	ev_io_start(__loop, &cn->w);

	cn->timeout_cb = timeout_cb;
	ev_timer_init(&cn->t, libev_timeout_cb, timeout, 0.);
	ev_timer_start(__loop, &cn->t);

	if (libev_set_socket_nonblock(fd) != 0) {
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_addr.s_addr = host;
	sa.sin_family = AF_INET;
	sa.sin_port = port;

	log_d("[%d] connect start", fd);

	cn->write_cb = cb;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		if (errno == EINPROGRESS)
			return LIBEV_RET_OK;

		log_e("connect [%d] failed: %s", fd, strerror(errno));
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	return LIBEV_RET_OK;
}

static void libev_init_signal_handlers()
{
	static struct ev_signal __sigint_watcher;
	static struct ev_signal __sigterm_watcher;
	static struct ev_signal __sigquit_watcher;
	static struct ev_signal __sigpipe_watcher;

	ev_signal_init(&__sigpipe_watcher, libev_signal_cb, SIGPIPE);
	ev_signal_start(__loop, &__sigpipe_watcher);

	ev_signal_init(&__sigint_watcher, libev_signal_cb, SIGINT);
	ev_signal_start(__loop, &__sigint_watcher);

	ev_signal_init(&__sigterm_watcher, libev_signal_cb, SIGTERM);
	ev_signal_start(__loop, &__sigterm_watcher);

	ev_signal_init(&__sigquit_watcher, libev_signal_cb, SIGQUIT);
	ev_signal_start(__loop, &__sigquit_watcher);
}

static void libev_timer_cb(EV_P_ ev_timer *t)
{
	struct libev_timer *lt = (struct libev_timer *)((void *)t - offsetof(struct libev_timer, t));

	(void)loop;

	switch (lt->cb(lt, lt->ctx)) {
	case LIBEV_TIMER_RET_CONT:
		break;
	case LIBEV_TIMER_RET_STOP:
		libev_timer_stop(lt);
		break;
	default:
		abort();
	}
}

struct libev_timer *libev_timer_create(float interval, float delay,
				       libev_timer_cb_t cb, void *ctx)
{
	struct libev_timer *t;

	t = calloc(1, sizeof(*t));
	t->interval = interval;
	t->delay = delay;
	t->ctx = ctx;
	t->cb = cb;

	ev_timer_init(&t->t, libev_timer_cb, interval, 0);

	return t;
}

void libev_timer_start(struct libev_timer *t)
{
	ev_timer_start(__loop, &t->t);
}

void libev_timer_stop(struct libev_timer *t)
{
	ev_timer_stop(__loop, &t->t);
}

void libev_timer_destroy(struct libev_timer *t)
{
	libev_timer_stop(t);
	free(t);
}

int libev_initialize()
{
	__loop = EV_DEFAULT;
	libev_init_signal_handlers();
	srand((unsigned)time(NULL));

	return 0;
}

void libev_run()
{
	ev_run(__loop, 0);
}

void libev_stop()
{
	ev_break(__loop, EVBREAK_ALL);
}

void libev_send(struct libev_conn *cn, const void *data, size_t size)
{
	struct config *conf;
	uint32_t delay;
	float after;

	sbuf_append(&cn->wbuf, data, size);
	libev_conn_on_write(cn);

	if (ev_is_active(&cn->dt) == true || ev_is_pending(&cn->dt) == true)
		// Timer is already activated
		return;

	conf = config_get();
	delay = (uint32_t)(conf->send_delay * 1e6); // msecs
	after = (rand() % delay) / 1e6f;

	ev_timer_set(&cn->dt, after, 0.);
	ev_timer_start(__loop, &cn->dt);
}

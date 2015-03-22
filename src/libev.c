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
#include "sbuf.h"
#include "libev.h"
#include "config.h"
#include "specter.h"

#define LIBEV_CONN(_w, _n) (struct libev_conn *)(((char *)_w) - offsetof(struct libev_conn, _n));

static struct ev_loop *__loop;
//static struct ev_io __node_watcher; // accept connections from nodes
static struct ev_io __client_watcher; // accept connections from clients

static struct ev_signal __sigint_watcher;
static struct ev_signal __sigterm_watcher;
static struct ev_signal __sigquit_watcher;
static struct ev_signal __sigpipe_watcher;

static void libev_read_cb(EV_P_ ev_io *w, int revent);
static void libev_write_cb(EV_P_ ev_io *w, int revent);
//static void libev_accept_new_node_cb(EV_P_ ev_io *w, int revents);
static void libev_accept_new_client_cb(EV_P_ ev_io *w, int revents);

__attribute__((destructor))
static void libev_cleanup(void)
{
	ev_loop_destroy(__loop);
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

#define LISTEN_QUEUE_SIZE 16
static int libev_bind_listen_tcp_socket(uint16_t port, uint32_t addr)
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

	return fd;
}

static void libev_cleanup_conn(struct libev_conn *lc)
{
	lc->read_cb = NULL;
	lc->write_cb = NULL;

	(void)close(lc->w.fd);
	ev_io_stop(__loop, &lc->w);
	ev_cleanup_stop(__loop, &lc->gc);

	lc->destroy_cb(lc);

	sbuf_delete(&lc->rbuf);
	sbuf_delete(&lc->wbuf);

	free(lc);
}

static void libev_cb(EV_P_ ev_io *w, int revent)
{
	if ((revent & EV_READ) != 0)
		libev_read_cb(EV_A_ w, revent);
	else if ((revent & EV_WRITE) != 0)
		libev_write_cb(EV_A_ w, revent);
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

			log_e("recv error: %s", strerror(errno));
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
		// TODO: disable it here if buffer is empty
	}

	if (lc->write_cb != NULL && lc->write_cb(lc) != LIBEV_RET_OK)
		libev_cleanup_conn(lc);
}

static void libev_signal_handler(EV_P_ ev_signal *w, int revents)
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

static void libev_init_signal_handlers()
{
	ev_signal_init(&__sigpipe_watcher, libev_signal_handler, SIGPIPE);
	ev_signal_start(__loop, &__sigpipe_watcher);

	ev_signal_init(&__sigint_watcher, libev_signal_handler, SIGINT);
	ev_signal_start(__loop, &__sigint_watcher);

	ev_signal_init(&__sigterm_watcher, libev_signal_handler, SIGTERM);
	ev_signal_start(__loop, &__sigterm_watcher);

	ev_signal_init(&__sigquit_watcher, libev_signal_handler, SIGQUIT);
	ev_signal_start(__loop, &__sigquit_watcher);
}

/*
static void libev_accept_new_node_cb(EV_P_ ev_io *w, int revents)
{
	(void)w;
	(void)revents;
}
*/

static void libev_cleanup_cb(EV_P_ ev_cleanup *gc)
{
	struct libev_conn *lc = LIBEV_CONN(gc, gc);

	(void)loop;

	libev_cleanup_conn(lc);
}

// XXX: `port' and `host' should have network byte order
enum libev_ret libev_connect_to(struct libev_conn *cn, uint16_t port,
				uint32_t host, libev_cb_t cb)
{
	int fd;
	struct sockaddr_in sa;

	fd = socket(AF_INET, SOCK_STREAM, 0);
	ev_io_init(&cn->w, libev_cb, fd, EV_READ | EV_WRITE);
	ev_io_start(__loop, &cn->w);

	ev_cleanup_init(&cn->gc, libev_cleanup_cb);
	ev_cleanup_start(__loop, &cn->gc);

	if (fd < 0) {
		log_e("can't create socket: %s", strerror(errno));
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	if (libev_set_socket_nonblock(fd) != 0) {
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sin_addr.s_addr = host;
	sa.sin_family = AF_INET;
	sa.sin_port = port;

	cn->write_cb = cb;
	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
		if (errno == EINPROGRESS)
			return LIBEV_RET_OK;

		log_e("connect failed: %s", strerror(errno));
		libev_cleanup_conn(cn);

		return LIBEV_RET_ERROR;
	}

	return LIBEV_RET_OK;
}

static void libev_accept_new_client_cb(EV_P_ ev_io *w, int revents)
{
	int client_fd;
	struct libev_conn *cn;
	struct sockaddr_in sa;
	socklen_t sa_len = sizeof(sa);

	(void)loop;
	(void)revents;

	client_fd = accept(w->fd, (struct sockaddr *)&sa, &sa_len);
	if (client_fd < 0) {
		log_e("can't accept new client: %s", strerror(errno));

		return;
	}

	if (libev_set_socket_nonblock(client_fd) != 0) {
		(void)close(client_fd);

		return;
	}

	cn = calloc(1, sizeof(*cn));
	assert(cn != NULL);

	sbuf_init(&cn->rbuf);
	sbuf_init(&cn->wbuf);

	ev_io_init(&cn->w, libev_cb, client_fd, EV_READ | EV_WRITE);
	ev_io_start(__loop, &cn->w);

	ev_cleanup_init(&cn->gc, libev_cleanup_cb);
	ev_cleanup_start(__loop, &cn->gc);

	specter_new_client_conn_init(cn);

	log_d("accept new client [%d]", client_fd);
}

int libev_initialize()
{
	struct config *config = config_get();
	int fd;

	__loop = EV_DEFAULT;

	fd = libev_bind_listen_tcp_socket(config->listen_port, config->listen_addr);
	if (fd == -1)
		return -1;

	ev_io_init(&__client_watcher, libev_accept_new_client_cb, fd, EV_READ);
	ev_io_start(__loop, &__client_watcher);

	/*fd = libev_bind_listen_tcp_socket(config->listen_node_port, config->listen_node_addr);
	if (fd == -1)
		return -1;

	ev_io_init(&__node_watcher, libev_accept_new_node_cb, fd, EV_READ);
	ev_io_start(__loop, &__node_watcher);*/

	libev_init_signal_handlers();

	return 0;
}

void libev_run()
{
	ev_run(__loop, 0);
}

void libev_send(struct libev_conn *cn, const void *data, size_t size)
{
	sbuf_append(&cn->wbuf, data, size);
	// TODO: enable write event here
}

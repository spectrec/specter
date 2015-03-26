#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "log.h"
#include "pack.h"
#include "libev.h"
#include "config.h"
#include "specter.h"
#include <arpa/inet.h>

enum designator_command {
	DESIGNATOR_COMMAND_PUT = 1,
	DESIGNATOR_COMMAND_GET = 2,
};

enum specter_context_for {
	CONTEXT_FOR_CLIENT = 1,
	CONTEXT_FOR_HOST,
};

struct specter_context {
	enum specter_context_for type;

	union {
		struct libev_conn *host;
		struct libev_conn *client;
	};
};

static enum libev_ret specter_conn_destroy(struct libev_conn *cn);

static enum libev_ret specter_timeout_cb(struct libev_conn *cn)
{
	log_e("[%d] connection failed: timed out", cn->w.fd);

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret specter_pass_to_client(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	assert(ctx != NULL);
	if (ctx->client == NULL)
		// client has been disconnected,
		// so we should close connection too
		return LIBEV_RET_ERROR;

	libev_send(ctx->client, cn->rbuf.data, cn->rbuf.size);
	sbuf_shrink(&cn->rbuf, cn->rbuf.size);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_pass_to_host(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	assert(ctx != NULL);
	if (ctx->host == NULL)
		// host has been disconnected,
		// so we should close connection too
		return LIBEV_RET_ERROR;

	libev_send(ctx->host, cn->rbuf.data, cn->rbuf.size);
	sbuf_shrink(&cn->rbuf, cn->rbuf.size);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_connected(struct libev_conn *cn)
{
	struct libev_conn *client;
	struct specter_context *host_ctx;
	struct specter_context *client_ctx;

	libev_conn_off_timer(cn);
	if (libev_socket_error_occurred(cn->w.fd) != 0)
		return LIBEV_RET_ERROR;

	host_ctx = cn->ctx;
	assert(host_ctx->type == CONTEXT_FOR_HOST);

	libev_conn_on_read(cn);
	cn->read_cb = specter_pass_to_client;
	cn->write_cb = NULL;

	if (host_ctx->client == NULL)
		// client has been disconnected
		return LIBEV_RET_ERROR;

	client = host_ctx->client;
	client_ctx = client->ctx;
	assert(client_ctx->type == CONTEXT_FOR_CLIENT);

	libev_conn_on_read(client);
	client->read_cb = specter_pass_to_host;
	client->write_cb = NULL;

	// send `ok' to client
	{
		uint8_t version = 0;
		uint8_t code = 90;
		uint16_t port = 0;
		uint32_t ip = 0;
		char buf[128] = {0};

		pack_init(res, buf, sizeof(buf));
		pack(res, &version, sizeof(version));
		pack(res, &code, sizeof(code));
		pack(res, &port, sizeof(port));
		pack(res, &ip, sizeof(ip));

		libev_send(client, pack_data(res), pack_len(res));
		log_d("sent ok to client");
	}

	return LIBEV_RET_OK;
}

// Assume that `port' and `host' has `network' bytes order
static enum libev_ret specter_connect_to(struct libev_conn *cn,
					 uint16_t port, uint32_t host)
{
	struct specter_context *ctx = cn->ctx;
	struct specter_context *host_ctx;
	struct libev_conn *host_cn;
	struct config *config;
	float timeout;

	host_ctx = calloc(1, sizeof(struct specter_context));
	assert(host_ctx != NULL);
	host_ctx->type = CONTEXT_FOR_HOST;
	host_ctx->client = cn;

	host_cn = libev_create_conn();
	host_cn->ctx = host_ctx;
	host_cn->destroy_cb = specter_conn_destroy;

	assert(ctx->host == NULL);
	assert(ctx->type == CONTEXT_FOR_CLIENT);
	ctx->host = host_cn;

	config = config_get();
	timeout = config->node_connect_timeout;
	if (libev_connect_to(host_cn, port, host,
			     specter_connected, timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;

	return LIBEV_RET_OK;
}

static enum libev_ret specter_read_socks_req(struct libev_conn *cn)
{
	uint8_t *version;
	uint8_t *code;
	uint16_t *port;
	uint32_t *ip;
	char *req_end = NULL;

	unpack_init(req, cn->rbuf.data, cn->rbuf.size);
	version = unpack(req, sizeof(*version));
	code = unpack(req, sizeof(*code));
	port = unpack(req, sizeof(*port));
	ip = unpack(req, sizeof(*ip));

	if (version == NULL || code == NULL ||
	    port == NULL || ip == NULL)
		// not fully readed
		return LIBEV_RET_OK;

	for (size_t i = 0; i < unpack_len(req); ++i) {
		char *p = (char *)unpack_data(req) + i;

		if (*p == '\0') {
			req_end = p;
			break;
		}
	}

	if (req_end == NULL)
		// not fully readed
		return LIBEV_RET_OK;

	// see http://www.openssh.com/txt/socks4.protocol
	if (*version != 4 || *code != 1)
		return LIBEV_RET_ERROR;

	sbuf_shrink(&cn->rbuf, req_end + 1 - cn->rbuf.data);
	cn->read_cb = NULL;

	return specter_connect_to(cn, *port, *ip);
}

static enum libev_ret specter_conn_destroy(struct libev_conn *cn)
{
	struct specter_context *ctx;

	ctx = cn->ctx;
	if (ctx->host != NULL) {
		struct specter_context *nested_ctx = ctx->host->ctx;
		nested_ctx->host = NULL;

		libev_cleanup_conn(ctx->host);
	}

	free(cn->ctx);
	cn->ctx = NULL;

	return LIBEV_RET_OK;
}

void specter_new_client_conn_init(struct libev_conn *cn)
{
	struct specter_context *ctx;

	ctx = calloc(1, sizeof(struct specter_context));
	ctx->type = CONTEXT_FOR_CLIENT;

	cn->ctx = ctx;
	cn->write_cb = NULL;
	cn->read_cb = specter_read_socks_req;
	cn->destroy_cb = specter_conn_destroy;
}

static enum libev_ret libev_accept_new_node_cb(struct libev_conn *listen_cn)
{
	struct libev_conn *cn;

	(void)listen_cn;
	(void)cn;

	return LIBEV_RET_OK;
}

static enum libev_ret libev_accept_new_client_cb(struct libev_conn *listen_cn)
{
	struct libev_conn *cn;

	cn = libev_accept(listen_cn);
	if (cn == NULL)
		// ignore fails
		return LIBEV_RET_OK;

	specter_new_client_conn_init(cn);
	libev_conn_on_read(cn);

	return LIBEV_RET_OK;
}

static enum libev_ret libev_close_after_write(struct libev_conn *cn)
{
	(void)cn;

	if (cn->rbuf.size != 0)
		return LIBEV_RET_OK;

	log_d("[%d] all data succesfully sent to master", cn->w.fd);

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret libev_continue_init_cb(struct libev_conn *cn)
{
	struct config *config = config_get();

	libev_conn_off_timer(cn);
	if (libev_socket_error_occurred(cn->w.fd) != 0) {
		libev_stop();

		return LIBEV_RET_ERROR;
	}

	if (libev_bind_listen_tcp_socket(config->listen_port, config->listen_addr,
					 libev_accept_new_client_cb) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;

	if (libev_bind_listen_tcp_socket(config->listen_node_port, config->listen_node_addr,
					 libev_accept_new_node_cb) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;

	log_d("success connected to designator");
	{
		char data[64] = {0};
		uint8_t cmd = DESIGNATOR_COMMAND_PUT;
		uint16_t port = htons(config->listen_node_port);
		uint32_t ip = htonl(config->listen_node_addr);

		pack_init(req, data, sizeof(data));
		pack(req, &cmd, sizeof(cmd));
		pack(req, &ip, sizeof(ip));
		pack(req, &port, sizeof(port));

		cn->write_cb = libev_close_after_write;
		libev_send(cn, pack_data(req), pack_len(req));
	}

	return LIBEV_RET_OK;
}

static enum libev_ret specter_timeout_break_all_cb(struct libev_conn *cn)
{
	log_e("timeout on connect [%d], exiting ...", cn->w.fd);
	libev_stop();

	return LIBEV_RET_CLOSE_CONN;
}

int specter_initialize(void)
{
	struct config *config = config_get();
	struct libev_conn *cn;

	cn = libev_create_conn();
	if (libev_connect_to(cn, htons(config->designator_port),
			     htonl(config->designator_addr),
			     libev_continue_init_cb,
			     config->designator_connect_timeout,
			     specter_timeout_break_all_cb) != LIBEV_RET_OK)
		return -1;

	return 0;
}

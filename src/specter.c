#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "log.h"
#include "pack.h"
#include "libev.h"
#include "config.h"
#include "specter.h"

enum designator_command {
	DESIGNATOR_COMMAND_PUT = 1,
	DESIGNATOR_COMMAND_GET = 2,
};

enum specter_context_for {
	CONTEXT_FOR_CLIENT	= 1,
	CONTEXT_FOR_HOST	= 2,
	CONTEXT_FOR_DESIGNATOR	= 3,
};

enum specter_flags {
	SPECTER_FLAG_NONE	= 0,
	SPECTER_FLAG_EXIT_NODE	= 1,
};

enum specter_ctx_is {
	CTX_IS_NONE		= 0,
	CLIENT_CTX_IS_FLAGS	= 1,
	CLIENT_CTX_IS_SBUF	= 2,
};

#define PUBLIC_KEY_SIZE 0
#define SESSION_KEY_SIZE 32

#define NODE_RECORD_SIZE (4 + 2 + 1 + SESSION_KEY_SIZE)
#define DESIGNATOR_RESP_RECORD_SIZE (4 + 2 + PUBLIC_KEY_SIZE)

static int __urandom_fd = -1;

__attribute__((destructor))
static void specter_cleanup(void)
{
	if (__urandom_fd != -1)
		(void)close(__urandom_fd);
}

// TODO: create global private key and use it

struct specter_context {
	enum specter_context_for type;

	union {
		struct libev_conn *client;

		struct specter_node_ctx {
			struct libev_conn *host;
			uint8_t session_key[SESSION_KEY_SIZE];

			enum specter_ctx_is ctx_is;
			union {
				uint8_t flags;
				struct sbuf data;
			};
		} *node_info;
	};
};

static enum libev_ret specter_generate_session_key(char *buf, ssize_t key_len)
{
	if (__urandom_fd == -1)
		__urandom_fd = open("/dev/urandom", O_RDONLY);

	if (__urandom_fd == -1) {
		log_e("can't gen session key: %s", strerror(errno));
		return LIBEV_RET_ERROR;
	}

	if (read(__urandom_fd, buf, key_len) != key_len) {
		log_e("gen session key failed: %s", strerror(errno));
		(void)close(__urandom_fd);
		__urandom_fd = -1;

		return LIBEV_RET_ERROR;
	}

	return LIBEV_RET_OK;
}

static enum libev_ret specter_conn_destroy(struct libev_conn *cn)
{
	struct specter_context *ctx;
	struct libev_conn *pair_cn;

	ctx = cn->ctx;
	switch (ctx->type) {
	case CONTEXT_FOR_HOST:
	case CONTEXT_FOR_DESIGNATOR:
		pair_cn = ctx->client;
		break;
	case CONTEXT_FOR_CLIENT:
		pair_cn = ctx->node_info->host;
		break;
	default:
		abort();
	}

	if (pair_cn != NULL) {
		struct specter_context *nested_ctx = pair_cn->ctx;

		switch (nested_ctx->type) {
		case CONTEXT_FOR_DESIGNATOR:
		case CONTEXT_FOR_HOST:
			nested_ctx->client = NULL;
			break;
		case CONTEXT_FOR_CLIENT:
			nested_ctx->node_info->host = NULL;
			break;
		default:
			abort();
		}

		libev_cleanup_conn(pair_cn);
	}

	if (ctx->type == CONTEXT_FOR_CLIENT) {
		if (ctx->node_info->ctx_is == CLIENT_CTX_IS_SBUF)
			sbuf_delete(&ctx->node_info->data);

		free(ctx->node_info);
		ctx->node_info = NULL;
	}

	free(cn->ctx);
	cn->ctx = NULL;

	return LIBEV_RET_OK;
}

static struct specter_context *specter_create_context_for(enum specter_context_for type,
							  enum specter_ctx_is ctx_is)
{
	struct specter_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	assert(ctx != NULL);

	ctx->type = type;
	if (ctx->type == CONTEXT_FOR_CLIENT) {
		ctx->node_info = calloc(1, sizeof(*ctx->node_info));
		assert(ctx->node_info != NULL);

		ctx->node_info->ctx_is = ctx_is;
		if (ctx_is == CLIENT_CTX_IS_SBUF)
			sbuf_init(&ctx->node_info->data);
	}

	return ctx;
}

static void specter_set_ctx(struct libev_conn *cn, struct specter_context *ctx)
{
	assert(cn->ctx == NULL);

	cn->ctx = ctx;
	cn->destroy_cb = specter_conn_destroy;
}

static enum libev_ret specter_timeout_break_all_cb(struct libev_conn *cn)
{
	log_e("timeout on connect [%d], exiting ...", cn->w.fd);
	libev_stop();

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret specter_timeout_cb(struct libev_conn *cn)
{
	log_e("[%d] connection failed: timed out", cn->w.fd);

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret specter_pass_to_chain(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	assert(ctx->type == CONTEXT_FOR_CLIENT);
	libev_send(ctx->node_info->host, cn->rbuf.data, cn->rbuf.size);
	sbuf_reset(&cn->rbuf);

	return LIBEV_RET_OK;
}

/*
static enum libev_ret specter_client_read_handler(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	// TODO: encode and pass to host
	assert(ctx->type == CONTEXT_FOR_CLIENT);
	libev_send(ctx->node_info->host, cn->rbuf.data, cn->rbuf.size);
	sbuf_reset(&cn->rbuf);

	return LIBEV_RET_OK;
}
*/

static enum libev_ret specter_pass_to_client(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	assert(ctx->type == CONTEXT_FOR_HOST);
	libev_send(ctx->client, cn->rbuf.data, cn->rbuf.size);
	sbuf_reset(&cn->rbuf);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_node_connected_to_next_node(struct libev_conn *next_node)
{
	struct specter_context *ctx, *client_ctx;

	next_node->write_cb = NULL;
	libev_conn_off_timer(next_node);
	if (libev_socket_error_occurred(next_node->w.fd) != 0)
		return LIBEV_RET_ERROR;

	ctx = next_node->ctx;
	assert(ctx->type == CONTEXT_FOR_HOST);

	ctx->client->read_cb = specter_pass_to_chain;
	next_node->read_cb = specter_pass_to_client;
	libev_conn_on_read(next_node);

	// send ok to client
	client_ctx = ctx->client->ctx;
	if ((client_ctx->node_info->flags & SPECTER_FLAG_EXIT_NODE) != 0) {
		char buf[32] = {0};
		uint8_t version = 0;
		uint8_t code = 90;
		uint16_t port = 0;
		uint32_t ip = 0;

		pack_init(res, buf, sizeof(buf));
		pack(res, &version, sizeof(version));
		pack(res, &code, sizeof(code));
		pack(res, &port, sizeof(port));
		pack(res, &ip, sizeof(ip));

		libev_send(ctx->client, pack_data(res), pack_len(res));
		log_d("[%d] sent ok to client", ctx->client->w.fd);
	}

	if (ctx->client->rbuf.size != 0)
		return ctx->client->read_cb(ctx->client);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_read_next_node_info(struct libev_conn *cn)
{
	struct specter_context *next_node_ctx, *ctx;
	struct config *config = config_get();
	struct libev_conn *next_node_cn;
	char *session_key;
	uint8_t *flags;
	uint16_t *port;
	uint32_t *ip;

	if (cn->rbuf.size < NODE_RECORD_SIZE)
		return LIBEV_RET_OK;

	unpack_init(r, cn->rbuf.data, cn->rbuf.size);
	session_key = unpack(r, SESSION_KEY_SIZE);
	ip = unpack(r, sizeof(*ip));
	port = unpack(r, sizeof(*port));
	flags = unpack(r, sizeof(*flags));
	assert(session_key != NULL && ip != NULL && port != NULL && flags != NULL);

	next_node_cn = libev_create_conn();
	next_node_ctx = specter_create_context_for(CONTEXT_FOR_HOST, CTX_IS_NONE);
	next_node_ctx->client = cn;
	specter_set_ctx(next_node_cn, next_node_ctx);

	ctx = specter_create_context_for(CONTEXT_FOR_CLIENT, CLIENT_CTX_IS_FLAGS);
	ctx->node_info->host = next_node_cn;
	ctx->node_info->flags = *flags;
	memcpy(ctx->node_info->session_key, session_key, SESSION_KEY_SIZE);
	specter_set_ctx(cn, ctx);

	if (libev_connect_to(next_node_cn, *port, *ip,
			     specter_node_connected_to_next_node,
			     config->node_connect_timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;

	sbuf_shrink(&cn->rbuf, NODE_RECORD_SIZE);
	cn->read_cb = NULL;

	return LIBEV_RET_OK;
}

static enum libev_ret specter_accept_new_node_cb(struct libev_conn *listen_cn)
{
	struct libev_conn *cn;

	cn = libev_accept(listen_cn);
	if (cn == NULL)
		// ignore fails
		return LIBEV_RET_OK;

	cn->read_cb = specter_read_next_node_info;
	libev_conn_on_read(cn);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_connected_to_next_node_cb(struct libev_conn *node_cn)
{
	struct specter_context *ctx, *client_ctx;
	struct libev_conn *client_cn;
	struct sbuf *req;

	node_cn->write_cb = NULL;
	libev_conn_off_timer(node_cn);
	if (libev_socket_error_occurred(node_cn->w.fd) != 0)
		return LIBEV_RET_ERROR;

	ctx = node_cn->ctx;
	client_cn = ctx->client;
	client_ctx = client_cn->ctx;

	req = &client_ctx->node_info->data;
	libev_send(node_cn, req->data, req->size);

	node_cn->read_cb = specter_pass_to_client;
	libev_conn_on_read(node_cn);

	client_cn->read_cb = specter_pass_to_chain;
	libev_conn_on_read(client_cn);

	assert(client_ctx->node_info->ctx_is == CLIENT_CTX_IS_SBUF);
	sbuf_delete(&client_ctx->node_info->data);
	client_ctx->node_info->ctx_is = CLIENT_CTX_IS_FLAGS;
	client_ctx->node_info->flags = SPECTER_FLAG_NONE;

	return LIBEV_RET_OK;
}

static enum libev_ret specter_make_tunnel(struct libev_conn *client,
					  uint32_t dest_ip, uint16_t dest_port)
{
	struct specter_context *ctx, *next_node_ctx;
	uint16_t *next_node_port_p, next_node_port;
	uint32_t *next_node_ip_p, next_node_ip;
	uint8_t flags = SPECTER_FLAG_EXIT_NODE;
	struct config *config = config_get();
	struct libev_conn *next_node_cn;
	char session_key[SESSION_KEY_SIZE] = {0};
	struct sbuf req;

	ctx = client->ctx;
	assert(ctx->type == CONTEXT_FOR_CLIENT);
	assert(ctx->node_info->ctx_is = CLIENT_CTX_IS_SBUF);

	unpack_init(r, ctx->node_info->data.data, ctx->node_info->data.size);
	next_node_ip_p = unpack(r, sizeof(*next_node_ip_p));
	next_node_port_p = unpack(r, sizeof(*next_node_port_p));
	assert(next_node_ip_p != NULL && next_node_port_p != NULL);

	sbuf_init(&req);
	if (specter_generate_session_key(session_key, SESSION_KEY_SIZE) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;
	memcpy(ctx->node_info->session_key, session_key, SESSION_KEY_SIZE);

	sbuf_append(&req, session_key, SESSION_KEY_SIZE);
	sbuf_append(&req, &dest_ip, sizeof(dest_ip));
	sbuf_append(&req, &dest_port, sizeof(dest_port));
	sbuf_append(&req, &flags, sizeof(flags));
	for (uint16_t i = 0; i < config->tunnel_node_count - 1; ++i) {
		uint32_t *ip = unpack(r, sizeof(*ip));
		uint16_t *port = unpack(r, sizeof(*port));
		uint8_t flags = SPECTER_FLAG_NONE;

		assert(ip != NULL && port != NULL);
		if (specter_generate_session_key(session_key, SESSION_KEY_SIZE) != LIBEV_RET_OK) {
			sbuf_delete(&req);
			return LIBEV_RET_ERROR;
		}

		sbuf_unshift(&req, &flags, sizeof(flags));
		sbuf_unshift(&req, port, sizeof(*port));
		sbuf_unshift(&req, ip, sizeof(*ip));
		sbuf_unshift(&req, session_key, SESSION_KEY_SIZE);
	}

	next_node_ip = *next_node_ip_p;
	next_node_port = *next_node_port_p;

	next_node_cn = libev_create_conn();
	next_node_ctx = specter_create_context_for(CONTEXT_FOR_HOST, CTX_IS_NONE);
	next_node_ctx->client = client;
	specter_set_ctx(next_node_cn, next_node_ctx);

	assert(ctx->node_info->host == NULL);
	ctx->node_info->host = next_node_cn;
	sbuf_delete(&ctx->node_info->data);
	ctx->node_info->data = req;

	if (libev_connect_to(next_node_cn, next_node_port, next_node_ip,
			     specter_connected_to_next_node_cb,
			     config->node_connect_timeout,
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

	return specter_make_tunnel(cn, *ip, *port);
}

static enum libev_ret specter_response_nodes_cb(struct libev_conn *designator_cn)
{
	struct libev_conn *client;
	struct config *config = config_get();
	struct specter_context *ctx, *client_ctx;
	uint16_t records_cnt = config->tunnel_node_count;

	if (designator_cn->rbuf.size < records_cnt * DESIGNATOR_RESP_RECORD_SIZE)
		return LIBEV_RET_OK;

	log_d("[%d] got nodes list", designator_cn->w.fd);

	ctx = designator_cn->ctx;
	client = ctx->client;
	ctx->client = NULL;

	client_ctx = client->ctx;
	client_ctx->node_info->host = NULL; // remove link to designator
	assert(client_ctx->node_info->ctx_is == CLIENT_CTX_IS_SBUF);
	sbuf_append(&client_ctx->node_info->data,
		    designator_cn->rbuf.data, designator_cn->rbuf.size);

	libev_conn_on_read(client);
	client->read_cb = specter_read_socks_req;
	if (client->read_cb(client) != LIBEV_RET_OK) {
		libev_cleanup_conn(client);
		// call read parser, because request may be already read
		return LIBEV_RET_ERROR;
	}

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret specter_request_nodes_cb(struct libev_conn *designator_cn)
{
	struct config *config = config_get();

	designator_cn->write_cb = NULL;
	libev_conn_off_timer(designator_cn);
	if (libev_socket_error_occurred(designator_cn->w.fd) != 0)
		return LIBEV_RET_ERROR;

	{
		char buf[8] = {0};
		uint8_t command = DESIGNATOR_COMMAND_GET;
		uint16_t count = htons(config->tunnel_node_count);

		pack_init(req, buf, sizeof(buf));
		pack(req, &command, sizeof(command));
		pack(req, &count, sizeof(count));

		libev_send(designator_cn, pack_data(req), pack_len(req));
		log_d("[%d] sent request for nodes", designator_cn->w.fd);
	}

	designator_cn->read_cb = specter_response_nodes_cb;
	libev_conn_on_read(designator_cn);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_accept_new_client_cb(struct libev_conn *listen_cn)
{
	struct specter_context *ctx, *client_ctx;
	struct config *config = config_get();
	struct libev_conn *designator_cn;
	struct libev_conn *cn;

	cn = libev_accept(listen_cn);
	if (cn == NULL)
		// ignore fails
		return LIBEV_RET_OK;

	designator_cn = libev_create_conn();
	ctx = specter_create_context_for(CONTEXT_FOR_DESIGNATOR, CTX_IS_NONE);
	ctx->client = cn;
	specter_set_ctx(designator_cn, ctx);

	client_ctx = specter_create_context_for(CONTEXT_FOR_CLIENT, CLIENT_CTX_IS_SBUF);
	client_ctx->node_info->host = designator_cn;
	specter_set_ctx(cn, client_ctx);

	libev_conn_on_read(cn); // to detect client disconnecting

	if (libev_connect_to(designator_cn, htons(config->designator_port),
			     htonl(config->designator_addr),
			     specter_request_nodes_cb,
			     config->designator_connect_timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		return LIBEV_RET_ERROR;

	return LIBEV_RET_OK;
}

static enum libev_ret libev_close_after_write(struct libev_conn *cn)
{
	(void)cn;

	if (cn->rbuf.size != 0)
		return LIBEV_RET_OK;

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
					 specter_accept_new_client_cb) != LIBEV_RET_OK) {
		libev_stop();

		return LIBEV_RET_ERROR;
	}

	if (libev_bind_listen_tcp_socket(config->listen_node_port, config->listen_node_addr,
					 specter_accept_new_node_cb) != LIBEV_RET_OK) {
		libev_stop();

		return LIBEV_RET_ERROR;
	}

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

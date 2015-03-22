#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "log.h"
#include "pack.h"
#include "libev.h"
#include "specter.h"

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
	int error;
	struct libev_conn *client;
	struct specter_context *host_ctx;
	struct specter_context *client_ctx;
	socklen_t optlen = sizeof(error);

	if (getsockopt(cn->w.fd, SOL_SOCKET, SO_ERROR, &error, &optlen) != 0) {
		log_e("getsockopt failed: %s", strerror(errno));

		return LIBEV_RET_ERROR;
	}
	if (error != 0) {
		log_e("connection failed: %s", strerror(error));

		return LIBEV_RET_ERROR;
	}

	host_ctx = cn->ctx;
	assert(host_ctx->type == CONTEXT_FOR_HOST);

	cn->read_cb = specter_pass_to_client;
	cn->write_cb = NULL;

	if (host_ctx->client == NULL)
		// client has been disconnected
		return LIBEV_RET_ERROR;

	client = host_ctx->client;
	client_ctx = client->ctx;
	assert(client_ctx->type == CONTEXT_FOR_CLIENT);

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

	host_cn = calloc(1, sizeof(*cn));
	host_ctx = calloc(1, sizeof(struct specter_context));

	host_cn->ctx = host_ctx;
	host_cn->destroy_cb = specter_conn_destroy;
	host_ctx->type = CONTEXT_FOR_HOST;
	host_ctx->client = cn;

	assert(ctx->host == NULL);
	assert(ctx->type == CONTEXT_FOR_CLIENT);
	ctx->host = host_cn;

	if (libev_connect_to(host_cn, port, host, specter_connected) != LIBEV_RET_OK)
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

	cn->destroy_cb = specter_conn_destroy;
	cn->read_cb = specter_read_socks_req;
	cn->write_cb = NULL;
}

#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "rsa.h"
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
	CONTEXT_FOR_ROOT	= 1,
	CONTEXT_FOR_NODE	= 2,
	CONTEXT_FOR_NEXT_NODE	= 3,
	CONTEXT_FOR_DESIGNATOR	= 4,
};

enum specter_flags {
	SPECTER_FLAG_NONE		= 0,
	SPECTER_FLAG_EXIT_NODE		= 1,
	SPECTER_FLAG_ENABLE_CIPHERING	= 2,
};

// XXX: 2048 bit's rsa key shoul be used
#define PUBLIC_KEY_SIZE 451

#define SESSION_KEY_SIZE 32

#define ENCODED_NODE_RECORD_SIZE RSA_BLOCK_SIZE
#define NODE_RECORD_SIZE (4 + 2 + 1 + SESSION_KEY_SIZE)

#define DESIGNATOR_RESP_RECORD_SIZE (4 + 2 + PUBLIC_KEY_SIZE)

#define PAYLOAD_SIZE 256
#define MESSAGE_SIZE (4 + PAYLOAD_SIZE)

static int __urandom_fd = -1;
static uint32_t __rsa_public_key_len;
static uint32_t __rsa_private_key_len;
static uint32_t __rsa_designator_public_key_len;

static char *__rsa_public_key;
static char *__rsa_private_key;
static char *__rsa_designator_public_key;

struct session_key {
	uint8_t data[SESSION_KEY_SIZE];
	uint8_t position;
};

struct specter_context {
	enum specter_context_for type;

	union {
		struct libev_conn *client;
		struct {
			struct libev_conn *client;
			struct session_key key;
		} *designator;

		struct {
			struct libev_conn *host;
			struct session_key key;
			uint8_t flags;
		} *node;

		struct {
			struct libev_conn *next_node;
			struct libev_timer *timer;
			struct session_key* keys;
			struct sbuf data;
		} *root_node;
	};
};

static enum libev_timer_ret specter_send_fake_packet_cb(struct libev_timer *t, void *ctx);

__attribute__((destructor))
static void specter_cleanup(void)
{
	if (__urandom_fd != -1)
		(void)close(__urandom_fd);

	free(__rsa_public_key);
	free(__rsa_private_key);
	free(__rsa_designator_public_key);
}

static enum libev_ret specter_get_random_data(char *buf, ssize_t key_len)
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

static enum libev_ret specter_generate_session_key(char *buf, ssize_t len)
{
	return specter_get_random_data(buf, len);
}

static enum libev_ret specter_conn_destroy(struct libev_conn *cn)
{
	struct specter_context *ctx;
	struct libev_conn *pair_cn;

	ctx = cn->ctx;
	switch (ctx->type) {
	case CONTEXT_FOR_NEXT_NODE:
		pair_cn = ctx->client;
		break;
	case CONTEXT_FOR_DESIGNATOR:
		pair_cn = ctx->designator->client;

		free(ctx->designator);
		ctx->designator = NULL;

		break;
	case CONTEXT_FOR_NODE:
		pair_cn = ctx->node->host;

		free(ctx->node);
		ctx->node = NULL;

		break;
	case CONTEXT_FOR_ROOT:
		pair_cn = ctx->root_node->next_node;

		free(ctx->root_node->keys);
		ctx->root_node->keys = NULL;

		libev_timer_destroy(ctx->root_node->timer);
		ctx->root_node->timer = NULL;

		sbuf_delete(&ctx->root_node->data);

		free(ctx->root_node);
		ctx->root_node = NULL;

		break;
	default:
		abort();
	}

	free(cn->ctx);
	cn->ctx = NULL;

	if (pair_cn != NULL) {
		struct specter_context *nested_ctx = pair_cn->ctx;

		switch (nested_ctx->type) {
		case CONTEXT_FOR_DESIGNATOR:
			nested_ctx->designator->client = NULL;
			break;
		case CONTEXT_FOR_NEXT_NODE:
			nested_ctx->client = NULL;
			break;
		case CONTEXT_FOR_NODE:
			nested_ctx->node->host = NULL;
			break;
		case CONTEXT_FOR_ROOT:
			nested_ctx->root_node->next_node = NULL;
			break;
		default:
			abort();
		}

		libev_cleanup_conn(pair_cn);
	}

	return LIBEV_RET_OK;
}

static struct specter_context *specter_create_context_for(struct libev_conn *cn, enum specter_context_for type)
{
	struct config *config = config_get();
	struct specter_context *ctx;

	ctx = calloc(1, sizeof(*ctx));
	assert(ctx != NULL);

	ctx->type = type;
	switch (ctx->type) {
	case CONTEXT_FOR_DESIGNATOR:
		ctx->designator = calloc(1, sizeof(*ctx->designator));
		assert(ctx->designator != NULL);
		break;
	case CONTEXT_FOR_NEXT_NODE:
		break;
	case CONTEXT_FOR_NODE:
		ctx->node = calloc(1, sizeof(*ctx->node));
		assert(ctx->node != NULL);
		break;
	case CONTEXT_FOR_ROOT:
		ctx->root_node = calloc(1, sizeof(*ctx->root_node));
		assert(ctx->root_node != NULL);

		ctx->root_node->keys = calloc(config->tunnel_node_count,
					      sizeof(struct session_key));
		assert(ctx->root_node->keys != NULL);
		sbuf_init(&ctx->root_node->data);

		ctx->root_node->timer = libev_timer_create(config->fake_packet_interval,
							   config->send_delay, specter_send_fake_packet_cb, cn);
		assert(ctx->root_node->timer != NULL);
		break;
	default:
		abort();
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

static void specter_encode_data(struct session_key *key, char *data, size_t size)
{
	for (size_t i = 0; i < size; ++i) {
		if (key->position == SESSION_KEY_SIZE)
			key->position = 0;

		data[i] ^= key->data[key->position++];
	}
}

static void specter_encode_with_session_key(struct specter_context *ctx,
					    char *data, size_t size)
{
	struct config *config = config_get();

	assert(ctx->type == CONTEXT_FOR_ROOT);
	for (int16_t j = config->tunnel_node_count - 1; j >= 0; --j) {
		struct session_key *key = &ctx->root_node->keys[j];

		specter_encode_data(key, data, size);
	}
}

static void specter_decode_with_session_key(struct specter_context *ctx,
					    char *data, size_t size)
{
	assert(ctx->type == CONTEXT_FOR_NODE);
	specter_encode_data(&ctx->node->key, data, size);
}

static enum libev_timer_ret specter_send_fake_packet_cb(struct libev_timer *t, void *ctx)
{
	struct libev_conn *cn = ctx;

	// FIXME
	(void)t;
	(void)cn;

	return LIBEV_TIMER_RET_CONT;
}

static enum libev_ret specter_decode_and_pass_to_chain(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;

	assert(ctx->type == CONTEXT_FOR_NODE);
	if ((ctx->node->flags & SPECTER_FLAG_ENABLE_CIPHERING) != 0)
		specter_decode_with_session_key(ctx, cn->rbuf.data, cn->rbuf.size);

	if ((ctx->node->flags & SPECTER_FLAG_EXIT_NODE) == 0) {
		libev_send(ctx->node->host, cn->rbuf.data, cn->rbuf.size);
		sbuf_reset(&cn->rbuf);

		return LIBEV_RET_OK;
	}

	// This is exit node
	for (size_t len = cn->rbuf.size; len > 0; len -= MESSAGE_SIZE) {
		const char *payload;
		uint32_t *msg_len;

		if (len < MESSAGE_SIZE)
			// this message not fully read
			return LIBEV_RET_OK;

		unpack_init(msg, cn->rbuf.data, MESSAGE_SIZE);
		msg_len = unpack(msg, sizeof(*msg_len));
		assert(msg_len != NULL);

		if (*msg_len != 0) {
			payload = unpack(msg, *msg_len);
			if (payload == NULL) {
				log_e("invalid packet received (msg len `%u'", *msg_len);
				return LIBEV_RET_ERROR;
			}

			libev_send(ctx->node->host, payload, *msg_len);
		} // else -- this is fake message

		sbuf_shrink(&cn->rbuf, MESSAGE_SIZE);
	}

	return LIBEV_RET_OK;
}

static enum libev_ret specter_encode_and_pass_to_chain(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;
	const char *data = cn->rbuf.data;
	size_t data_len = cn->rbuf.size;
	char buf[MESSAGE_SIZE];

	assert(ctx->type == CONTEXT_FOR_ROOT);
	while (data_len > 0) {
		uint32_t packet_size = data_len < PAYLOAD_SIZE
				     ? data_len : PAYLOAD_SIZE;

		pack_init(r, buf, sizeof(buf));
		pack(r, &packet_size, sizeof(packet_size));
		pack(r, data, packet_size);
		if (packet_size < PAYLOAD_SIZE) {
			size_t left = PAYLOAD_SIZE - packet_size;
			char rand_buf[left];

			if (specter_get_random_data(rand_buf, left) != LIBEV_RET_OK)
				return LIBEV_RET_ERROR;

			log_i("append `%zu' bytes of random data", left);
			pack(r, rand_buf, left);
		}

		specter_encode_with_session_key(ctx, pack_data(r), pack_len(r));
		libev_send(ctx->node->host, pack_data(r), pack_len(r));

		data_len -= packet_size;
		data += packet_size;
	}

	sbuf_reset(&cn->rbuf);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_pass_to_client(struct libev_conn *cn)
{
	struct specter_context *ctx = cn->ctx;
	struct specter_context *client_ctx = ctx->client->ctx;

	assert(ctx->type == CONTEXT_FOR_NEXT_NODE);
	libev_send(ctx->client, cn->rbuf.data, cn->rbuf.size);
	sbuf_reset(&cn->rbuf);

	if (client_ctx->type == CONTEXT_FOR_NODE)
		// ciphering should be enabled only
		// after response from last node
		client_ctx->node->flags |= SPECTER_FLAG_ENABLE_CIPHERING;

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
	assert(ctx->type == CONTEXT_FOR_NEXT_NODE);

	ctx->client->read_cb = specter_decode_and_pass_to_chain;
	next_node->read_cb = specter_pass_to_client;
	libev_conn_on_read(next_node);

	// send ok to client
	client_ctx = ctx->client->ctx;
	if ((client_ctx->node->flags & SPECTER_FLAG_EXIT_NODE) != 0) {
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

		client_ctx->node->flags |= SPECTER_FLAG_ENABLE_CIPHERING;
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
	char node_record[RSA_BLOCK_SIZE];
	char *session_key;
	uint8_t *flags;
	uint16_t *port;
	uint32_t *ip;
	int len;

	if (cn->rbuf.size < ENCODED_NODE_RECORD_SIZE)
		return LIBEV_RET_OK;

	len = private_decrypt(cn->rbuf.data, ENCODED_NODE_RECORD_SIZE,
			      __rsa_private_key, __rsa_private_key_len, node_record);

	if (len != NODE_RECORD_SIZE) {
		log_e("[%d] decrypt error, invalid packet: "
		      "got size `%d', expected: `%d' ", cn->w.fd, len, NODE_RECORD_SIZE);
		return LIBEV_RET_ERROR;
	}

	unpack_init(r, node_record, len);
	session_key = unpack(r, SESSION_KEY_SIZE);
	ip = unpack(r, sizeof(*ip));
	port = unpack(r, sizeof(*port));
	flags = unpack(r, sizeof(*flags));
	assert(session_key != NULL && ip != NULL && port != NULL && flags != NULL);

	next_node_cn = libev_create_conn();
	next_node_ctx = specter_create_context_for(NULL, CONTEXT_FOR_NEXT_NODE);
	next_node_ctx->client = cn;
	specter_set_ctx(next_node_cn, next_node_ctx);

	ctx = specter_create_context_for(NULL, CONTEXT_FOR_NODE);
	ctx->node->host = next_node_cn;
	ctx->node->flags = *flags;
	memcpy(ctx->node->key.data, session_key, SESSION_KEY_SIZE);
	specter_set_ctx(cn, ctx);

	if (libev_connect_to(next_node_cn, *port, *ip,
			     specter_node_connected_to_next_node,
			     config->node_connect_timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		// Return ok to avoid double free inside after failed `read_cb'
		return LIBEV_RET_OK;

	sbuf_shrink(&cn->rbuf, ENCODED_NODE_RECORD_SIZE);
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

static enum libev_ret specter_connected_to_chain_cb(struct libev_conn *node_cn)
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

	req = &client_ctx->root_node->data;
	libev_send(node_cn, req->data, req->size);
	sbuf_delete(&client_ctx->root_node->data);

	node_cn->read_cb = specter_pass_to_client;
	libev_conn_on_read(node_cn);

	client_cn->read_cb = specter_encode_and_pass_to_chain;
	libev_conn_on_read(client_cn);

	return LIBEV_RET_OK;
}

static enum libev_ret specter_make_tunnel(struct libev_conn *root,
					  uint32_t dest_ip, uint16_t dest_port)
{
	struct specter_context *ctx, *next_node_ctx;
	uint16_t *next_node_port_p, next_node_port;
	uint32_t *next_node_ip_p, next_node_ip;
	uint8_t flags = SPECTER_FLAG_EXIT_NODE;
	struct config *config = config_get();
	char encoded_node_record[RSA_BLOCK_SIZE];
	char session_key[SESSION_KEY_SIZE];
	char node_record[NODE_RECORD_SIZE];
	struct libev_conn *next_node_cn;
	char *public_key;
	struct sbuf req;
	int encoded_len;

	ctx = root->ctx;
	assert(ctx->type == CONTEXT_FOR_ROOT);

	assert(ctx->root_node->keys != NULL);
	for (uint16_t i = 0; i < config->tunnel_node_count; ++i) {
		if (specter_generate_session_key(session_key, SESSION_KEY_SIZE) != LIBEV_RET_OK)
			return LIBEV_RET_ERROR;

		memcpy(ctx->root_node->keys[i].data, session_key, SESSION_KEY_SIZE);
	}

	unpack_init(r, ctx->root_node->data.data, ctx->root_node->data.size);
	next_node_ip_p = unpack(r, sizeof(*next_node_ip_p));
	next_node_port_p = unpack(r, sizeof(*next_node_port_p));
	public_key = unpack(r, PUBLIC_KEY_SIZE);
	assert(next_node_ip_p != NULL && next_node_port_p != NULL && public_key != NULL);

	sbuf_init(&req);
	for (int16_t i = config->tunnel_node_count - 1; i >= 0; --i) {
		uint16_t port = dest_port;
		uint32_t ip = dest_ip;

		pack_init(r, node_record, sizeof(node_record));
		pack(r, ctx->root_node->keys[i].data, SESSION_KEY_SIZE);
		pack(r, &ip, sizeof(ip));
		pack(r, &port, sizeof(port));
		pack(r, &flags, sizeof(flags));

		encoded_len = public_encrypt(pack_data(r), (int)pack_len(r),
					     public_key, PUBLIC_KEY_SIZE, encoded_node_record);
		if (encoded_len != ENCODED_NODE_RECORD_SIZE) {
			log_e("[%d] encrypt error, invalid encrypted size", root->w.fd);
			sbuf_delete(&req);

			return LIBEV_RET_ERROR;
		}
		sbuf_unshift(&req, encoded_node_record, encoded_len);

		dest_port = *next_node_port_p;
		dest_ip = *next_node_ip_p;
		flags = SPECTER_FLAG_NONE;

		if (i > 0) {
			// In case `i == 0' -- all data has been unpacked
			next_node_ip_p = unpack(r, sizeof(*next_node_ip_p));
			next_node_port_p = unpack(r, sizeof(*next_node_port_p));
			public_key = unpack(r, PUBLIC_KEY_SIZE);
			assert(next_node_ip_p != NULL && next_node_port_p != NULL && public_key != NULL);
		}
	}

	next_node_ip = *next_node_ip_p;
	next_node_port = *next_node_port_p;

	next_node_cn = libev_create_conn();
	next_node_ctx = specter_create_context_for(NULL, CONTEXT_FOR_NEXT_NODE);
	next_node_ctx->client = root;
	specter_set_ctx(next_node_cn, next_node_ctx);

	assert(ctx->root_node->next_node == NULL);
	ctx->root_node->next_node = next_node_cn;
	sbuf_delete(&ctx->root_node->data);
	ctx->root_node->data = req;

	if (libev_connect_to(next_node_cn, next_node_port, next_node_ip,
			     specter_connected_to_chain_cb,
			     config->node_connect_timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		// Return ok to avoid double free,
		// because clien conn is already free'd.
		return LIBEV_RET_OK;

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
	client = ctx->designator->client;
	ctx->designator->client = NULL;

	client_ctx = client->ctx;
	client_ctx->root_node->next_node = NULL;
	sbuf_append(&client_ctx->root_node->data,
		    designator_cn->rbuf.data, designator_cn->rbuf.size);

	// decode data with designator's session key
	specter_encode_data(&ctx->designator->key,
			    client_ctx->root_node->data.data,
			    client_ctx->root_node->data.size);

	libev_conn_on_read(client);
	client->read_cb = specter_read_socks_req;

	// call read parser, because request may be already read
	if (client->read_cb(client) != LIBEV_RET_OK) {
		libev_cleanup_conn(client);
		return LIBEV_RET_ERROR;
	}

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret specter_request_nodes_cb(struct libev_conn *designator_cn)
{
	struct config *config = config_get();
	struct specter_context *ctx = designator_cn->ctx;

	designator_cn->write_cb = NULL;
	libev_conn_off_timer(designator_cn);
	if (libev_socket_error_occurred(designator_cn->w.fd) != 0)
		return LIBEV_RET_ERROR;

	{
		char buf[512] = {0};
		char payload[64] = {0};
		char crypted_payload[512] = {0};
		char session_key[SESSION_KEY_SIZE] = {0};
		uint8_t command = DESIGNATOR_COMMAND_GET;
		uint16_t count = htons(config->tunnel_node_count);
		int32_t payload_len;

		if (specter_generate_session_key(session_key, SESSION_KEY_SIZE) != LIBEV_RET_OK)
			return LIBEV_RET_ERROR;
		memcpy(ctx->designator->key.data, session_key, SESSION_KEY_SIZE);

		pack_init(p, payload, sizeof(payload));
		pack(p, &count, sizeof(count));
		pack(p, session_key, SESSION_KEY_SIZE);

		payload_len = public_encrypt(pack_data(p), pack_len(p), __rsa_designator_public_key,
					     __rsa_designator_public_key_len, crypted_payload);
		if (payload_len == -1)
			return LIBEV_RET_ERROR;

		pack_init(req, buf, sizeof(buf));
		pack(req, &command, sizeof(command));
		pack(req, crypted_payload, payload_len);

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
	ctx = specter_create_context_for(NULL, CONTEXT_FOR_DESIGNATOR);
	ctx->designator->client = cn;
	specter_set_ctx(designator_cn, ctx);

	client_ctx = specter_create_context_for(cn, CONTEXT_FOR_ROOT);
	client_ctx->root_node->next_node = designator_cn;
	specter_set_ctx(cn, client_ctx);

	libev_conn_on_read(cn); // to detect client disconnecting

	if (libev_connect_to(designator_cn, htons(config->designator_port),
			     htonl(config->designator_addr),
			     specter_request_nodes_cb,
			     config->designator_connect_timeout,
			     specter_timeout_cb) != LIBEV_RET_OK)
		// Retrun ok, because connection has been destroyed
		return LIBEV_RET_OK;

	return LIBEV_RET_OK;
}

static enum libev_ret libev_read_designator_pub_key_cb(struct libev_conn *cn)
{
	char *public_key;
	uint32_t *key_len_p, key_len;

	if (cn->rbuf.size < sizeof(*key_len_p))
		// not fully read
		return LIBEV_RET_OK;

	unpack_init(r, cn->rbuf.data, cn->rbuf.size);
	key_len_p = unpack(r, sizeof(*key_len_p));
	assert(key_len_p != NULL);

	key_len = ntohl(*key_len_p);
	public_key = unpack(r, key_len);
	if (public_key == NULL)
		// not fully read
		return LIBEV_RET_OK;

	assert(__rsa_designator_public_key == NULL);
	__rsa_designator_public_key = strndup(public_key, key_len);
	__rsa_designator_public_key_len = key_len;
	assert(__rsa_designator_public_key != NULL);

	return LIBEV_RET_CLOSE_CONN;
}

static enum libev_ret libev_continue_init_cb(struct libev_conn *cn)
{
	struct config *config = config_get();

	cn->write_cb = NULL;
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
		char data[1024] = {0};
		uint8_t cmd = DESIGNATOR_COMMAND_PUT;
		uint16_t port = htons(config->listen_node_port);
		uint32_t ip = htonl(config->listen_node_addr);
		uint32_t key_len = htonl(__rsa_public_key_len);

		pack_init(req, data, sizeof(data));
		pack(req, &cmd, sizeof(cmd));
		pack(req, &ip, sizeof(ip));
		pack(req, &port, sizeof(port));
		pack(req, &key_len, sizeof(key_len));
		pack(req, __rsa_public_key, __rsa_public_key_len);

		libev_send(cn, pack_data(req), pack_len(req));

		cn->read_cb = libev_read_designator_pub_key_cb;
		libev_conn_on_read(cn);
	}

	return LIBEV_RET_OK;
}

static void cleanup_file(int *fd)
{
	if (*fd != -1)
		(void)close(*fd);
}

int specter_read_rsa_key(const char *filename, char **key, uint32_t *size)
{
	int fd __attribute__((cleanup(cleanup_file))) = -1;
	struct stat buf;
	char *result;

	if (stat(filename, &buf) != 0) {
		log_e("failed to stat `%s': %s", filename, strerror(errno));
		return -1;
	}

	result = malloc(buf.st_size + 1);
	assert(result != NULL);

	if ((fd = open(filename, O_RDONLY)) == -1) {
		log_e("filed to open `%s': %s", filename, strerror(errno));
		free(result);

		return -1;
	}

	if (read(fd, result, buf.st_size) != buf.st_size) {
		log_e("can't read full key");
		free(result);

		return -1;
	}
	result[buf.st_size] = '\0';

	*key = result;
	if (size != NULL)
		*size = buf.st_size;

	return 0;
}

int specter_initialize(void)
{
	struct config *config = config_get();
	struct libev_conn *cn;

	if (specter_read_rsa_key(config->public_key, &__rsa_public_key, &__rsa_public_key_len) != 0 ||
	    specter_read_rsa_key(config->private_key, &__rsa_private_key, &__rsa_private_key_len) != 0)
		return -1;

	if (rsa_key_check(__rsa_public_key, __rsa_public_key_len, true) != 0 ||
	    rsa_key_check(__rsa_private_key, __rsa_private_key_len, false) != 0) {
		log_e("rsa keys are invalid, regen them");
		return -1;
	}

	cn = libev_create_conn();
	if (libev_connect_to(cn, htons(config->designator_port),
			     htonl(config->designator_addr),
			     libev_continue_init_cb,
			     config->designator_connect_timeout,
			     specter_timeout_break_all_cb) != LIBEV_RET_OK)
		return -1;

	return 0;
}

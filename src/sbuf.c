#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdarg.h>
#include <sys/types.h>

#include "sbuf.h"

void sbuf_init(struct sbuf *buf)
{
	assert(buf != NULL);

	buf->data = NULL;
	buf->size = 0;
	buf->alloc_size = 0;
}

void sbuf_delete(struct sbuf *buf)
{
	assert(buf != NULL);

	if (buf->data == NULL)
		return;

	free(buf->data);
	sbuf_init(buf);
}

void sbuf_reset(struct sbuf *buf)
{
	assert(buf != NULL);
	buf->size = 0;
}

void sbuf_ensure(struct sbuf *buf, size_t size)
{
	if (buf->size + size >= buf->alloc_size) {
		size_t new_size = buf->alloc_size * 2;
		if (new_size == 0)
			new_size = size + 1;

		while (buf->size + size >= new_size)
			new_size *= 2;

		char *new_buf = (char *)realloc(buf->data, new_size);
		assert(new_buf != NULL);

		buf->data = new_buf;
		buf->alloc_size = new_size;
	}
}

void sbuf_append(struct sbuf *buf, const void *data, size_t size)
{
	sbuf_ensure(buf, size);
	memcpy(buf->data + buf->size, data, size);
	buf->size += size;
}

void sbuf_unshift(struct sbuf *buf, const void *data, size_t size)
{
	sbuf_ensure(buf, size);
	memmove(buf->data + size, buf->data, buf->size);
	memcpy(buf->data, data, size);
	buf->size += size;
}

void sbuf_shrink(struct sbuf *buf, size_t size)
{
	if (size > buf->size) {
		buf->size = 0;
		return;
	}

	memmove(buf->data, buf->data + size, buf->size - size);
	buf->size -= size;
}

void sbuf_insert(struct sbuf *buf, const void *data, size_t size)
{
	sbuf_reset(buf);
	sbuf_append(buf, data, size);
}

void sbuf_printf(struct sbuf *buf, const char *format, ...)
{
	va_list ap, ap_cpy;
	va_start(ap, format);
	va_copy(ap_cpy, ap);

	int len = vsnprintf(NULL, 0, format, ap_cpy);
	va_end(ap_cpy);

	sbuf_ensure(buf, len);
	vsprintf(buf->data + buf->size, format, ap);
	buf->size += len;
	va_end(ap);
}

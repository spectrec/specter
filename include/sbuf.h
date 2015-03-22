#ifndef __SBUF_H__
#define __SBUF_H__

#include <sys/types.h>

struct sbuf {
    char *data;

    size_t size;
    size_t alloc_size;
};

void sbuf_init(struct sbuf *buf);
void sbuf_reset(struct sbuf *buf);
void sbuf_delete(struct sbuf *buf);
void sbuf_shrink(struct sbuf *buf, size_t size);
void sbuf_ensure(struct sbuf *buf, size_t size);
void sbuf_append(struct sbuf *buf, const void *data, size_t size);
void sbuf_insert(struct sbuf *buf, const void *data, size_t size);

void sbuf_printf(struct sbuf *buf, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

#endif

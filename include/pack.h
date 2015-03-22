#ifndef __PACK_H__
#define __PACK_H__

#include <assert.h>
#include <string.h>

#define concat(_x, _y) _x ## _y

#define unpack_init(_name, _data, _len) struct {	\
	void *data;					\
	size_t len;					\
} concat(unpack, _name) = {				\
	.data = (_data),				\
	.len = (_len),					\
};

#define unpack_len(_name) concat(unpack, _name).len
#define unpack_data(_name) concat(unpack, _name).data

#define unpack(_name, _size) ({				\
	void *ret = NULL;				\
							\
	if (unpack_len(_name) >= (_size)) {		\
		ret = unpack_data(_name);		\
		unpack_len(_name) -= (_size);		\
		unpack_data(_name) += (_size);		\
	}						\
							\
	ret;						\
})

#define pack_init(_name, _buf, _size) struct {	\
	void *data;				\
	size_t len;				\
	size_t size;				\
} concat(pack, _name) = {			\
	.data = (_buf),				\
	.size = (_size),			\
	.len = 0,				\
};

#define pack_len(_name)  concat(pack, _name).len
#define pack_data(_name) concat(pack, _name).data
#define pack_size(_name) concat(pack, _name).size

#define pack(_name, _data, _size) ({						\
	if (pack_data(_name) != NULL) {						\
		assert(pack_size(_name) >= pack_len(_name) + (_size));		\
										\
		memcpy(pack_data(_name) + pack_len(_name), (_data), (_size));	\
	}									\
										\
	pack_len(_name) += (_size);						\
})

#endif

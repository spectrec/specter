#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include "config.h"

static struct config __config;
static bool __config_initialized;

#define convert_str_to_addr(_src, _dst) {				\
	if (inet_pton(AF_INET, (_src), (_dst)) != 1) {			\
		fprintf(stderr, "can't convert `%s' to addr", _src);	\
									\
		return -1;						\
	}								\
}

#define convert_str_to_long(_str) ({					\
	char *endptr = NULL;						\
	long val;							\
									\
	val = strtol(_str, &endptr, 10);				\
	if (*endptr != '\0') {						\
		fprintf(stderr, "can't convert `%s' to digit, "		\
				"error at `%s'", _str, endptr);		\
									\
		return -1;						\
	}								\
									\
	val;								\
})

#define convert_str_to_float(_str) ({					\
	char *endptr = NULL;						\
	float val;							\
									\
	val = strtof(_str, &endptr);					\
	if (*endptr != '\0') {						\
		fprintf(stderr, "can't convert `%s' to digit, "		\
				"error at `%s'", _str, endptr);		\
									\
		return -1;						\
	}								\
									\
	val;								\
})

__attribute__((destructor))
static void config_cleanup(void)
{
	if (__config_initialized == false)
		return;

	free(__config.public_key);
	free(__config.private_key);
}

static int config_store_value(const char *key, const char *value)
{
	assert(*key != '\0');

	if (*value == '\0') {
		fprintf(stderr, "value for key `%s' is empty", key);

		return -1;
	}

	if (strcmp(key, "listen_addr") == 0) {
		convert_str_to_addr(value, &__config.listen_addr);
		__config.listen_addr = ntohl(__config.listen_addr);
	} else if (strcmp(key, "listen_node_addr") == 0) {
		convert_str_to_addr(value, &__config.listen_node_addr);
		__config.listen_node_addr = ntohl(__config.listen_node_addr);
	} else if (strcmp(key, "designator_addr") == 0) {
		convert_str_to_addr(value, &__config.designator_addr);
		__config.designator_addr = ntohl(__config.designator_addr);
	} else if (strcmp(key, "public_key") == 0) {
		__config.public_key = strdup(value);
	} else if (strcmp(key, "private_key") == 0) {
		__config.private_key = strdup(value);
	} else if (strcmp(key, "tunnel_node_count") == 0) {
		__config.tunnel_node_count = (uint16_t)convert_str_to_long(value);
	} else if (strcmp(key, "listen_port") == 0) {
		__config.listen_port = (uint16_t)convert_str_to_long(value);
	} else if (strcmp(key, "listen_node_port") == 0) {
		__config.listen_node_port = (uint16_t)convert_str_to_long(value);
	} else if (strcmp(key, "designator_port") == 0) {
		__config.designator_port = (uint16_t)convert_str_to_long(value);
	} else if (strcmp(key, "node_connect_timeout") == 0) {
		__config.node_connect_timeout = (float)convert_str_to_float(value);
	} else if (strcmp(key, "designator_connect_timeout") == 0) {
		__config.designator_connect_timeout = (float)convert_str_to_float(value);
	} else if (strcmp(key, "fake_packet_interval") == 0) {
		__config.fake_packet_interval = (float)convert_str_to_float(value);
	} else if (strcmp(key, "send_delay") == 0) {
		__config.send_delay = (float)convert_str_to_float(value);
	} else {
		fprintf(stderr, "unknown key `%s'", key);

		return -1;
	}

	return 0;
}

static int config_parse_line(char *line)
{
	const char *key_beg, *key_end;
	const char *value_beg, *value_end;

	// skip spaces before key
	for (; isspace(*line) != 0 && *line != '\0'; ++line);

	key_beg = line;
	for (; isspace(*line) == 0 && *line != '\0'; ++line);
	key_end = line;

	// skip spaces before value
	for (; isspace(*line) != 0 && *line != '\0'; ++line);

	value_beg = line;
	for (; isspace(*line) == 0 && *line != '\0'; ++line);
	value_end = line;

	if (key_beg == key_end)
		return 0;

	return config_store_value(strndupa(key_beg, key_end - key_beg),
				  strndupa(value_beg, value_end - value_beg));
}

static void close_file(FILE **f)
{
	if (*f != NULL)
		fclose(*f);
}

int config_read(const char *path)
{
	FILE *f __attribute__((cleanup(close_file))) = fopen(path, "r");

	if (f == NULL) {
		fprintf(stderr, path);

		return -1;
	}

	// Set `initialized' true to cleanup all allocs
	__config_initialized = true;

	while (feof(f) == 0) {
		char *comment, *eol;
		char line[4096] = {0};

		if (fgets(line, sizeof(line) - 1, f) == NULL) {
			if (ferror(f) != 0)
				return -1;

			break;
		}

		eol = strchr(line, '\n');
		*eol = '\0';

		comment = strchr(line, '#');
		if (comment != NULL)
			*comment = '\0';

		if (config_parse_line(line) != 0)
			return -1;
	}

	return 0;
}

struct config *config_get(void)
{
	assert(__config_initialized == true);

	return &__config;
}

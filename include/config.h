#ifndef __CONFIG_H__
#define __CONFIG_H__

#include <stdint.h>

#define DEFAULT_CONFIG "etc/specter.conf"

struct config {
	uint16_t listen_port;
	uint32_t listen_addr;

	uint16_t listen_node_port;
	uint32_t listen_node_addr;

	uint16_t designator_port;
	uint32_t designator_addr;

	char *public_key;
	char *private_key;

	float node_connect_timeout;
	float designator_connect_timeout;
};

struct config *config_get(void);
int config_read(const char *path);

#endif

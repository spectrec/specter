#include "libev.h"
#include "config.h"

int main(void)
{
	if (config_read(DEFAULT_CONFIG) != 0)
		return -1;

	if (libev_initialize() != 0)
		return -1;

	libev_run();

	return 0;
}

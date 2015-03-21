#include "config.h"

int main(void)
{
	if (config_read(DEFAULT_CONFIG) != 0)
		return -1;

	return 0;
}

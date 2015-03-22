#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>

enum log_level {
	LOG_ERR		= 1,
	LOG_WARN	= 2,
	LOG_INFO	= 3,
	LOG_DEBUG	= 4,
};

#define log(_level, _fmt, _args...) fprintf(stderr, _fmt "\n", ##_args)

#define log_e(_fmt, _args...) log(LOG_ERR, _fmt, ##_args)
#define log_w(_fmt, _args...) log(LOG_WARN, _fmt, ##_args)
#define log_i(_fmt, _args...) log(LOG_INFO, _fmt, ##_args)
#define log_d(_fmt, _args...) log(LOG_DEBUG, _fmt, ##_args)

#endif

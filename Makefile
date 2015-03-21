CC = gcc

CFLAGS = -std=gnu99 \
	 -D_GNU_SOURCE \
	 -Iinclude \
	 -Wall \
	 -Wextra \
	 -Werror \
	 -MMD -MP

LDFLAGS = -lev -ggdb3

sources = src/main.c \
	  src/config.c

program = specter

ifeq (${COV},1)
CFLAGS += --coverage
endif

ifeq (${NO_LTO},)
CFLAGS += -flto
LDFLAGS += -flto
endif

deps = $(patsubst %.c,%.d,${sources})
objects = $(patsubst %.c,%.o,${sources})

all: ${program}

${program}: ${objects}
	$(CC) -o $@ $^ ${CFLAGS} ${LDFLAGS}

-include ${deps}


clean:
	@rm -f src/*.{d,o}

.PHONY: clean all

#pragma once

#include <stdint.h>
#include <cstdio>

/* ############# USEFUL MACROS ########## */
#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    /* Don't do anything in release builds */
#endif

/* Can be used to update the timeout */
#define TIMEOUT_SEND(delay) (delay == 0 ? 100 : delay / 2 + 30)

#include <stdlib.h>
#include <errno.h>
#define DIE(assertion, call_description)						\
	do {													    \
		if (assertion) {										\
			fprintf(stderr, "(%s, %d): ", __FILE__, __LINE__);	\
			perror(call_description);							\
			exit(errno);										\
		}												        \
	} while (0)

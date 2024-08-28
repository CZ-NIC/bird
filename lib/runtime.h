/*
 *	BIRD Internet Routing Daemon -- Global runtime context
 *
 *	(c) 2024       Maria Matejka <mq@jmq.cz>
 *	(c) 2024       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/timer.h"

/* Shutdown requested, behave accordingly.
 * Initially zero, once set to one, never reset. */
extern int shutting_down;

/* I/O loops log information about task scheduling */
enum latency_debug_flags {
  DL_PING = 1,
  DL_WAKEUP = 2,
  DL_SCHEDULING = 4,
  DL_ALLOCATOR = 8,
  DL_SOCKETS = 0x10,
  DL_EVENTS = 0x20,
  DL_TIMERS = 0x40,
};

#define GLOBAL_RUNTIME_CONTENTS \
  struct timeformat tf_log;		/* Time format for the logfile */		\
  struct timeformat tf_base;		/* Time format for other purposes */		\
  btime load_time;			/* When we reconfigured last time */		\
  enum latency_debug_flags latency_debug;	/* What to log about IO loop */		\
  u32 latency_limit;			/* Events with longer duration are logged (us) */	\
  u32 watchdog_warning;			/* I/O loop watchdog limit for warning (us) */	\
  const char *hostname;			/* Hostname */					\

struct global_runtime { GLOBAL_RUNTIME_CONTENTS };
extern struct global_runtime * _Atomic global_runtime;

void switch_runtime(struct global_runtime *);

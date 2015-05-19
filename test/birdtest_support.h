#include "sysdep/config.h"
#include "lib/event.c"		/* REMOVE ME */
#include "lib/ip.c"		/* REMOVE ME */
#include "lib/resource.c"	/* REMOVE ME */
#include "lib/printf.c"		/* REMOVE ME */
#include "lib/xmalloc.c"	/* REMOVE ME */
#include "lib/bitops.c"		/* REMOVE ME */
#include "lib/mempool.c"	/* REMOVE ME */

#define bug(msg, ...)		debug("BUG: "     msg, ##__VA_ARGS__)
#define log_msg(msg, ...)	debug("LOG_MSG: " msg, ##__VA_ARGS__)

void
debug(const char *msg, ...)
{
  va_list argptr;
  va_start(argptr, msg);
  vfprintf(stderr, msg, argptr);
  va_end(argptr);
};

void
die(const char *msg, ...)
{
  va_list argptr;
  va_start(argptr, msg);
  vfprintf(stderr, msg, argptr);
  va_end(argptr);
  exit(3);
};

void
io_log_event(void *hook, void *data)
{
  bt_debug("This is io_log_event mockup. \n");
};

#include "lib/slab.c"		/* REMOVE ME */

#include "sysdep/config.h"
#include "lib/event.c" 		/* REMOVE ME */
#include "lib/ip.c"		/* REMOVE ME */
#include "lib/resource.c"	/* REMOVE ME */
#include "lib/printf.c"		/* REMOVE ME */
#include "lib/xmalloc.c"	/* REMOVE ME */
#include "lib/bitops.c"		/* REMOVE ME */

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

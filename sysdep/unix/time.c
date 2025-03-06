/*
 *	BIRD Internet Routing Daemon -- Clock
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *      (c) 2004       Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* Unfortunately, some glibc versions hide parts of RFC 3542 API
   if _GNU_SOURCE is not defined. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netdb.h>

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/locking.h"
#include "lib/timer.h"
#include "lib/string.h"
#include "nest/iface.h"
#include "conf/conf.h"

#include "sysdep/unix/unix.h"
#include "sysdep/unix/io-loop.h"

/* Maximum number of calls of tx handler for one socket in one
 * poll iteration. Should be small enough to not monopolize CPU by
 * one protocol instance.
 */
#define MAX_STEPS 4

/* Maximum number of calls of rx handler for all sockets in one poll
   iteration. RX callbacks are often much more costly so we limit
   this to gen small latencies */
#define MAX_RX_STEPS 4


/*
 *	Time clock
 */

btime boot_time;


void
times_update(void)
{
  struct timespec ts;
  int rv;

  btime old_time = current_time();
  btime old_real_time = current_real_time();

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("Monotonic clock is missing");

  if ((ts.tv_sec < 0) || (((u64) ts.tv_sec) > ((u64) 1 << 40)))
    log(L_WARN "Monotonic clock is crazy");

  btime new_time = ts.tv_sec S + ts.tv_nsec NS;

  if (new_time < old_time)
    log(L_ERR "Monotonic clock is broken");

  rv = clock_gettime(CLOCK_REALTIME, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  btime new_real_time = ts.tv_sec S + ts.tv_nsec NS;

  if (!atomic_compare_exchange_strong_explicit(
      &last_time,
      &old_time,
      new_time,
      memory_order_acq_rel,
      memory_order_relaxed))
    DBG("Time update collision: last_time");

  if (!atomic_compare_exchange_strong_explicit(
      &real_time,
      &old_real_time,
      new_real_time,
      memory_order_acq_rel,
      memory_order_relaxed))
    DBG("Time update collision: real_time");
}

btime
current_time_now(void)
{
  struct timespec ts;
  int rv;

  rv = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (rv < 0)
    die("clock_gettime: %m");

  return ts.tv_sec S + ts.tv_nsec NS;
}

/*
 *	BIRD Internet Routing Daemon -- Unix I/O
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
#include <sys/stat.h>
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
#include "nest/cli.h"
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

#if 0
/**********
 * Internal event log for the mainloop only makes no sense.
 * To be replaced by a lockless event log keeping much more information
 * about all the logs throughout all the threads.
 */

/*
 *	Internal event log and watchdog
 */

#define EVENT_LOG_LENGTH 32

struct event_log_entry
{
  void *hook;
  void *data;
  btime timestamp;
  btime duration;
};

static struct event_log_entry event_log[EVENT_LOG_LENGTH];
static struct event_log_entry *event_open;
static int event_log_pos, event_log_num, watchdog_active;
static btime last_io_time;
static btime loop_time;

static void
io_update_time(void)
{
  last_io_time = current_time();

  if (event_open)
  {
    event_open->duration = last_io_time - event_open->timestamp;

    struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
    if (event_open->duration > gr->latency_limit)
      log(L_WARN "Event 0x%p 0x%p took %u.%03u ms",
	  event_open->hook, event_open->data, (uint) (event_open->duration TO_MS), (uint) (event_open->duration % 1000));

    event_open = NULL;
  }
}

/**
 * io_log_event - mark approaching event into event log
 * @hook: event hook address
 * @data: event data address
 *
 * Store info (hook, data, timestamp) about the following internal event into
 * a circular event log (@event_log). When latency tracking is enabled, the log
 * entry is kept open (in @event_open) so the duration can be filled later.
 */
void
io_log_event(void *hook, void *data, uint flag)
{
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  if (gr->latency_debug & flag)
    io_update_time();

  struct event_log_entry *en = event_log + event_log_pos;

  en->hook = hook;
  en->data = data;
  en->timestamp = last_io_time;
  en->duration = 0;

  event_log_num++;
  event_log_pos++;
  event_log_pos %= EVENT_LOG_LENGTH;

  event_open = (gr->latency_debug & flag) ? en : NULL;
}

static inline void
io_close_event(void)
{
  if (event_open)
    io_update_time();
}

void
io_log_dump(struct dump_request *dreq)
{
  int i;

  RDUMP("Event log:\n");
  for (i = 0; i < EVENT_LOG_LENGTH; i++)
  {
    struct event_log_entry *en = event_log + (event_log_pos + i) % EVENT_LOG_LENGTH;
    if (en->hook)
      RDUMP("  Event 0x%p 0x%p at %8d for %d ms\n", en->hook, en->data,
	  (int) ((last_io_time - en->timestamp) TO_MS), (int) (en->duration TO_MS));
  }
}

#endif

static btime last_io_time, loop_time;
static int watchdog_active;

void
watchdog_sigalrm(int sig UNUSED)
{
  /* Update last_io_time and duration, but skip latency check */
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  gr->latency_limit = 0xffffffff;

  last_io_time = current_time_now();

  debug_safe("Watchdog timer timed out\n");

  /* We want core dump */
  abort();
}

static inline void
watchdog_start1(void)
{
  loop_time = last_io_time = current_time_now();
}

static inline void
watchdog_start(void)
{
  loop_time = last_io_time = current_time_now();
//  event_log_num = 0;

  union bird_global_runtime *gr = BIRD_GLOBAL_RUNTIME;
  if (gr->watchdog_timeout)
  {
    alarm(gr->watchdog_timeout);
    watchdog_active = 1;
  }
}

static inline void
watchdog_stop(void)
{
  last_io_time = current_time_now();

  if (watchdog_active)
  {
    alarm(0);
    watchdog_active = 0;
  }

  btime duration = last_io_time - loop_time;
  union bird_global_runtime *gr = BIRD_GLOBAL_RUNTIME;
  /*
  if (duration > gr->watchdog_warning)
    log(L_WARN "I/O loop cycle took %u.%03u ms for %d events",
	(uint) (duration TO_MS), (uint) (duration % 1000), event_log_num);
	*/

  if (duration > gr->watchdog_warning)
    log(L_WARN "I/O loop cycle took %u.%03u ms",
	(uint) (duration TO_MS), (uint) (duration % 1000));
}


/*
 *	Main I/O Loop
 */

void
io_init(void)
{
  init_list(&main_birdloop.sock_list);
  ev_init_list(&global_event_list, &main_birdloop, "Global event list");
  ev_init_list(&global_work_list, &main_birdloop, "Global work list");
  ev_init_list(&main_birdloop.event_list, &main_birdloop, "Global fast event list");
  krt_io_init();
  // XXX init_times();
  // XXX update_times();
  boot_time = current_time();

  u64 now = (u64) current_real_time();
  srandom((uint) (now ^ (now >> 32)));
}

static int short_loops = 0;
#define SHORT_LOOP_MAX 10
#define WORK_EVENTS_MAX 10

extern sock *stored_sock; /* mainloop hack */

int sk_read(sock *s, int revents);
int sk_write(sock *s);
void sk_err(sock *s, int revents);

void
io_loop(void)
{
  int poll_tout, timeout;
  int events, pout;
  timer *t;
  struct pfd pfd;
  BUFFER_INIT(pfd.pfd, &root_pool, 16);
  BUFFER_INIT(pfd.loop, &root_pool, 16);

  watchdog_start1();
  for(;;)
    {
      times_update();
      ev_run_list(&global_event_list);
      ev_run_list_limited(&global_work_list, WORK_EVENTS_MAX);
      ev_run_list(&main_birdloop.event_list);
      timers_fire(&main_birdloop.time);
//      io_close_event();

      events =
	!ev_list_empty(&global_event_list) ||
	!ev_list_empty(&global_work_list) ||
	!ev_list_empty(&main_birdloop.event_list);

      poll_tout = (events ? 0 : 3000); /* Time in milliseconds */
      if (t = timers_first(&main_birdloop.time))
      {
	times_update();
	timeout = (tm_remains(t) TO_MS) + 1;
	poll_tout = MIN(poll_tout, timeout);
      }

      BUFFER_FLUSH(pfd.pfd);
      BUFFER_FLUSH(pfd.loop);

      pipe_pollin(&main_birdloop.thread->wakeup, &pfd);
      sockets_prepare(&main_birdloop, &pfd);

      /*
       * Yes, this is racy. But even if the signal comes before this test
       * and entering poll(), it gets caught on the next timer tick.
       */

      if (async_config_flag)
	{
//	  io_log_event(async_config, NULL, DL_EVENTS);
	  async_config();
	  async_config_flag = 0;
	  continue;
	}
      if (async_dump_flag)
	{
//	  io_log_event(async_dump, NULL, DL_EVENTS);
	  async_dump();
	  async_dump_flag = 0;
	  continue;
	}
      if (async_shutdown_flag)
	{
//	  io_log_event(async_shutdown, NULL, DL_EVENTS);
	  async_shutdown();
	  async_shutdown_flag = 0;
	  continue;
	}

      /* And finally enter poll() to find active sockets */
      watchdog_stop();
      birdloop_leave(&main_birdloop);
      pout = poll(pfd.pfd.data, pfd.pfd.used, poll_tout);
      birdloop_enter(&main_birdloop);
      watchdog_start();

      if (pout < 0)
	{
	  if (errno == EINTR || errno == EAGAIN)
	    continue;
	  bug("poll: %m");
	}
      if (pout)
	{
	  if (pfd.pfd.data[0].revents & POLLIN)
	  {
	    /* IO loop reload requested */
	    pipe_drain(&main_birdloop.thread->wakeup);
	    atomic_fetch_and_explicit(&main_birdloop.thread_transition, ~LTT_PING, memory_order_acq_rel);
	    continue;
	  }

	  times_update();

	  /* guaranteed to be non-empty */
	  main_birdloop.sock_active = SKIP_BACK(sock, n, HEAD(main_birdloop.sock_list));

	  while (main_birdloop.sock_active)
	  {
	    sock *s = main_birdloop.sock_active;
	    if (s->index != -1)
	    {
	      int e;
	      int steps;

	      steps = MAX_STEPS;
	      if (s->fast_rx && (pfd.pfd.data[s->index].revents & POLLIN) && s->rx_hook)
		do
		  {
		    steps--;
//		    io_log_event(s->rx_hook, s->data, DL_SOCKETS);
		    e = sk_read(s, pfd.pfd.data[s->index].revents);
		  }
		while (e && (main_birdloop.sock_active == s) && s->rx_hook && steps);

	      if (s != main_birdloop.sock_active)
		continue;

	      steps = MAX_STEPS;
	      if (pfd.pfd.data[s->index].revents & POLLOUT)
		do
		  {
		    steps--;
//		    io_log_event(s->tx_hook, s->data, DL_SOCKETS);
		    e = sk_write(s);
		  }
		while (e && (main_birdloop.sock_active == s) && steps);

	      if (s != main_birdloop.sock_active)
		continue;
	    }

	    main_birdloop.sock_active = sk_next(s);
	  }

	  short_loops++;
	  if (events && (short_loops < SHORT_LOOP_MAX))
	    continue;
	  short_loops = 0;

	  int count = 0;
	  main_birdloop.sock_active = stored_sock;
	  if (main_birdloop.sock_active == NULL)
	    main_birdloop.sock_active = SKIP_BACK(sock, n, HEAD(main_birdloop.sock_list));

	  while (main_birdloop.sock_active && count < MAX_RX_STEPS)
	    {
	      sock *s = main_birdloop.sock_active;
	      if (s->index == -1)
		goto next2;

	      if (!s->fast_rx && (pfd.pfd.data[s->index].revents & POLLIN) && s->rx_hook)
		{
		  count++;
//		  io_log_event(s->rx_hook, s->data, DL_SOCKETS);
		  sk_read(s, pfd.pfd.data[s->index].revents);
		  if (s != main_birdloop.sock_active)
		    continue;
		}

	      if (pfd.pfd.data[s->index].revents & (POLLHUP | POLLERR))
		{
		  sk_err(s, pfd.pfd.data[s->index].revents);
		  if (s != main_birdloop.sock_active)
		    continue;
		}

	    next2: ;
	      main_birdloop.sock_active = sk_next(s);
	    }


	  stored_sock = main_birdloop.sock_active;
	}
    }
}

void
test_old_bird(const char *path)
{
  int fd;
  struct sockaddr_un sa;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    die("Cannot create socket: %m");
  if (strlen(path) >= sizeof(sa.sun_path))
    die("Socket path too long");
  bzero(&sa, sizeof(sa));
  sa.sun_family = AF_UNIX;
  strcpy(sa.sun_path, path);
  if (connect(fd, (struct sockaddr *) &sa, SUN_LEN(&sa)) == 0)
    die("I found another BIRD running.");
  close(fd);
}


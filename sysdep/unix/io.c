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


/*
 *	Tracked Files
 */

struct rfile {
  resource r;
  struct stat stat;
  int fd;
  off_t limit;
  _Atomic off_t pos;
  void *mapping;
};

struct rfile rf_stderr = {
  .fd = 2,
};

static void
rf_free(resource *r)
{
  struct rfile *a = (struct rfile *) r;

  if (a->mapping)
    munmap(a->mapping, a->limit);

  close(a->fd);
}

static void
rf_dump(struct dump_request *dreq, resource *r)
{
  struct rfile *a = (struct rfile *) r;

  RDUMP("(fd %d)\n", a->fd);
}

static struct resclass rf_class = {
  "FILE",
  sizeof(struct rfile),
  rf_free,
  rf_dump,
  NULL,
  NULL
};

int
rf_fileno(struct rfile *f)
{
  return f->fd;
}

static int
rf_open_get_fd(const char *name, enum rf_mode mode)
{
  int omode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;
  int flags;

  switch (mode)
  {
    case RF_APPEND:
      flags = O_WRONLY | O_CREAT | O_APPEND;
      break;

    case RF_FIXED:
      flags = O_RDWR | O_CREAT;
      break;

    default:
      bug("rf_open() must have the mode set");
  }

  return open(name, flags, omode);
}

static void
rf_stat(struct rfile *r)
{
  if (fstat(r->fd, &r->stat) < 0)
    die("fstat() failed: %m");
}

struct rfile *
rf_open(pool *p, const char *name, enum rf_mode mode, off_t limit)
{
  int fd = rf_open_get_fd(name, mode);
  if (fd < 0)
    return NULL; /* The caller takes care of printing %m. */

  struct rfile *r = ralloc(p, &rf_class);
  r->fd = fd;
  r->limit = limit;

  switch (mode)
  {
    case RF_APPEND:
      rf_stat(r);
      atomic_store_explicit(&r->pos, S_ISREG(r->stat.st_mode) ? r->stat.st_size : 0, memory_order_relaxed);
      break;

    case RF_FIXED:
      if ((ftruncate(fd, limit) < 0)
	  || ((r->mapping = mmap(NULL, limit, PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED))
      {
	int erf = errno;
	r->mapping = NULL;
	rfree(r);
	errno = erf;
	return NULL;
      }
      break;

    default:
      bug("rf_open() must have the mode set");
  }


  return r;
}

off_t
rf_size(struct rfile *r)
{
  return atomic_load_explicit(&r->pos, memory_order_relaxed);
}

int
rf_same(struct rfile *a, struct rfile *b)
{
  rf_stat(a);
  rf_stat(b);

  return
    (a->limit == b->limit) &&
    (a->stat.st_mode == b->stat.st_mode) &&
    (a->stat.st_dev == b->stat.st_dev) &&
    (a->stat.st_ino == b->stat.st_ino);
}

void
rf_write_crude(struct rfile *r, const char *buf, int sz)
{
  if (r->mapping)
    memcpy(r->mapping, buf, sz);
  else
    write(r->fd, buf, sz);
}


int
rf_writev(struct rfile *r, struct iovec *iov, int iov_count)
{
  off_t size = 0;
  for (int i = 0; i < iov_count; i++)
    size += iov[i].iov_len;

  if (r->mapping)
  {
    /* Update the pointer */
    off_t target = atomic_fetch_add_explicit(&r->pos, size, memory_order_relaxed) % r->limit;

    /* Write the line */
    for (int i = 0; i < iov_count; i++)
    {
      /* Take care of wrapping; this should really happen only once */
      off_t rsz;
      while ((rsz = r->limit - target) < (off_t) iov[i].iov_len)
      {
	memcpy(r->mapping + target, iov[i].iov_base, rsz);
	iov[i].iov_base += rsz;
	iov[i].iov_len -= rsz;
	target = 0;
      }

      memcpy(r->mapping + target, iov[i].iov_base, iov[i].iov_len);
      target += iov[i].iov_len;
    }
    return 1;
  }
  else if (r->limit && (atomic_fetch_add_explicit(&r->pos, size, memory_order_relaxed) + size > r->limit))
  {
    atomic_fetch_sub_explicit(&r->pos, size, memory_order_relaxed);
    return 0;
  }
  else
  {
    while (size > 0)
    {
      /* Try to write */
      ssize_t e = writev(r->fd, iov, iov_count);
      if (e < 0)
	if (errno == EINTR)
	  continue;
	else
	  return 1; /* FIXME: What should we do when we suddenly can't write? */

      /* It is expected that we always write the whole bunch at once */
      if (e == size)
	return 1;

      /* Block split should not happen (we write small enough messages)
       * but if it happens, let's try to write the rest of the log */
      size -= e;
      while (e > 0)
      {
	if ((ssize_t) iov[0].iov_len > e)
	{
	  /* Some bytes are remaining in the first chunk */
	  iov[0].iov_len -= e;
	  iov[0].iov_base += e;
	  break;
	}

	/* First chunk written completely, get rid of it */
	e -= iov[0].iov_len;
	iov++;
	iov_count--;
	ASSERT_DIE(iov_count > 0);
      }
    }

    return 1;
  }
}

/*
 *	Dumping to files
 */

struct dump_request_file {
  struct dump_request dr;
  uint pos, max; int fd;
  uint last_progress_info;
  char data[0];
};

static void
dump_to_file_flush(struct dump_request_file *req)
{
  if (req->fd < 0)
    return;

  for (uint sent = 0; sent < req->pos; )
  {
    int e = write(req->fd, &req->data[sent], req->pos - sent);
    if (e <= 0)
    {
      req->dr.report(&req->dr, 8009, "Failed to write data: %m");
      close(req->fd);
      req->fd = -1;
      return;
    }
    sent += e;
  }

  req->dr.size += req->pos;
  req->pos = 0;

  for (uint reported = 0; req->dr.size >> req->last_progress_info; req->last_progress_info++)
    if (!reported++)
      req->dr.report(&req->dr, -13, "... dumped %lu bytes in %t s",
	  req->dr.size, current_time_now() - req->dr.begin);
}

static void
dump_to_file_write(struct dump_request *dr, const char *fmt, ...)
{
  struct dump_request_file *req = SKIP_BACK(struct dump_request_file, dr, dr);

  for (uint phase = 0; (req->fd >= 0) && (phase < 2); phase++)
  {
    va_list args;
    va_start(args, fmt);
    int i = bvsnprintf(&req->data[req->pos], req->max - req->pos, fmt, args);
    va_end(args);

    if (i >= 0)
    {
      req->pos += i;
      return;
    }
    else
      dump_to_file_flush(req);
  }

  bug("Too long dump call");
}

struct dump_request *
dump_to_file_init(off_t offset)
{
  ASSERT_DIE(offset + sizeof(struct dump_request_file) + 1024 < (unsigned long) page_size);

  struct dump_request_file *req = alloc_page() + offset;
  *req = (struct dump_request_file) {
    .dr = {
      .write = dump_to_file_write,
      .begin = current_time_now(),
      .offset = offset,
    },
    .max = page_size - offset - OFFSETOF(struct dump_request_file, data[0]),
    .fd = -1,
  };

  return &req->dr;
}

void
dump_to_file_run(struct dump_request *dr, const char *file, const char *what, void (*dump)(struct dump_request *))
{
  struct dump_request_file *req = SKIP_BACK(struct dump_request_file, dr, dr);
  req->fd = open(file, O_CREAT | O_WRONLY | O_EXCL, S_IRUSR);

  if (req->fd < 0)
  {
    dr->report(dr, 8009, "Failed to open file %s: %m", file);
    goto cleanup;
  }

  dr->report(dr, -13, "Dumping %s to %s", what, file);

  dump(dr);

  if (req->fd >= 0)
  {
    dump_to_file_flush(req);
    close(req->fd);
  }

  btime end = current_time_now();
  dr->report(dr, 13, "Dumped %lu bytes in %t s", dr->size, end - dr->begin);

cleanup:
  free_page(((void *) req) - dr->offset);
}

struct dump_request_cli {
  cli *cli;
  struct dump_request dr;
};

static void
cmd_dump_report(struct dump_request *dr, int state, const char *fmt, ...)
{
  struct dump_request_cli *req = SKIP_BACK(struct dump_request_cli, dr, dr);
  va_list args;
  va_start(args, fmt);
  cli_vprintf(req->cli, state, fmt, args);
  va_end(args);
}

void
cmd_dump_file(struct cli *cli, const char *file, const char *what, void (*dump)(struct dump_request *))
{
  if (cli->restricted)
    return cli_printf(cli, 8007, "Access denied");

  struct dump_request_cli *req = SKIP_BACK(struct dump_request_cli, dr,
      dump_to_file_init(OFFSETOF(struct dump_request_cli, dr)));

  req->cli = cli;
  req->dr.report = cmd_dump_report;

  dump_to_file_run(&req->dr, file, what, dump);
}


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

void
watchdog_sigalrm(int sig UNUSED)
{
  /* Update last_io_time and duration, but skip latency check */
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  gr->latency_limit = 0xffffffff;
  io_update_time();

  debug_safe("Watchdog timer timed out\n");

  /* We want core dump */
  abort();
}

static inline void
watchdog_start1(void)
{
  io_update_time();

  loop_time = last_io_time;
}

static inline void
watchdog_start(void)
{
  io_update_time();

  loop_time = last_io_time;
  event_log_num = 0;

  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  if (gr->watchdog_timeout)
  {
    alarm(gr->watchdog_timeout);
    watchdog_active = 1;
  }
}

static inline void
watchdog_stop(void)
{
  io_update_time();

  if (watchdog_active)
  {
    alarm(0);
    watchdog_active = 0;
  }

  btime duration = last_io_time - loop_time;
  struct global_runtime *gr = atomic_load_explicit(&global_runtime, memory_order_relaxed);
  if (duration > gr->watchdog_warning)
    log(L_WARN "I/O loop cycle took %u.%03u ms for %d events",
	(uint) (duration TO_MS), (uint) (duration % 1000), event_log_num);
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

sock *stored_sock;

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
      timers_fire(&main_birdloop.time, 1);
      io_close_event();

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
	  io_log_event(async_config, NULL, DL_EVENTS);
	  async_config();
	  async_config_flag = 0;
	  continue;
	}
      if (async_dump_flag)
	{
	  io_log_event(async_dump, NULL, DL_EVENTS);
	  async_dump();
	  async_dump_flag = 0;
	  continue;
	}
      if (async_shutdown_flag)
	{
	  io_log_event(async_shutdown, NULL, DL_EVENTS);
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
		    io_log_event(s->rx_hook, s->data, DL_SOCKETS);
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
		    io_log_event(s->tx_hook, s->data, DL_SOCKETS);
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
		  io_log_event(s->rx_hook, s->data, DL_SOCKETS);
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


/*
 *	DNS resolver
 */

ip_addr
resolve_hostname(const char *host, int type, const char **err_msg)
{
  struct addrinfo *res;
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = (type == SK_UDP) ? SOCK_DGRAM : SOCK_STREAM,
    .ai_flags = AI_ADDRCONFIG,
  };

  *err_msg = NULL;

  int err_code = getaddrinfo(host, NULL, &hints, &res);
  if (err_code != 0)
  {
    *err_msg = gai_strerror(err_code);
    return IPA_NONE;
  }

  ip_addr addr = IPA_NONE;
  uint unused;

  sockaddr_read((sockaddr *) res->ai_addr, res->ai_family, &addr, NULL, &unused);
  freeaddrinfo(res);

  return addr;
}

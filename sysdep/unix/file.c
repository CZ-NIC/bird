/*
 *	BIRD Internet Routing Daemon -- Tracked Files
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
#include "nest/cli.h"
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

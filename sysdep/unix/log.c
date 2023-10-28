/*
 *	BIRD Library -- Logging Functions
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Logging
 *
 * The Logging module offers a simple set of functions for writing
 * messages to system logs and to the debug output. Message classes
 * used by this module are described in |birdlib.h| and also in the
 * user's manual.
 */

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

#include "nest/bird.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/lists.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/io-loop.h"

static pool *log_pool;

static struct rfile *dbg_rf;
static char *current_syslog_name = NULL; /* NULL -> syslog closed */

_Atomic uint max_thread_id = ATOMIC_VAR_INIT(1);
_Thread_local uint this_thread_id;

#include <pthread.h>

DEFINE_DOMAIN(logging);
static DOMAIN(logging) log_domain;
#define log_lock()  LOCK_DOMAIN(logging, log_domain);
#define log_unlock()  UNLOCK_DOMAIN(logging, log_domain);

static struct log_channel * _Atomic global_logs;

/* Logging flags to validly prepare logging messages */
#define LOGGING_TO_TERMINAL   0x1
#define LOGGING_TO_FILE	      0x2

static _Atomic uint logging_flags;
static _Atomic uint logging_mask;

#ifdef HAVE_SYSLOG_H
#include <sys/syslog.h>

static int syslog_priorities[] = {
  LOG_DEBUG,
  LOG_DEBUG,
  LOG_DEBUG,
  LOG_INFO,
  LOG_ERR,
  LOG_WARNING,
  LOG_ERR,
  LOG_ERR,
  LOG_CRIT,
  LOG_CRIT
};
#endif

static char *class_names[] = {
  "???",
  "DBG",
  "TRACE",
  "INFO",
  "RMT",
  "WARN",
  "ERR",
  "AUTH",
  "FATAL",
  "BUG"
};

struct log_channel {
  struct log_channel * _Atomic next;
  const char *filename;			/* Log filename */
  const char *backup;			/* Secondary filename (for log rotation) */
  struct rfile * _Atomic rf;		/* File handle */
  off_t limit;				/* Log size limit */
  _Atomic uint mask;			/* Classes to log */
  uint new_mask;			/* Pending new mask */
  uint terminal:1;			/* Is terminal */
};

struct log_thread_syncer {
  struct bird_thread_syncer sync;
  struct log_channel *lc_close;
  struct rfile *rf_close;
  const char *name;
  event lts_event;
};

static void
lts_done(struct bird_thread_syncer *sync)
{
  struct log_thread_syncer *lts = SKIP_BACK(struct log_thread_syncer, sync, sync);

  log_lock();
  if (lts->lc_close)
  {
    lts->rf_close = atomic_load_explicit(&lts->lc_close->rf, memory_order_relaxed);
    mb_free(lts->lc_close);
  }

  if (lts->rf_close && lts->rf_close != &rf_stderr)
    rfree(lts->rf_close);

  mb_free(lts);
  log_unlock();
}

static void
lts_event(void *_lts)
{
  struct log_thread_syncer *lts = _lts;
  bird_thread_sync_all(&lts->sync, NULL, lts_done, lts->name);
}

static void
lts_request(struct log_channel *lc_close, struct rfile *rf_close, const char *name)
{
  struct log_thread_syncer *lts = mb_allocz(log_pool, sizeof *lts);
  lts->lc_close = lc_close;
  lts->rf_close = rf_close;
  lts->name = name;
  lts->lts_event = (event) { .hook = lts_event, .data = lts, };
  ev_send_loop(&main_birdloop, &lts->lts_event);
}

static void
log_rotate(struct log_channel *lc)
{
  struct log_thread_syncer *lts = mb_allocz(log_pool, sizeof *lts);

  if ((rename(lc->filename, lc->backup) < 0) && (unlink(lc->filename) < 0))
    return lts_request(lc, NULL, "Log Rotate Failed");

  struct rfile *rf = rf_open(log_pool, lc->filename, RF_APPEND, lc->limit);
  if (!rf)
    return lts_request(lc, NULL, "Log Rotate Failed");

  lts_request(NULL, atomic_load_explicit(&lc->rf, memory_order_relaxed), "Log Rotate Close Old File");
  atomic_store_explicit(&lc->rf, rf, memory_order_release);
}

#define LOG_MSG_OFFSET	(TM_DATETIME_BUFFER_SIZE + 64)

/**
 * log_commit - commit a log message
 * @class: message class information (%L_DEBUG to %L_BUG, see |lib/birdlib.h|)
 * @buf: message to write
 *
 * This function writes a message prepared in the log buffer to the
 * log file (as specified in the configuration). The log buffer is
 * reset after that. The log message is a full line, log_commit()
 * terminates it.
 *
 * The message class is an integer, not a first char of a string like
 * in log(), so it should be written like *L_INFO.
 */
void
log_commit(log_buffer *buf)
{
  if (buf->buf.pos == buf->buf.end)
#define TOO_LONG " ... <too long>"
    memcpy(buf->buf.end - sizeof TOO_LONG, TOO_LONG, sizeof TOO_LONG);
#undef TOO_LONG

  for (
      struct log_channel *l = atomic_load_explicit(&global_logs, memory_order_acquire);
      l;
      l = atomic_load_explicit(&l->next, memory_order_acquire)
      )
    {
      uint mask = atomic_load_explicit(&l->mask, memory_order_acquire);
      if (!(mask & (1 << buf->class)))
	continue;

      struct rfile *rf = atomic_load_explicit(&l->rf, memory_order_acquire);
      if (rf && buf->tm_pos)
	{
	  *buf->buf.pos = '\n';
	  byte *begin = l->terminal ? buf->buf.start : buf->tm_pos;
	  off_t msg_len = buf->buf.pos - begin + 1;
	  do {
	    if (rf_write(rf, begin, msg_len))
	      break;

	    log_lock();
	    rf = atomic_load_explicit(&l->rf, memory_order_acquire);
	    if (rf_write(rf, begin, msg_len))
	    {
	      log_unlock();
	      break;
	    }

	    log_rotate(l);
	    log_unlock();

	    rf = atomic_load_explicit(&l->rf, memory_order_relaxed);
	  } while (!rf_write(rf, begin, msg_len));
	}
#ifdef HAVE_SYSLOG_H
      else
      {
	*buf->buf.pos = '\0';
	syslog(syslog_priorities[buf->class], "%s", buf->msg_pos);
      }
#endif
    }

  buf->msg_pos = buf->tm_pos = NULL;
}

int buffer_vprint(buffer *buf, const char *fmt, va_list args);

void
log_prepare(log_buffer *buf, int class)
{
  buf->buf.start = buf->buf.pos = buf->block;
  buf->buf.end = buf->block + sizeof buf->block;

  int lf = atomic_load_explicit(&logging_flags, memory_order_acquire);
  if (lf & LOGGING_TO_TERMINAL)
    buffer_puts(&buf->buf, "bird: ");

  if (lf & LOGGING_TO_FILE)
  {
    const char *fmt = config ? config->tf_log.fmt1 : "%F %T.%3f";

    buf->tm_pos = buf->buf.pos;
    int t = tm_format_real_time(buf->buf.pos, buf->buf.end - buf->buf.pos, fmt, current_real_time());
    if (t)
      buf->buf.pos += t;
    else
      buffer_puts(&buf->buf, "<time format error>");

    buffer_print(&buf->buf, " [%04x] <%s> ", THIS_THREAD_ID, class_names[class]);
  }
  else
    buf->tm_pos = NULL;

  buf->msg_pos = buf->buf.pos;
  buf->class = class;
}

static void
vlog(int class, const char *msg, va_list args)
{
  static _Thread_local log_buffer buf;

  /* No logging at all if nobody would receive the message either */
  if (!(atomic_load_explicit(&logging_mask, memory_order_acquire) & (1 << class)))
    return;

  log_prepare(&buf, class);
  buffer_vprint(&buf.buf, msg, args);
  log_commit(&buf);
}


/**
 * log - log a message
 * @msg: printf-like formatting string with message class information
 * prepended (%L_DEBUG to %L_BUG, see |lib/birdlib.h|)
 *
 * This function formats a message according to the format string @msg
 * and writes it to the corresponding log file (as specified in the
 * configuration). Please note that the message is automatically
 * formatted as a full line, no need to include |\n| inside.
 * It is essentially a sequence of log_reset(), logn() and log_commit().
 */
void
log_msg(const char *msg, ...)
{
  int class = 1;
  va_list args;

  va_start(args, msg);
  if (*msg >= 1 && *msg <= 8)
    class = *msg++;
  vlog(class, msg, args);
  va_end(args);
}

void
log_rl(struct tbf *f, const char *msg, ...)
{
  int class = 1;
  va_list args;

  /* Rate limiting is a bit tricky here as it also logs '...' during the first hit */
  if (tbf_limit(f) && (f->drop > 1))
    return;

  if (*msg >= 1 && *msg <= 8)
    class = *msg++;

  va_start(args, msg);
  vlog(class, (f->drop ? "..." : msg), args);
  va_end(args);
}

/**
 * bug - report an internal error
 * @msg: a printf-like error message
 *
 * This function logs an internal error and aborts execution
 * of the program.
 */
void
bug(const char *msg, ...)
{
  va_list args;

  va_start(args, msg);
  vlog(L_BUG[0], msg, args);
  va_end(args);
  abort();
}

/**
 * bug - report a fatal error
 * @msg: a printf-like error message
 *
 * This function logs a fatal error and aborts execution
 * of the program.
 */
void
die(const char *msg, ...)
{
  va_list args;

  va_start(args, msg);
  vlog(L_FATAL[0], msg, args);
  va_end(args);
  exit(1);
}

static struct timespec dbg_time_start;

/**
 * debug - write to debug output
 * @msg: a printf-like message
 *
 * This function formats the message @msg and prints it out
 * to the debugging output. No newline character is appended.
 */
void
debug(const char *msg, ...)
{
#define MAX_DEBUG_BUFSIZE 16384
  va_list args;
  char buf[MAX_DEBUG_BUFSIZE], *pos = buf;
  int max = MAX_DEBUG_BUFSIZE;

  va_start(args, msg);
  if (dbg_rf)
    {
      int s = bvsnprintf(pos, max, msg, args);
      if (s < 0)
	bug("Extremely long debug output, split it.");

      rf_write(dbg_rf, buf, s);
    }
  va_end(args);
}

/**
 * debug_safe - async-safe write to debug output
 * @msg: a string message
 *
 * This function prints the message @msg to the debugging output in a
 * way that is async safe and can be used in signal handlers. No newline
 * character is appended.
 */
void
debug_safe(const char *msg)
{
  if (dbg_rf)
    rf_write(dbg_rf, msg, strlen(msg));
}

static list *
default_log_list(int initial, const char **syslog_name)
{
  static list log_list;
  init_list(&log_list);
  *syslog_name = NULL;

#ifdef HAVE_SYSLOG_H
  if (!dbg_rf)
    {
      static struct log_config lc_syslog;
      lc_syslog = (struct log_config){
	.mask = ~0
      };

      add_tail(&log_list, &lc_syslog.n);
      *syslog_name = bird_name;
    }
#endif

  if (dbg_rf && (dbg_rf != &rf_stderr))
    {
      static struct log_config lc_debug;
      lc_debug = (struct log_config){
	.mask = ~0,
	.rf = dbg_rf,
      };

      add_tail(&log_list, &lc_debug.n);
    }

  if (initial || (dbg_rf == &rf_stderr))
    {
      static struct log_config lc_stderr;
      lc_stderr = (struct log_config){
	.mask = ~0,
	.terminal_flag = 1,
	.rf = &rf_stderr,
      };

      add_tail(&log_list, &lc_stderr.n);
    }

  return &log_list;
}

void
log_switch(int initial, list *logs, const char *new_syslog_name)
{
  if (initial)
  {
    log_domain = DOMAIN_NEW(logging);
    log_lock();
    log_pool = rp_new(&root_pool, log_domain.logging, "Log files");

#if HAVE_SYSLOG_H
    /* Create syslog channel */
    struct log_channel *lc = mb_alloc(log_pool, sizeof *lc);

    *lc = (struct log_channel) {};
    ASSERT_DIE(NULL == atomic_exchange_explicit(&global_logs, lc, memory_order_release));
#endif

    log_unlock();
  }

  if (!logs || EMPTY_LIST(*logs))
    logs = default_log_list(initial, &new_syslog_name);

  ASSERT_DIE(logs);

  /* Prepare the new log configuration */
  struct log_config *l;
  WALK_LIST(l, *logs)
  {
    int erf = 0;
    log_lock();
    if (l->rf && (l->rf != &rf_stderr))
      rmove(l->rf, log_pool);
    else if (l->filename)
    {
      l->rf = rf_open(log_pool, l->filename, RF_APPEND, l->limit);
      erf = l->rf ? 0 : errno;
    }
    log_unlock();
    if (erf)
      log(L_ERR "Failed to open log file '%s': %M", l->filename, erf);
  }

  uint total_mask = 0;
  uint flags = 0;

  /* Update pre-existing log channels */
  for (
      struct log_channel * _Atomic *pprev = &global_logs, *ol;
      ol = atomic_load_explicit(pprev, memory_order_acquire);
      pprev = &ol->next)
  {
    ol->new_mask = 0;
    if (ol->rf)
    {
      WALK_LIST(l, *logs)
	if (l->rf && rf_same(l->rf, ol->rf))
	{
	  /* Merge the mask */
	  ol->new_mask |= l->mask;
	  total_mask |= l->mask;

	  /* Merge flags */
	  flags |= LOGGING_TO_FILE;
	  if (l->terminal_flag)
	  {
	    flags |= LOGGING_TO_TERMINAL;
	    ol->terminal = 1;
	  }

	  /* The filehandle is no longer needed */
	  if (l->rf != &rf_stderr)
	  {
	    log_lock();
	    rfree(l->rf);
	    log_unlock();
	  }

	  l->rf = NULL;
	}
    }
    else
      WALK_LIST(l, *logs)
	if (!l->filename && !l->rf)
	{
	  ol->new_mask |= l->mask;
	  total_mask |= l->mask;
	}

    /* First only extend masks */
    atomic_fetch_or_explicit(&ol->mask, ol->new_mask, memory_order_acq_rel);
  }

  atomic_fetch_or_explicit(&logging_mask, total_mask, memory_order_acq_rel);

  /* Open new log channels */
  WALK_LIST(l, *logs)
  {
    if (!l->rf)
      continue;

    /* Truly new log channel */
    log_lock();
    struct log_channel *lc = mb_alloc(log_pool, sizeof *lc);
    log_unlock();

    *lc = (struct log_channel) {
      .filename = l->filename,
      .backup = l->backup,
      .rf = l->rf,
      .limit = l->limit,
      .new_mask = l->mask,
      .terminal = l->terminal_flag,
    };

    total_mask |= l->mask;

    /* Message preparation flags */
    flags |= LOGGING_TO_FILE;
    if (l->terminal_flag)
    {
      flags |= LOGGING_TO_TERMINAL;
      lc->terminal = 1;
    }

    /* Now the file handle ownership is transferred to the log channel */
    l->rf = NULL;

    /* Find more */
    for (struct log_config *ll = NODE_NEXT(l); NODE_VALID(ll); ll = NODE_NEXT(ll))
      if (ll->filename && ll->rf && rf_same(lc->rf, ll->rf))
      {
	/* Merged with this channel */
	lc->new_mask |= ll->mask;
	total_mask |= ll->mask;

	if (l->rf != &rf_stderr)
	{
	  log_lock();
	  rfree(ll->rf);
	  log_unlock();
	}
	ll->rf = NULL;
      }

    atomic_store_explicit(&lc->mask, lc->new_mask, memory_order_release);

    /* Insert into the main log list */
    struct log_channel *head = atomic_load_explicit(&global_logs, memory_order_acquire);
    do atomic_store_explicit(&lc->next, head, memory_order_release);
    while (!atomic_compare_exchange_strong_explicit(
	  &global_logs, &head, lc,
	  memory_order_acq_rel, memory_order_acquire));
  }

  /* Merge overall flags */
  atomic_fetch_or_explicit(&logging_flags, flags, memory_order_acq_rel);
  atomic_fetch_or_explicit(&logging_mask, total_mask, memory_order_acq_rel);

  /* Close end-of-life log channels */
  for (struct log_channel * _Atomic *pprev = &global_logs,
			  *ol = atomic_load_explicit(pprev, memory_order_acquire);
      ol; )
  {
    /* Store new mask after opening new files to minimize missing log message race conditions */
    atomic_store_explicit(&ol->mask, ol->new_mask, memory_order_release);

    /* Never close syslog channel */
    if (ol->new_mask || !ol->rf)
    {
      pprev = &ol->next;
      ol = atomic_load_explicit(pprev, memory_order_acquire);
    }
    else
    {
      /* This file has no logging set up, remove from list */
      struct log_channel *next = atomic_load_explicit(&ol->next, memory_order_acquire);
      atomic_store_explicit(pprev, next, memory_order_release);

      /* Free the channel after all worker threads leave the critical section */
      log_lock();
      lts_request(ol, NULL, "Log Reconfigure Close Old File");
      log_unlock();

      /* Continue to next */
      ol = next;
    }
  }

  /* Set overall flags after files are closed */
  atomic_store_explicit(&logging_flags, flags, memory_order_release);
  atomic_store_explicit(&logging_mask, total_mask, memory_order_release);

#ifdef HAVE_SYSLOG_H
  if ((!current_syslog_name != !new_syslog_name)
      || bstrcmp(current_syslog_name, new_syslog_name))
  {
    char *old_syslog_name = current_syslog_name;

    if (new_syslog_name)
    {
      current_syslog_name = xstrdup(new_syslog_name);
      openlog(current_syslog_name, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
    }
    else
    {
      current_syslog_name = NULL;
      closelog();
    }

    if (old_syslog_name)
      xfree(old_syslog_name);
  }
#endif
}

void
log_init_debug(char *f)
{
  clock_gettime(CLOCK_MONOTONIC, &dbg_time_start);

  if (dbg_rf && dbg_rf != &rf_stderr)
    rfree(dbg_rf);

  if (!f)
    dbg_rf = NULL;
  else if (!*f)
    dbg_rf = &rf_stderr;
  else if (!(dbg_rf = rf_open(&root_pool, f, RF_APPEND, 0)))
  {
    /* Cannot use die() nor log() here, logging is not yet initialized */
    fprintf(stderr, "bird: Unable to open debug file %s: %s\n", f, strerror(errno));
    exit(1);
  }
}

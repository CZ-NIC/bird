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
#include "lib/socket.h"
#include "sysdep/unix/unix.h"
#include "sysdep/unix/io-loop.h"

static pool *log_pool;

static struct rfile *dbg_rf;
static char *current_syslog_name = NULL; /* NULL -> syslog closed */

_Atomic uint max_thread_id = 1;
_Thread_local uint this_thread_id;

#include <pthread.h>

static DOMAIN(logging) log_domain;
#define log_lock()  LOCK_DOMAIN(logging, log_domain);
#define log_unlock()  UNLOCK_DOMAIN(logging, log_domain);

static struct log_channel * _Atomic global_logs;

/* Logging flags to validly prepare logging messages */

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
  uint prepare;				/* Which message parts to prepare */
  const char *udp_host;			/* UDP log dst host name */
  ip_addr udp_ip;			/* UDP log dst IP address */
  uint udp_port;			/* UDP log dst port */
  sock * _Atomic udp_sk;		/* UDP socket */
};

struct log_thread_syncer {
  struct bird_thread_syncer sync;
  struct log_channel *lc_close;
  struct rfile *rf_close;
  sock *sk_close;
  const char *name;
  event lts_event;
};

static void
lts_done(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct log_thread_syncer, lts, sync, sync);

  log_lock();
  if (lts->lc_close)
  {
    lts->rf_close = atomic_load_explicit(&lts->lc_close->rf, memory_order_relaxed);
    lts->sk_close = atomic_load_explicit(&lts->lc_close->udp_sk, memory_order_relaxed);
    mb_free(lts->lc_close);
  }

  if (lts->rf_close && lts->rf_close != &rf_stderr)
    rfree(lts->rf_close);

  if (lts->sk_close)
    rfree(lts->sk_close);

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
  /* Store the last pointer */
  buf->pos[LBP__MAX] = buf->buf.pos;

  /* Append the too-long message if too long */
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
      sock *sk = atomic_load_explicit(&l->udp_sk, memory_order_acquire);

      if (rf || sk)
	{
	  /* Construct the iovec */
	  static char terminal_prefix[] = "bird: ",
		      newline[] = "\n";
	  STATIC_ASSERT(sizeof newline == 2);

	  struct iovec iov[LBP__MAX+2];
	  uint iov_count = 0;
	  if (BIT32_TEST(&l->prepare, LBPP_TERMINAL))
	    iov[iov_count++] = (struct iovec) {
	      .iov_base = terminal_prefix,
	      .iov_len = sizeof terminal_prefix - 1,
	    };

	  for (uint p = 0; p < LBP__MAX; p++)
	    if (BIT32_TEST(&l->prepare, p))
	    {
	      off_t sz = buf->pos[p+1] - buf->pos[p];
	      if (sz > 0)
		iov[iov_count++] = (struct iovec) {
		  .iov_base = buf->pos[p],
		  .iov_len = sz,
		};
	    }

	  if (rf)
	  {
	    iov[iov_count++] = (struct iovec) {
	      .iov_base = newline,
	      .iov_len = sizeof newline - 1,
	    };

	    do {
	      if (rf_writev(rf, iov, iov_count))
		break;

	      log_lock();
	      rf = atomic_load_explicit(&l->rf, memory_order_acquire);
	      if (rf_writev(rf, iov, iov_count))
	      {
		log_unlock();
		break;
	      }

	      log_rotate(l);
	      log_unlock();

	      rf = atomic_load_explicit(&l->rf, memory_order_relaxed);
	    } while (!rf_writev(rf, iov, iov_count));
	  }
	  else if (sk)
	  {
	    while ((writev(sk->fd, iov, iov_count) < 0) && (errno == EINTR))
	      ;
	    /* FIXME: Silently ignoring write errors */
	  }
	}
#ifdef HAVE_SYSLOG_H
      else
      {
	syslog(syslog_priorities[buf->class], "%s", buf->pos[LBP_MSG]);
      }
#endif
    }
}

int buffer_vprint(buffer *buf, const char *fmt, va_list args);

void
log_prepare(log_buffer *buf, int class)
{
  buf->class = class;

  buf->buf.start = buf->buf.pos = buf->block;
  buf->buf.end = buf->block + sizeof buf->block;

  int lf = atomic_load_explicit(&logging_flags, memory_order_acquire);

  buf->pos[LBP_TIMESTAMP] = buf->buf.pos;
  if (BIT32_TEST(&lf, LBP_TIMESTAMP))
  {
    rcu_read_lock();
    const char *fmt = atomic_load_explicit(&global_runtime, memory_order_acquire)->tf_log.fmt1;
    int t = tm_format_real_time(buf->buf.pos, buf->buf.end - buf->buf.pos, fmt, current_real_time());
    rcu_read_unlock();
    if (t)
      buf->buf.pos += t;
    else
      buffer_puts(&buf->buf, "<time format error>");

    *(buf->buf.pos++) = ' ';
  }

  buf->pos[LBP_UDP_HEADER] = buf->buf.pos;
  if (BIT32_TEST(&lf, LBP_UDP_HEADER))
  {
    /* Legacy RFC 3164 format, but with us precision */
    buffer_print(&buf->buf, "<%d>", LOG_DAEMON | syslog_priorities[class]);

    const char *fmt = "%b %d %T.%6f";
    int t = tm_format_real_time(buf->buf.pos, buf->buf.end - buf->buf.pos, fmt, current_real_time());
    if (t)
      buf->buf.pos += t;
    else
      buffer_puts(&buf->buf, "<time format error>");

    rcu_read_lock();
    const char *hostname = atomic_load_explicit(&global_runtime, memory_order_acquire)->hostname ?: "<none>";
    buffer_print(&buf->buf, " %s %s: ", hostname, bird_name);
    rcu_read_unlock();
  }

  buf->pos[LBP_THREAD_ID] = buf->buf.pos;
  if (BIT32_TEST(&lf, LBP_THREAD_ID))
    buffer_print(&buf->buf, "[%04x] ", THIS_THREAD_ID);

  buf->pos[LBP_CLASS] = buf->buf.pos;
  if (BIT32_TEST(&lf, LBP_CLASS))
    buffer_print(&buf->buf, "<%s> ", class_names[class]);

  buf->pos[LBP_MSG] = buf->buf.pos;
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

      struct iovec i = {
	.iov_base = buf,
	.iov_len = s,
      };
      rf_writev(dbg_rf, &i, 1);
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
    rf_write_crude(dbg_rf, msg, strlen(msg));
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
	.mask = ~0,
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

    *lc = (struct log_channel) {
      .prepare = BIT32_ALL(LBP_MSG),
    };
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
    struct rfile *orf = atomic_load_explicit(&ol->rf, memory_order_relaxed);
    if (orf)
    {
      WALK_LIST(l, *logs)
	if (l->rf && rf_same(l->rf, orf))
	{
	  /* Merge the mask */
	  ol->new_mask |= l->mask;
	  total_mask |= l->mask;

	  /* Merge flags */
	  flags |= ol->prepare;

	  /* The filehandle is no longer needed */
	  if ((l->rf != &rf_stderr ) && (l->rf != dbg_rf))
	  {
	    log_lock();
	    rfree(l->rf);
	    log_unlock();
	  }

	  l->rf = NULL;
	  l->found_old = 1;
	}
    }
    else if (ol->udp_port)
    {
      WALK_LIST(l, *logs)
	if (
	    (l->udp_port == ol->udp_port) && (
	      (l->udp_host && !strcmp(l->udp_host, ol->udp_host)) ||
	      (ipa_nonzero(l->udp_ip) && (ipa_equal(l->udp_ip, ol->udp_ip)))
	      ))
	{
	  /* Merge the mask */
	  ol->new_mask |= l->mask;
	  total_mask |= l->mask;

	  /* Merge flags */
	  flags |= ol->prepare;

	  /* The socket just stays open */
	  l->found_old = 1;
	}
    }
    else
    {
      WALK_LIST(l, *logs)
	if (!l->filename && !l->rf && !l->udp_port)
	{
	  ol->new_mask |= l->mask;
	  total_mask |= l->mask;
	  l->found_old = 1;
	}
    }

    /* First only extend masks */
    atomic_fetch_or_explicit(&ol->mask, ol->new_mask, memory_order_acq_rel);
  }

  atomic_fetch_or_explicit(&logging_mask, total_mask, memory_order_acq_rel);

  /* Open new log channels */
  WALK_LIST(l, *logs)
  {
    if (l->found_old)
      continue;

    if (!l->rf && !l->udp_port)
      continue;

    /* Truly new log channel */
    log_lock();
    struct log_channel *lc = mb_alloc(log_pool, sizeof *lc);
    log_unlock();

    if (l->rf)
    {
      *lc = (struct log_channel) {
	.filename = l->filename,
	.backup = l->backup,
	.rf = l->rf,
	.limit = l->limit,
	.new_mask = l->mask,
	.prepare = BIT32_ALL(LBP_TIMESTAMP, LBP_THREAD_ID, LBP_CLASS, LBP_MSG) |
	  (l->terminal_flag ? BIT32_VAL(LBPP_TERMINAL) : 0),
      };

      /* Now the file handle ownership is transferred to the log channel */
      l->rf = NULL;

      /* Find more */
      for (struct log_config *ll = NODE_NEXT(l); NODE_VALID(ll); ll = NODE_NEXT(ll))
      {
	struct rfile *crf = atomic_load_explicit(&lc->rf, memory_order_relaxed);
	if (ll->filename && ll->rf && rf_same(crf, ll->rf))
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
      }
    }
    else if (l->udp_port)
    {
      sock *sk;

      ASSERT(l->udp_host || ipa_nonzero(l->udp_ip));

      *lc = (struct log_channel) {
	.new_mask = l->mask,
	.prepare = BIT32_ALL(LBP_UDP_HEADER, LBP_MSG),
	.udp_host = l->udp_host,
	.udp_port = l->udp_port,
	.udp_ip = l->udp_ip,
      };

      if (lc->udp_host && ipa_zero(lc->udp_ip))
      {
	const char *err_msg;
	lc->udp_ip = resolve_hostname(lc->udp_host, SK_UDP, &err_msg);

	if (ipa_zero(lc->udp_ip))
	{
	  cf_warn("Cannot resolve hostname '%s': %s", l->udp_host, err_msg);
	  goto resolve_fail;
	}
      }

      log_lock();
      sk = sk_new(log_pool);
      log_unlock();
      sk->type = SK_UDP;
      sk->daddr = lc->udp_ip;
      sk->dport = lc->udp_port;
      sk->flags = SKF_CONNECT;

      if (sk_open(sk, &main_birdloop) < 0)
      {
	cf_warn("Cannot open UDP log socket: %s%#m", sk->err);
	rfree(sk);
resolve_fail:
	log_lock();
	mb_free(lc);
	log_unlock();
	continue;
      }

      atomic_store_explicit(&lc->udp_sk, sk, memory_order_relaxed);

      /* Find more */
      for (struct log_config *ll = NODE_NEXT(l); NODE_VALID(ll); ll = NODE_NEXT(ll))
	if (
	    (l->udp_port == ll->udp_port) && (
	      (l->udp_host && !strcmp(l->udp_host, ll->udp_host)) ||
	      (ipa_nonzero(l->udp_ip) && (ipa_equal(l->udp_ip, ll->udp_ip)))
	      ))
	{
	  /* Merged with this channel */
	  lc->new_mask |= ll->mask;
	  total_mask |= ll->mask;

	  ll->found_old = 1;
	}
    }

    /* Mask union */
    total_mask |= l->mask;

    /* Store the new final local mask */
    atomic_store_explicit(&lc->mask, lc->new_mask, memory_order_release);

    /* Message preparation flags */
    flags |= lc->prepare;

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

    /* Never close syslog channel or debug */
    struct rfile *orf = atomic_load_explicit(&ol->rf, memory_order_relaxed);
    sock *ousk = atomic_load_explicit(&ol->udp_sk, memory_order_relaxed);
    if (ol->new_mask || (!orf && !ousk) || (orf == dbg_rf))
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

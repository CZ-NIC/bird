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
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "nest/bird.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "lib/lists.h"
#include "sysdep/unix/unix.h"

static struct rfile *dbg_rf;
static list *current_log_list;
static char *current_syslog_name; /* NULL -> syslog closed */

_Atomic uint max_thread_id = ATOMIC_VAR_INIT(1);
_Thread_local uint this_thread_id;

#include <pthread.h>

static pthread_mutex_t log_mutex;
static inline void log_lock(void) { pthread_mutex_lock(&log_mutex); }
static inline void log_unlock(void) { pthread_mutex_unlock(&log_mutex); }

/* Logging flags to validly prepare logging messages */
#define LOGGING_TO_TERMINAL   0x1
#define LOGGING_TO_FILE	      0x2

static _Atomic uint logging_flags;

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

static inline off_t
log_size(struct log_config *l)
{
  struct stat st;
  return (!fstat(rf_fileno(l->rf), &st) && S_ISREG(st.st_mode)) ? st.st_size : 0;
}

static void
log_close(struct log_config *l)
{
  if (l->rf != &rf_stderr)
    rfree(l->rf);

  l->rf = NULL;
}

static int
log_open(struct log_config *l)
{
  l->rf = rf_open(config->pool, l->filename, RF_APPEND);
  if (!l->rf)
  {
    /* Well, we cannot do much in case of error as log is closed */
    l->mask = 0;
    return -1;
  }

  l->pos = log_size(l);

  return 0;
}

static int
log_rotate(struct log_config *l)
{
  log_close(l);

  /* If we cannot rename the logfile, we at least try to delete it
     in order to continue logging and not exceeding logfile size */
  if ((rename(l->filename, l->backup) < 0) &&
      (unlink(l->filename) < 0))
  {
    l->mask = 0;
    return -1;
  }

  return log_open(l);
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
  struct log_config *l;

  if (buf->buf.pos == buf->buf.end)
#define TOO_LONG " ... <too long>"
    memcpy(buf->buf.end - sizeof TOO_LONG, TOO_LONG, sizeof TOO_LONG);
#undef TOO_LONG

  log_lock();
  WALK_LIST(l, *current_log_list)
    {
      if (!(l->mask & (1 << buf->class)))
	continue;
      if (l->rf && buf->tm_pos)
	{
	  *buf->buf.pos = '\n';
	  byte *begin = l->terminal_flag ? buf->buf.start : buf->tm_pos;
	  off_t msg_len = buf->buf.pos - begin + 1;
	  if (l->limit && (l->pos + msg_len > l->limit) && (log_rotate(l) < 0))
	    continue;

	  l->pos += msg_len;
	  while ((write(rf_fileno(l->rf), buf->tm_pos, msg_len) < 0) && (errno == EINTR))
	    ;
	}
#ifdef HAVE_SYSLOG_H
      else
      {
	*buf->buf.pos = '\0';
	syslog(syslog_priorities[buf->class], "%s", buf->msg_pos);
      }
#endif
    }
  log_unlock();

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

  buf->msg_pos = buf->buf.pos;
  buf->class = class;
}

static void
vlog(int class, const char *msg, va_list args)
{
  static _Thread_local log_buffer buf;

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

      write(rf_fileno(dbg_rf), buf, s);
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
    write(rf_fileno(dbg_rf), msg, strlen(msg));
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
  struct log_config *l;

  /* We should not manipulate with log list when other threads may use it */
  log_lock();

  if (!logs || EMPTY_LIST(*logs))
    logs = default_log_list(initial, &new_syslog_name);

  /* Close the logs to avoid pinning them on disk when deleted */
  if (current_log_list)
    WALK_LIST(l, *current_log_list)
      if (l->rf)
	log_close(l);

  /* Reopen the logs, needed for 'configure undo' */
  uint flags = 0;
  if (logs)
    WALK_LIST(l, *logs)
    {
      if (l->terminal_flag)
	flags |= LOGGING_TO_TERMINAL;
      if (l->filename && !l->rf)
	log_open(l);
      if (l->rf)
	flags |= LOGGING_TO_FILE;
    }

  atomic_store_explicit(&logging_flags, flags, memory_order_release);

  current_log_list = logs;

#ifdef HAVE_SYSLOG_H
  if (!bstrcmp(current_syslog_name, new_syslog_name))
    goto done;

  if (current_syslog_name)
  {
    closelog();
    xfree(current_syslog_name);
    current_syslog_name = NULL;
  }

  if (new_syslog_name)
  {
    current_syslog_name = xstrdup(new_syslog_name);
    openlog(current_syslog_name, LOG_CONS | LOG_NDELAY, LOG_DAEMON);
  }

#endif

done:
  /* Logs exchange done, let the threads log as before */
  log_unlock();
}

void
log_init_debug(char *f)
{
  clock_gettime(CLOCK_MONOTONIC, &dbg_time_start);

  if (dbg_rf && dbg_rf != &rf_stderr)
    close(rf_fileno(dbg_rf));

  if (!f)
    dbg_rf = NULL;
  else if (!*f)
    dbg_rf = &rf_stderr;
  else if (!(dbg_rf = rf_open(&root_pool, f, RF_APPEND)))
  {
    /* Cannot use die() nor log() here, logging is not yet initialized */
    fprintf(stderr, "bird: Unable to open debug file %s: %s\n", f, strerror(errno));
    exit(1);
  }
}

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

static FILE *dbgf;
static list *current_log_list;
static char *current_syslog_name; /* NULL -> syslog closed */


#ifdef USE_PTHREADS

#include <pthread.h>

static pthread_mutex_t log_mutex;
static inline void log_lock(void) { pthread_mutex_lock(&log_mutex); }
static inline void log_unlock(void) { pthread_mutex_unlock(&log_mutex); }

static pthread_t main_thread;
void main_thread_init(void) { main_thread = pthread_self(); }
static int main_thread_self(void) { return pthread_equal(pthread_self(), main_thread); }

#else

static inline void log_lock(void) {  }
static inline void log_unlock(void) {  }
void main_thread_init(void) { }
static int main_thread_self(void) { return 1; }

#endif


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
  rfree(l->rf);
  l->rf = NULL;
  l->fh = NULL;
}

static int
log_open(struct log_config *l)
{
  l->rf = rf_open(config->pool, l->filename, "a");
  if (!l->rf)
  {
    /* Well, we cannot do much in case of error as log is closed */
    l->mask = 0;
    return -1;
  }

  l->fh = rf_file(l->rf);
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
log_commit(int class, buffer *buf)
{
  struct log_config *l;

  if (buf->pos == buf->end)
    strcpy(buf->end - 100, " ... <too long>");

  log_lock();
  WALK_LIST(l, *current_log_list)
    {
      if (!(l->mask & (1 << class)))
	continue;
      if (l->fh)
	{
	  if (l->terminal_flag)
	    fputs("bird: ", l->fh);
	  else
	    {
	      byte tbuf[TM_DATETIME_BUFFER_SIZE];
	      const char *fmt = config ? config->tf_log.fmt1 : "%F %T.%3f";
	      if (!tm_format_real_time(tbuf, sizeof(tbuf), fmt, current_real_time()))
		strcpy(tbuf, "<error>");

	      if (l->limit)
	      {
		off_t msg_len = strlen(tbuf) + strlen(class_names[class]) +
		  (buf->pos - buf->start) + 5;

		if (l->pos < 0)
		  l->pos = log_size(l);

		if (l->pos + msg_len > l->limit)
		  if (log_rotate(l) < 0)
		    continue;

		l->pos += msg_len;
	      }

	      fprintf(l->fh, "%s <%s> ", tbuf, class_names[class]);
	    }
	  fputs(buf->start, l->fh);
	  fputc('\n', l->fh);
	  fflush(l->fh);
	}
#ifdef HAVE_SYSLOG_H
      else
	syslog(syslog_priorities[class], "%s", buf->start);
#endif
    }
  log_unlock();

  /* cli_echo is not thread-safe, so call it just from the main thread */
  if (main_thread_self())
    cli_echo(class, buf->start);

  buf->pos = buf->start;
}

int buffer_vprint(buffer *buf, const char *fmt, va_list args);

static void
vlog(int class, const char *msg, va_list args)
{
  buffer buf;
  LOG_BUFFER_INIT(buf);
  buffer_vprint(&buf, msg, args);
  log_commit(class, &buf);
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
#define MAX_DEBUG_BUFSIZE       65536
  va_list args;
  static uint bufsize = 4096;
  static char *buf = NULL;

  if (!buf)
    buf = mb_alloc(&root_pool, bufsize);

  va_start(args, msg);
  if (dbgf)
    {
      while (bvsnprintf(buf, bufsize, msg, args) < 0)
        if (bufsize >= MAX_DEBUG_BUFSIZE)
          bug("Extremely long debug output, split it.");
        else
          buf = mb_realloc(buf, (bufsize *= 2));

      fputs(buf, dbgf);
    }
  va_end(args);
}

static list *
default_log_list(int initial, char **syslog_name)
{
  static list log_list;
  init_list(&log_list);
  *syslog_name = NULL;

#ifdef HAVE_SYSLOG_H
  if (!dbgf)
    {
      static struct log_config lc_syslog = { .mask = ~0 };
      add_tail(&log_list, &lc_syslog.n);
      *syslog_name = bird_name;
    }
#endif

  if (dbgf && (dbgf != stderr))
    {
      static struct log_config lc_debug = { .mask = ~0 };
      lc_debug.fh = dbgf;
      add_tail(&log_list, &lc_debug.n);
    }

  if (initial || (dbgf == stderr))
    {
      static struct log_config lc_stderr = { .mask = ~0, .terminal_flag = 1};
      lc_stderr.fh = stderr;
      add_tail(&log_list, &lc_stderr.n);
    }

  return &log_list;
}

void
log_switch(int initial, list *logs, char *new_syslog_name)
{
  struct log_config *l;

  if (!logs || EMPTY_LIST(*logs))
    logs = default_log_list(initial, &new_syslog_name);

  /* We shouldn't close the logs when other threads may use them */
  log_lock();

  /* Close the logs to avoid pinning them on disk when deleted */
  if (current_log_list)
    WALK_LIST(l, *current_log_list)
      if (l->rf)
	log_close(l);

  /* Reopen the logs, needed for 'configure undo' */
  if (logs)
    WALK_LIST(l, *logs)
      if (l->filename && !l->rf)
	log_open(l);

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
  if (dbgf && dbgf != stderr)
    fclose(dbgf);
  if (!f)
    dbgf = NULL;
  else if (!*f)
    dbgf = stderr;
  else if (!(dbgf = fopen(f, "a")))
  {
    /* Cannot use die() nor log() here, logging is not yet initialized */
    fprintf(stderr, "bird: Unable to open debug file %s: %s\n", f, strerror(errno));
    exit(1);
  }
  if (dbgf)
    setvbuf(dbgf, NULL, _IONBF, 0);
}

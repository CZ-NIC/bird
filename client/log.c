/*
 *	BIRD Client Logging Stubs
 *
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int shutting_down;

void write_msg(va_list args, const char *msg, const char *type)
{
  char buf[4096];
  bvsnprintf(buf, sizeof buf, msg, args);
  fputs(type, stderr);
  fputs(": ", stderr);
  fputs(buf, stderr);
  fputc('\n', stderr);
}

void cf_error(const char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  write_msg(args, msg, "error");
  va_end(args);
  exit(1);
}

void log_msg(const char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  write_msg(args, msg, "info");
  va_end(args);
  exit(1);
}

void debug(const char *msg, ...)
{
  va_list args;
  va_start(args, msg);
  write_msg(args, msg, "debug");
  va_end(args);
  exit(1);
}

/* Ignore all events for now */
struct event;
void ev_schedule(struct event *e UNUSED) 
{ }

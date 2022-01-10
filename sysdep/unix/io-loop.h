/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_UNIX_IO_LOOP_H_
#define _BIRD_SYSDEP_UNIX_IO_LOOP_H_

#include "nest/bird.h"

#include "lib/lists.h"
#include "lib/event.h"
#include "lib/timer.h"

struct free_pages
{
  list list;		/* List of empty pages */
  event *cleanup;	/* Event to call when number of pages is outside bounds */
  u16 min, max;		/* Minimal and maximal number of free pages kept */
  uint cnt;		/* Number of empty pages */
};

struct birdloop
{
  resource r;

  pool *pool;
  pool *parent;

  struct timeloop time;
  event_list event_list;
  list sock_list;
  uint sock_num;

  BUFFER(sock *) poll_sk;
  BUFFER(struct pollfd) poll_fd;
  u8 poll_changed;

  _Atomic u32 ping_sent;
  int wakeup_fds[2];

  uint links;

  struct free_pages pages;

  void (*stopped)(void *data);
  void *stop_data;

  struct birdloop *prev_loop;
};

extern _Thread_local struct birdloop *birdloop_current;

void init_pages(struct birdloop *loop);
void flush_pages(struct birdloop *loop);

#endif

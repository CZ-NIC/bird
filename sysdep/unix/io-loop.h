/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_UNIX_IO_LOOP_H_
#define _BIRD_SYSDEP_UNIX_IO_LOOP_H_

#include "lib/rcu.h"

#include <pthread.h>

struct pipe
{
  int fd[2];
};

void pipe_new(struct pipe *);
void pipe_pollin(struct pipe *, struct pollfd *);
void pipe_drain(struct pipe *);
void pipe_kick(struct pipe *);

struct birdloop
{
  node n;

  pool *pool;

  struct timeloop time;
  event_list event_list;
  list sock_list;
  int sock_num;

  uint ping_pending;

  uint links;

  _Atomic u32 flags;
  struct birdloop_flag_handler *flag_handler;

  void (*stopped)(void *data);
  void *stop_data;

  struct birdloop *prev_loop;

  struct bird_thread *thread;
  struct pollfd *pfd;

  u64 total_time_spent_ns;
};

struct bird_thread
{
  node n;

  struct pollfd *pfd;
  uint pfd_max;

  _Atomic u32 ping_sent;
  _Atomic u32 run_cleanup;
  _Atomic u32 poll_changed;

  struct pipe wakeup;
  event_list priority_events;

  pthread_t thread_id;
  pthread_attr_t thread_attr;

  struct rcu_thread rcu;

  list loops;
  pool *pool;

  event cleanup_event;
};

#endif

/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_UNIX_IO_LOOP_H_
#define _BIRD_SYSDEP_UNIX_IO_LOOP_H_

#include "lib/rcu.h"

struct birdloop
{
  pool *pool;

  struct timeloop time;
  event_list event_list;
  list sock_list;
  uint sock_num;

  BUFFER(sock *) poll_sk;
  BUFFER(struct pollfd) poll_fd;
  u8 poll_changed;
  u8 close_scheduled;

  uint ping_pending;
  _Atomic u32 ping_sent;
  int wakeup_fds[2];

  pthread_t thread_id;
  pthread_attr_t thread_attr;

  struct rcu_birdloop rcu;

  uint links;

  _Atomic u32 flags;
  struct birdloop_flag_handler *flag_handler;

  void (*stopped)(void *data);
  void *stop_data;

  struct birdloop *prev_loop;
};

#endif

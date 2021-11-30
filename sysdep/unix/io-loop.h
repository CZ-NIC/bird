/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_UNIX_IO_LOOP_H_
#define _BIRD_SYSDEP_UNIX_IO_LOOP_H_

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
  u8 close_scheduled;

  _Atomic u32 ping_sent;
  int wakeup_fds[2];

  uint links;

  void (*stopped)(void *data);
  void *stop_data;

  struct birdloop *prev_loop;
};

#endif

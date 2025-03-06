/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SYSDEP_UNIX_IO_LOOP_H_
#define _BIRD_SYSDEP_UNIX_IO_LOOP_H_

#include "lib/rcu.h"
#include "lib/tlists.h"
#include <pthread.h>

struct pipe
{
  int fd[2];
};

struct pfd {
  BUFFER(struct pollfd) pfd;
  BUFFER(struct birdloop *) loop;
};

void sockets_prepare(struct birdloop *, struct pfd *);
void socket_changed(struct birdsock *);

void pipe_new(struct pipe *);
void pipe_pollin(struct pipe *, struct pfd *);
void pipe_drain(struct pipe *);
void pipe_kick(struct pipe *);

#define TIME_BY_SEC_SIZE	16

struct spent_time {
  u64 total_ns;
  u64 last_written_ns;
  u64 by_sec_ns[TIME_BY_SEC_SIZE];
};

struct birdloop
{
#define TLIST_PREFIX birdloop
#define TLIST_TYPE struct birdloop
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL
  TLIST_DEFAULT_NODE;

  event event;
  timer timer;

  pool *pool;

  struct timeloop time;
  event_list event_list;
  event_list defer_list;
  list sock_list;
  struct birdsock *sock_active;
  int sock_num;
  uint sock_changed:1;

  uint ping_pending;

  _Atomic u32 thread_transition;
#define LTT_PING  1
#define LTT_MOVE  2

  u64 last_transition_ns;

  void (*stopped)(void *data);
  void *stop_data;

  struct birdloop *prev_loop;

  struct bird_thread *thread;
  thread_group *thread_group;

#define TIME_BY_SEC_SIZE	16
  struct spent_time working, locking;
};
#include "lib/tlists.h"


typedef union thread_group_public thread_group;
struct bird_thread
{
#define TLIST_PREFIX thread
#define TLIST_TYPE struct bird_thread
#define TLIST_ITEM n
#define TLIST_WANT_WALK
#define TLIST_WANT_ADD_TAIL
  TLIST_DEFAULT_NODE;

  struct pipe wakeup;
  event_list priority_events;

  struct birdloop *meta;

  pthread_t thread_id;
  pthread_attr_t thread_attr;

  TLIST_LIST(birdloop) loops;
  thread_group *group;
  pool *pool;
  struct pfd *pfd;

  event cleanup_event;

  u8 sock_changed;
  u8 busy_active;
  u16 busy_counter;
  uint loop_count;

  struct thread_params params;
  u64 max_loop_time_ns;

  struct spent_time overhead, idle;
};
#include "lib/tlists.h"

extern _Thread_local struct bird_thread *this_thread;

struct bird_thread_syncer {
  pool *pool;
  DOMAIN(control) lock;
  uint total;
  uint done;
  void (*hook)(struct bird_thread_syncer *);	/* Runs in worker threads */
  void (*finish)(struct bird_thread_syncer *);	/* Runs in main thread last */
};

void bird_thread_sync_all(struct bird_thread_syncer *sync,
    void (*hook)(struct bird_thread_syncer *),
    void (*done)(struct bird_thread_syncer *), const char *name);

struct birdloop_pickup_group {
  DOMAIN(attrs) domain;
  list loops;
  list threads;
  uint thread_count;
  uint thread_busy_count;
  uint loop_count;
  uint loop_unassigned_count;
  btime max_latency;
  event start_threads;
};

extern struct birdloop_pickup_group pickup_groups[2];

#endif

/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IO_LOOP_H_
#define _BIRD_IO_LOOP_H_

extern struct birdloop main_birdloop;

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/locking.h"
#include "lib/resource.h"
#include "lib/buffer.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "lib/socket.h"

/* Currently running birdloop */
extern _Thread_local struct birdloop *this_birdloop;

/* Lowest entered birdloop */
extern _Thread_local struct birdloop *birdloop_current;

/* Check that the task has enough time to do a bit more */
bool task_still_in_limit(void);
bool task_before_halftime(void);

#define MAYBE_DEFER_TASK(target, event, fmt, args...) do { \
  if (!task_still_in_limit()) { \
    if (atomic_load_explicit(&global_runtime, memory_order_relaxed)->latency_debug & DL_SCHEDULING) \
      log(L_TRACE "Deferring " fmt, ##args); \
    return ev_send(target, event); \
  } } while (0)

/* Start a new birdloop owned by given pool and domain */
struct birdloop *birdloop_new(pool *p, uint order, btime max_latency, const char *fmt, ...);

/* Stop the loop. At the end, the @stopped callback is called unlocked in tail
 * position to finish cleanup. Run birdloop_free() from that callback to free
 * the loop itself. */
void birdloop_stop(struct birdloop *loop, void (*stopped)(void *data), void *data);
void birdloop_stop_self(struct birdloop *loop, void (*stopped)(void *data), void *data);
void birdloop_free(struct birdloop *loop);

/* Run this event in the running loop's priority event list to run asap */
void ev_send_defer(event *e);

/* Get birdloop's time heap */
struct timeloop *birdloop_time_loop(struct birdloop *loop);
#define birdloop_domain(l)  (birdloop_time_loop((l))->domain)

/* Get birdloop's pool */
pool *birdloop_pool(struct birdloop *loop);

/* Enter and exit the birdloop */
void birdloop_enter(struct birdloop *loop);
void birdloop_leave(struct birdloop *loop);

bool birdloop_inside(struct birdloop *loop);

void birdloop_mask_wakeups(struct birdloop *loop);
void birdloop_unmask_wakeups(struct birdloop *loop);

void birdloop_link(struct birdloop *loop);
void birdloop_unlink(struct birdloop *loop);

void birdloop_ping(struct birdloop *loop);

/* Setup sockets */
void birdloop_add_socket(struct birdloop *, struct birdsock *);
void birdloop_remove_socket(struct birdloop *, struct birdsock *);

void birdloop_init(void);

#endif /* _BIRD_IO_LOOP_H_ */

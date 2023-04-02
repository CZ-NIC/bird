/*
 *	BIRD -- I/O and event loop
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IO_LOOP_H_
#define _BIRD_IO_LOOP_H_

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/locking.h"
#include "lib/resource.h"
#include "lib/event.h"
#include "lib/socket.h"

extern struct birdloop main_birdloop;

/* Start a new birdloop owned by given pool and domain */
struct birdloop *birdloop_new(pool *p, uint order, const char *name);

/* Stop the loop. At the end, the @stopped callback is called unlocked in tail
 * position to finish cleanup. Run birdloop_free() from that callback to free
 * the loop itself. */
void birdloop_stop(struct birdloop *loop, void (*stopped)(void *data), void *data);
void birdloop_stop_self(struct birdloop *loop, void (*stopped)(void *data), void *data);
void birdloop_free(struct birdloop *loop);

/* Get birdloop's event list */
event_list *birdloop_event_list(struct birdloop *loop);

/* Get birdloop's time heap */
struct timeloop *birdloop_time_loop(struct birdloop *loop);

/* Enter and exit the birdloop */
void birdloop_enter(struct birdloop *loop);
void birdloop_leave(struct birdloop *loop);

_Bool birdloop_inside(struct birdloop *loop);

void birdloop_mask_wakeups(struct birdloop *loop);
void birdloop_unmask_wakeups(struct birdloop *loop);

void birdloop_link(struct birdloop *loop);
void birdloop_unlink(struct birdloop *loop);

void birdloop_ping(struct birdloop *loop);

struct birdloop_flag_handler {
  void (*hook)(struct birdloop_flag_handler *, u32 flags);
  void *data;
};

void birdloop_flag(struct birdloop *loop, u32 flag);
void birdloop_flag_set_handler(struct birdloop *, struct birdloop_flag_handler *);

/* Setup sockets */
void birdloop_add_socket(struct birdloop *, struct birdsock *);
void birdloop_remove_socket(struct birdloop *, struct birdsock *);

void birdloop_init(void);

/* Yield for a little while. Use only in special cases. */
void birdloop_yield(void);

#endif /* _BIRD_IO_LOOP_H_ */

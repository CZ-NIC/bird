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
typedef union thread_group_public thread_group;
struct birdloop *birdloop_new(pool *p, uint order, thread_group *tg, const char *fmt, ...);

/* Transfer the loop to a different thread group */
void birdloop_transfer(struct birdloop *, thread_group *from, thread_group *to);

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

/* Enter the birdloop, leave at the end of the block. */
#define BIRDLOOP_ENTER(_loop) CLEANUP(birdloop_leave_cleanup) UNUSED struct birdloop *_loop_entered = (birdloop_enter(_loop), (_loop))

/* Prematurely leave the birdloop */
#define BIRDLOOP_LEAVE(_loop) (birdloop_leave_cleanup(&_loop), _loop = NULL);

/* Auxiliary cleanup function for BIRDLOOP_ENTER */
void birdloop_leave_cleanup(struct birdloop **);

/* Structures similar to LOBJ_*, see lib/locking.h */
#define BLO_UNLOCK_CLEANUP_NAME(_stem) _blo__##_stem##_unlock_cleanup
#define BLO_UNLOCK_CLEANUP(_stem) \
  static inline void BLO_UNLOCK_CLEANUP_NAME(_stem)(struct _stem##_private **obj) { \
    if (!*obj) return; \
    ASSERT_DIE(birdloop_inside((*obj)->loop)); \
    ASSERT_DIE((*obj)->locked_at == obj); \
    (*obj)->locked_at = NULL; \
    birdloop_leave((*obj)->loop); \
  }

#define BLO_LOCK(_obj, _pobj, _stem) \
  CLEANUP(BLO_UNLOCK_CLEANUP_NAME(_stem)) struct _stem##_private *_pobj = &(_obj)->priv; birdloop_enter(_pobj->loop); _pobj->locked_at = &_pobj;

#define BLO_LOCKED(_obj, _pobj, _stem) \
  for (CLEANUP(BLO_UNLOCK_CLEANUP_NAME(_stem)) struct _stem##_private *_pobj = &(_obj)->priv; \
      _pobj ? (birdloop_enter(_pobj->loop), _pobj->locked_at = &_pobj) : NULL; \
      BLO_UNLOCK_CLEANUP_NAME(_stem)(&_pobj), _pobj = NULL)

/* Explicitly enter and exit the birdloop */
void birdloop_enter(struct birdloop *loop);
void birdloop_leave(struct birdloop *loop);

/* Check whether we are actually inside a birdloop */
bool birdloop_inside(struct birdloop *loop);

/* Internal API, do not call */
void birdloop_mask_wakeups(struct birdloop *loop);
void birdloop_unmask_wakeups(struct birdloop *loop);

void birdloop_link(struct birdloop *loop);
void birdloop_unlink(struct birdloop *loop);

void birdloop_ping(struct birdloop *loop);

/* Setup sockets */
void birdloop_add_socket(struct birdloop *, struct birdsock *);
void birdloop_remove_socket(struct birdloop *, struct birdsock *);

void birdloop_init(void);

/* Configure threads */
struct thread_group_config {
#define TLIST_PREFIX thread_group_config
#define TLIST_TYPE struct thread_group_config
#define TLIST_ITEM n
#define TLIST_WANT_ADD_TAIL
#define TLIST_WANT_WALK
  TLIST_DEFAULT_NODE;
  thread_group *group;
  struct symbol *symbol;
  struct thread_params {
    btime max_time;
    btime min_time;
    btime max_latency;
    btime wakeup_time;
  } params;
  uint thread_count;
};
#include "lib/tlists.h"

extern const struct thread_group_config thread_group_config_default_worker, thread_group_config_default_express;

void thread_group_finalize_config(void);

#endif /* _BIRD_IO_LOOP_H_ */

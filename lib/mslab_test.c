/*
 *	BIRD Library -- Multithreaded mslab Alloc / Dealloc Tests
 *
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "lib/resource.h"
#include "lib/bitops.h"
#include "lib/event.h"
#include "lib/io-loop.h"
#include "lib/rcu.h"
#include "lib/timer.h"
#include "sysdep/unix/io-loop.h"

#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/*
 * The concurrent tests need to stop a thread at an exact place inside
 * the allocator, e.g. between loading a pointer and the CAS using it.
 * To get there without touching lib/mslab.c, we compile a private copy
 * of it right here, with the public symbols renamed (lib/mslab.o is linked
 * into this binary as well), and with a few calls redirected to hooks:
 *
 *   ASSERT_DIE()	runs after its argument is evaluated, so the asserts
 *			at the right places serve as injection points
 *   rcu_begin_sync()	cleanup has taken its RCU phase
 *   rcu_end_sync()	cleanup is waiting for an RCU reader
 *   synchronize_rcu()	cleanup or thread end is about to wait for readers
 *   alloc_page(), free_page()	track which pages are live
 *
 * Every hook point has a gate. An armed gate stops (or just notes) one
 * selected thread when it passes the point. All the headers lib/mslab.c needs
 * are included above, so the redirections below affect only lib/mslab.c.
 */

/* Rename the public mslab API of the private copy */
#define msl_new		mslt_new
#define msl_delete	mslt_delete
#define msl_alloc	mslt_alloc
#define msl_allocz	mslt_allocz
#define msl_free	mslt_free

mslab *msl_new(pool *p, struct event_list *cleanup_ev_list, uint size);
void *msl_alloc(mslab *);
void *msl_allocz(mslab *);
void msl_free(void *);
void msl_delete(mslab *);

enum mslt_point {
  MP_PICK,		/* msl_get_partial_head(): next pointer loaded, CAS pending */
  MP_FREE,		/* msl_free(): bit cleared in head, num_full not yet decremented */
  MP_CLEANUP,		/* msl_cleanup(): RCU phase taken, full heads walk pending */
  MP_ENDSYNC,		/* msl_cleanup(): rcu_end_sync() found an active older reader */
  MP_SYNC,		/* synchronize_rcu() called from lib/mslab.c */
  MP__MAX,
};

static const char * const mslt_point_name[MP__MAX] = {
  [MP_PICK] = "msl_get_partial_head() before CAS",
  [MP_FREE] = "msl_free() between bitfield and num_full update",
  [MP_CLEANUP] = "msl_cleanup() after rcu_begin_sync()",
  [MP_ENDSYNC] = "msl_cleanup() waiting in rcu_end_sync()",
  [MP_SYNC] = "synchronize_rcu() in lib/mslab.c",
};

struct mslt_gate {
  _Atomic uint thread;	/* Thread ID + 1 which should stop here, 0 if not armed */
  _Atomic bool hold;	/* Stop the thread until released; otherwise just note the passage */
  _Atomic bool reached;	/* The thread has passed the point */
  _Atomic bool release;	/* The thread may continue */
};

static struct mslt_gate mslt_gates[MP__MAX];

/* Random delays at hook points to widen race windows in the stress test */
static _Atomic bool mslt_jitter;
static _Thread_local u64 mslt_rnd_state;

static u64
mslt_rnd(void)
{
  /* xorshift64, seeded lazily per thread */
  if (!mslt_rnd_state)
    mslt_rnd_state = 0x9e3779b97f4a7c15ULL * (THIS_THREAD_ID + 1) ^ (uintptr_t) &mslt_rnd_state;

  mslt_rnd_state ^= mslt_rnd_state << 13;
  mslt_rnd_state ^= mslt_rnd_state >> 7;
  mslt_rnd_state ^= mslt_rnd_state << 17;
  return mslt_rnd_state;
}

static void
mslt_point(enum mslt_point p)
{
  if (atomic_load_explicit(&mslt_jitter, memory_order_relaxed))
  {
    u64 r = mslt_rnd();
    if (!(r & 7))
      usleep((r >> 8) % 200);
  }

  struct mslt_gate *g = &mslt_gates[p];
  uint me = THIS_THREAD_ID + 1;

  /* One-shot: disarm when the selected thread passes */
  if (!atomic_compare_exchange_strong_explicit(&g->thread, &me, 0,
	memory_order_acq_rel, memory_order_acquire))
    return;

  atomic_store_explicit(&g->reached, 1, memory_order_release);

  if (atomic_load_explicit(&g->hold, memory_order_acquire))
    while (!atomic_load_explicit(&g->release, memory_order_acquire))
      usleep(10);
}

static void
mslt_assert(bool ok, const char *expr, const char *file, int line)
{
  /* The asserts below sit exactly where we need the injection points */
  if (!strcmp(expr, "new_partial != NULL"))
    mslt_point(MP_PICK);
  else if (!strcmp(expr, "check & (1U << (pos % 32))"))
    mslt_point(MP_FREE);

  if (!ok)
    bug("Assertion '%s' failed at %s:%d", expr, file, line);
}

static UNUSED struct rcu_stored_phase
mslt_begin_sync(void)
{
  struct rcu_stored_phase phase = rcu_begin_sync();
  mslt_point(MP_CLEANUP);
  return phase;
}

static UNUSED bool
mslt_end_sync(struct rcu_stored_phase phase)
{
  bool done = rcu_end_sync(phase);
  if (!done)
    mslt_point(MP_ENDSYNC);
  return done;
}

static void
mslt_synchronize(void)
{
  mslt_point(MP_SYNC);
  synchronize_rcu();
}

/* Page tracking; detects use of freed heads and double frees */
#define MSLT_PAGES	4096
static void *mslt_live[MSLT_PAGES];
static uint mslt_live_cnt;
static bool mslt_live_overflow;
static pthread_mutex_t mslt_live_lock = PTHREAD_MUTEX_INITIALIZER;

static void *
mslt_alloc_page(void)
{
  void *p = alloc_page();

  pthread_mutex_lock(&mslt_live_lock);
  if (mslt_live_cnt < MSLT_PAGES)
    mslt_live[mslt_live_cnt++] = p;
  else
    mslt_live_overflow = 1;
  pthread_mutex_unlock(&mslt_live_lock);

  return p;
}

static void
mslt_free_page(void *p)
{
  bool found = 0;

  pthread_mutex_lock(&mslt_live_lock);
  for (uint i = 0; i < mslt_live_cnt; i++)
    if (mslt_live[i] == p)
    {
      mslt_live[i] = mslt_live[--mslt_live_cnt];
      found = 1;
      break;
    }
  bool overflow = mslt_live_overflow;
  pthread_mutex_unlock(&mslt_live_lock);

  if (!found && !overflow)
    bug("mslab freed page %p which is not allocated", p);

  free_page(p);
}

static bool
mslt_page_live(void *p)
{
  bool found = 0;

  pthread_mutex_lock(&mslt_live_lock);
  for (uint i = 0; i < mslt_live_cnt; i++)
    if (mslt_live[i] == p)
    {
      found = 1;
      break;
    }
  pthread_mutex_unlock(&mslt_live_lock);

  return found;
}

/* Compile the instrumented private copy */
#undef ASSERT_DIE
#define ASSERT_DIE(x)		mslt_assert(!!(x), #x, __FILE__, __LINE__)
#define rcu_begin_sync()	mslt_begin_sync()
#define rcu_end_sync(p)		mslt_end_sync(p)
#define synchronize_rcu()	mslt_synchronize()
#define alloc_page()		mslt_alloc_page()
#define free_page(p)		mslt_free_page(p)

#include "lib/mslab.c"

#undef ASSERT_DIE
#define ASSERT_DIE(x) do { if (!(x)) bug("Assertion '%s' failed at %s:%d", #x, __FILE__, __LINE__); } while(0)
#undef rcu_begin_sync
#undef rcu_end_sync
#undef synchronize_rcu
#undef alloc_page
#undef free_page


/*
 * Gate control
 */

static void
mslt_reset_gates(void)
{
  for (uint i = 0; i < MP__MAX; i++)
  {
    atomic_store(&mslt_gates[i].thread, 0);
    atomic_store(&mslt_gates[i].hold, 0);
    atomic_store(&mslt_gates[i].reached, 0);
    atomic_store(&mslt_gates[i].release, 0);
  }
  atomic_store(&mslt_jitter, 0);
}

static void
mslt_arm(enum mslt_point p, uint thread, bool hold)
{
  struct mslt_gate *g = &mslt_gates[p];
  atomic_store(&g->hold, hold);
  atomic_store(&g->reached, 0);
  atomic_store(&g->release, 0);
  atomic_store(&g->thread, thread + 1);
}

static void
mslt_release(enum mslt_point p)
{
  atomic_store(&mslt_gates[p].thread, 0);
  atomic_store(&mslt_gates[p].release, 1);
}


/*
 * Worker threads. Every worker poses as a BIRD thread with a fixed ID,
 * so it has its own per-thread mslab info; it is created in advance by
 * mslt_prepare() because the worker has no thread pool to allocate from.
 *
 * Workers are persistent and execute commands one by one. They can't just end
 * after every step because rcu_thread_stop() waits for RCU readers, and some
 * scenarios keep a reader stopped inside its critical section for a long time.
 */

#define ID_W1		201	/* Fills heads during setup */
#define ID_T1		202	/* The thread which gets stuck while picking a head */
#define ID_T2		203	/* The thread which wins the race */
#define ID_F		204	/* Frees blocks */
#define ID_C		250	/* Runs the cleanup */
#define ID_STRESS	210	/* Stress test workers, ID_STRESS + i */

struct mslt_worker {
  pthread_t thread;
  uint id;
  bool running;
  _Atomic bool quit;

  /* Current command */
  void (* _Atomic fn)(struct mslt_worker *);
  mslab *s;
  void **blocks;
  uint cnt;
  _Atomic bool done;
};

static struct mslt_worker mslt_workers[MAX_THREADS];

static void *
mslt_worker_main(void *data)
{
  struct mslt_worker *w = data;

  this_thread_id = w->id;
  rcu_thread_start();

  while (!atomic_load_explicit(&w->quit, memory_order_acquire))
  {
    void (*fn)(struct mslt_worker *) = atomic_load_explicit(&w->fn, memory_order_acquire);
    if (!fn)
    {
      usleep(10);
      continue;
    }

    fn(w);

    atomic_store_explicit(&w->fn, NULL, memory_order_relaxed);
    atomic_store_explicit(&w->done, 1, memory_order_release);
  }

  flush_local_pages();
  rcu_thread_stop();
  return NULL;
}

/* Wait for the command to finish */
static void
mslt_join(struct mslt_worker *w)
{
  while (!atomic_load_explicit(&w->done, memory_order_acquire))
    usleep(10);
}

/* Give a command to the worker with the given ID, starting it if needed */
static struct mslt_worker *
mslt_start(uint id, mslab *s, void (*fn)(struct mslt_worker *), void **blocks, uint cnt)
{
  struct mslt_worker *w = &mslt_workers[id];

  if (!w->running)
  {
    w->id = id;
    w->running = 1;
    atomic_store(&w->quit, 0);
    atomic_store(&w->fn, NULL);
    atomic_store(&w->done, 1);

    if (pthread_create(&w->thread, NULL, mslt_worker_main, w))
      bug("pthread_create failed");
  }

  /* Previous command must be finished */
  mslt_join(w);

  w->s = s;
  w->blocks = blocks;
  w->cnt = cnt;
  atomic_store_explicit(&w->done, 0, memory_order_relaxed);
  atomic_store_explicit(&w->fn, fn, memory_order_release);

  return w;
}

static void
mslt_run(uint id, mslab *s, void (*fn)(struct mslt_worker *), void **blocks, uint cnt)
{
  mslt_join(mslt_start(id, s, fn, blocks, cnt));
}

/* Release all gates, finish all commands and end all workers */
static void
mslt_stop_all(void)
{
  for (uint p = 0; p < MP__MAX; p++)
    mslt_release(p);

  for (uint i = 0; i < MAX_THREADS; i++)
  {
    struct mslt_worker *w = &mslt_workers[i];
    if (!w->running)
      continue;

    mslt_join(w);
    atomic_store_explicit(&w->quit, 1, memory_order_release);
    pthread_join(w->thread, NULL);
    w->running = 0;
  }
}

#define MPB(p)	(1U << (p))

static bool
mslt_reached(uint mask)
{
  for (uint p = 0; p < MP__MAX; p++)
    if ((mask & MPB(p)) && atomic_load_explicit(&mslt_gates[p].reached, memory_order_acquire))
      return 1;

  return 0;
}

/* Wait until any of the gates in mask is passed, the command ends, or a timeout expires */
static bool
mslt_wait(uint mask, struct mslt_worker *w, uint timeout_ms)
{
  for (uint i = 0; i < timeout_ms * 10; i++)
  {
    if (mslt_reached(mask))
      return 1;

    if (w && atomic_load_explicit(&w->done, memory_order_acquire))
      return mslt_reached(mask);

    usleep(100);
  }

  return 0;
}

static void
mslt_prepare(mslab *s, uint id)
{
  uint saved = this_thread_id;
  this_thread_id = id;
  msl_get_pti(s);
  this_thread_id = saved;
}

static void
mslt_do_alloc(struct mslt_worker *w)
{
  for (uint i = 0; i < w->cnt; i++)
    w->blocks[i] = msl_alloc(w->s);
}

static void
mslt_do_free(struct mslt_worker *w)
{
  for (uint i = 0; i < w->cnt; i++)
    if (w->blocks[i])
    {
      msl_free(w->blocks[i]);
      w->blocks[i] = NULL;
    }
}

static void
mslt_do_cleanup(struct mslt_worker *w)
{
  msl_cleanup(w->s);
}

static void
mslt_do_thread_end(struct mslt_worker *w)
{
  msl_thread_end(&w->s->thread_end);
}


/* Every scenario ends all its workers, also on early return */
#define MSLT_SCENARIO(name) \
  static int name##_body(void); \
  static int name(void) { int r = name##_body(); mslt_stop_all(); return r; } \
  static int name##_body(void)

/*
 * Helpers for the scenarios
 */

#define MSLT_SIZE	1000	/* A few objects per page, heads fill up quickly */

static mslab *
mslt_new_slab(uint size)
{
  mslab *s = msl_new(&root_pool, birdloop_event_list(&main_birdloop), size);

  /* We run the cleanup explicitly */
  ev_postpone(&s->event_clean);

  const uint ids[] = { ID_W1, ID_T1, ID_T2, ID_F, ID_C };
  for (uint i = 0; i < ARRAY_SIZE(ids); i++)
    mslt_prepare(s, ids[i]);

  return s;
}

static void
mslt_free_blocks(void **b, uint cnt)
{
  for (uint i = 0; i < cnt; i++)
    if (b[i])
    {
      msl_free(b[i]);
      b[i] = NULL;
    }
}

/* Check that full_heads and partial_heads contain only live heads in the right state */
static bool
mslt_check_lists(mslab *s)
{
  uint limit = MSLT_PAGES;

  for (msl_head *h = atomic_load(&s->full_heads); h != &slh_dummy_last_full; h = atomic_load(&h->next))
  {
    if (!limit--)
    {
      bt_assert_msg(0, "full_heads list is looped");
      return 0;
    }

    if (!mslt_page_live(h))
    {
      bt_assert_msg(0, "full_heads contains freed page %p", h);
      return 0;
    }

    if ((h->mslab != s) || (MSL_GET_STATE(h) != slh_full))
    {
      bt_assert_msg(0, "full_heads contains head %p in state %d", h, MSL_GET_STATE(h));
      return 0;
    }
  }

  limit = MSLT_PAGES;
  for (msl_head *h = atomic_load(&s->partial_heads); h != &slh_dummy_last_partial; h = atomic_load(&h->next))
  {
    if (!limit--)
    {
      bt_assert_msg(0, "partial_heads list is looped");
      return 0;
    }

    if (!mslt_page_live(h))
    {
      bt_assert_msg(0, "partial_heads contains freed page %p", h);
      return 0;
    }

    if ((h->mslab != s) || (MSL_GET_STATE(h) != slh_partial))
    {
      bt_assert_msg(0, "partial_heads contains head %p in state %d", h, MSL_GET_STATE(h));
      return 0;
    }

    if (atomic_load(&h->num_full) >= s->objs_per_slab)
    {
      bt_assert_msg(0, "partial_heads contains full head %p", h);
      return 0;
    }
  }

  return 1;
}

/* Run the cleanup as long as it is scheduled, like the event loop would do */
static void
mslt_settle(mslab *s)
{
  for (uint i = 0; ev_active(&s->event_clean) && (i < 16); i++)
  {
    ev_postpone(&s->event_clean);
    msl_cleanup(s);
  }
}

/*
 * Common setup: two partially used heads in partial_heads.
 *
 *   partial_heads = H1 -> H2
 *   H1: blocks b[1] .. b[objs-1] allocated, b[0] free
 *   H2: blocks b[objs+1] .. b[2*objs-1] allocated, b[objs] free
 *   H3: W1's head, block b[2*objs] allocated
 */
struct mslt_setup {
  mslab *s;
  uint objs;
  void **b;
  msl_head *h1, *h2, *h3;
};

static bool
mslt_setup_partials(struct mslt_setup *st)
{
  mslab *s = st->s;
  uint objs = st->objs = s->objs_per_slab;

  if (objs < 3)
  {
    bt_assert_msg(0, "Too few objects per page (%u) for this test", objs);
    return 0;
  }

  /* W1 fills two heads and starts a third one */
  mslt_run(ID_W1, s, mslt_do_alloc, st->b, 2 * objs + 1);

  st->h1 = MSL_GET_HEAD(st->b[0]);
  st->h2 = MSL_GET_HEAD(st->b[objs]);
  st->h3 = MSL_GET_HEAD(st->b[2 * objs]);

  for (uint i = 0; i < objs; i++)
  {
    bt_assert(MSL_GET_HEAD(st->b[i]) == st->h1);
    bt_assert(MSL_GET_HEAD(st->b[objs + i]) == st->h2);
  }

  bt_assert(atomic_load(&s->full_heads) == st->h2);
  bt_assert(atomic_load(&st->h2->next) == st->h1);
  bt_assert(atomic_load(&st->h1->next) == &slh_dummy_last_full);

  /* Free one block from each and move them to partial_heads */
  msl_free(st->b[0]);
  st->b[0] = NULL;
  msl_free(st->b[objs]);
  st->b[objs] = NULL;

  msl_cleanup(s);

  bt_assert(atomic_load(&s->full_heads) == &slh_dummy_last_full);
  bt_assert(atomic_load(&s->partial_heads) == st->h1);
  bt_assert(atomic_load(&st->h1->next) == st->h2);
  bt_assert(atomic_load(&st->h2->next) == &slh_dummy_last_partial);

  return bt_suite_result;
}


/*
 * Scenario: the race fixed by "Lib: Fix race condition in mslab".
 *
 * T1 loads H1 from partial_heads and stops before its CAS. T2 takes H1, fills
 * it and pushes it to full_heads. All blocks of H1 get freed and the cleanup
 * finds H1 empty in full_heads. The cleanup must not free H1 before T1
 * leaves its RCU critical section.
 */
MSLT_SCENARIO(t_pick_vs_cleanup)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  uint objs = s->objs_per_slab;
  void *b[2 * objs + 1], *t1b[1] = {}, *t2b[2] = {};
  struct mslt_setup st = { .s = s, .b = b };

  if (!mslt_setup_partials(&st))
    return 0;

  /* T1 gets stuck in msl_get_partial_head() holding H1 */
  struct mslt_worker *t1, *c;
  mslt_arm(MP_PICK, ID_T1, 1);
  t1 = mslt_start(ID_T1, s, mslt_do_alloc, t1b, 1);
  if (!mslt_wait(MPB(MP_PICK), t1, 5000))
    bug("T1 did not reach %s", mslt_point_name[MP_PICK]);

  /* T2 takes H1, fills it, pushes it to full_heads and takes H2 */
  mslt_run(ID_T2, s, mslt_do_alloc, t2b, 2);
  bt_assert(MSL_GET_HEAD(t2b[0]) == st.h1);
  bt_assert(MSL_GET_HEAD(t2b[1]) == st.h2);
  bt_assert(atomic_load(&s->full_heads) == st.h1);

  /* Everything in H1 is freed */
  mslt_free_blocks(&b[1], objs - 1);
  mslt_free_blocks(&t2b[0], 1);
  bt_assert(atomic_load(&st.h1->num_full) == 0);

  /* The cleanup finds H1 empty and has to wait for T1 */
  mslt_arm(MP_ENDSYNC, ID_C, 0);
  mslt_arm(MP_SYNC, ID_C, 0);
  c = mslt_start(ID_C, s, mslt_do_cleanup, NULL, 0);
  bt_assert_msg(mslt_wait(MPB(MP_ENDSYNC) | MPB(MP_SYNC), c, 5000), "Cleanup did not wait for T1");
  bt_assert_msg(mslt_page_live(st.h1), "Cleanup freed H1 while T1 still holds it");

  /* Let T1 finish; its CAS must fail */
  mslt_release(MP_PICK);
  mslt_join(t1);
  mslt_join(c);
  bt_assert(MSL_GET_HEAD(t1b[0]) != st.h1);

  if (!mslt_check_lists(s))
    return 0;

  mslt_free_blocks(b, 2 * objs + 1);
  mslt_free_blocks(t1b, 1);
  mslt_free_blocks(t2b, 2);
  rfree(s);

  return 1;
}

/*
 * Scenario: the same race, but the head is freed by msl_thread_end().
 *
 * T2 takes H1, all blocks in H1 get freed, and then T2 ends. The thread end
 * finds H1 empty and must not free it before T1 leaves its RCU critical section.
 */
MSLT_SCENARIO(t_pick_vs_thread_end)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  uint objs = s->objs_per_slab;
  void *b[2 * objs + 1], *t1b[1] = {}, *t2b[1] = {};
  struct mslt_setup st = { .s = s, .b = b };

  if (!mslt_setup_partials(&st))
    return 0;

  /* T1 gets stuck in msl_get_partial_head() holding H1 */
  struct mslt_worker *t1, *t2;
  mslt_arm(MP_PICK, ID_T1, 1);
  t1 = mslt_start(ID_T1, s, mslt_do_alloc, t1b, 1);
  if (!mslt_wait(MPB(MP_PICK), t1, 5000))
    bug("T1 did not reach %s", mslt_point_name[MP_PICK]);

  /* T2 takes H1 and allocates its last free block */
  mslt_run(ID_T2, s, mslt_do_alloc, t2b, 1);
  bt_assert(MSL_GET_HEAD(t2b[0]) == st.h1);

  /* Everything in H1 is freed */
  mslt_free_blocks(&b[1], objs - 1);
  mslt_free_blocks(t2b, 1);

  /* T2 ends with an empty head */
  mslt_arm(MP_SYNC, ID_T2, 0);
  t2 = mslt_start(ID_T2, s, mslt_do_thread_end, NULL, 0);
  mslt_wait(MPB(MP_SYNC), t2, 1000);
  bt_assert_msg(mslt_page_live(st.h1), "Thread end freed H1 while T1 still holds it");

  mslt_release(MP_PICK);
  mslt_join(t1);
  mslt_join(t2);
  bt_assert(!mslt_page_live(st.h1));

  if (!mslt_check_lists(s))
    return 0;

  mslt_free_blocks(b, 2 * objs + 1);
  mslt_free_blocks(t1b, 1);
  rfree(s);

  return 1;
}

/*
 * Scenario: a head picker locking RCU after the cleanup took its phase.
 *
 * The cleanup takes its RCU phase before walking full_heads and waits only
 * for readers older than that. T1 locks RCU later, loads H1 and stops.
 * Meanwhile, H1 travels to full_heads, the cleanup moves it back to the top
 * of partial_heads, and T1's stale CAS(H1 -> H2) succeeds. H2 has already
 * been exchanged out of partial_heads and the cleanup frees it as empty,
 * leaving a freed page on top of partial_heads.
 */
MSLT_SCENARIO(t_cleanup_phase_vs_pick)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  uint objs = s->objs_per_slab;
  void *b[2 * objs + 1], *t1b[1] = {}, *t2b[1] = {};
  struct mslt_setup st = { .s = s, .b = b };

  if (!mslt_setup_partials(&st))
    return 0;

  /* H2 becomes empty while in partial_heads */
  mslt_free_blocks(&b[objs + 1], objs - 1);

  /* The cleanup takes its RCU phase and stops. If the cleanup doesn't
   * take the phase by rcu_begin_sync(), it just runs through, and we start
   * another cleanup later at the moment when the stopped one would continue. */
  struct mslt_worker *t1, *c;
  mslt_arm(MP_CLEANUP, ID_C, 1);
  c = mslt_start(ID_C, s, mslt_do_cleanup, NULL, 0);
  bool early_phase = mslt_wait(MPB(MP_CLEANUP), c, 1000);
  if (!early_phase)
  {
    bt_debug("Cleanup did not reach %s\n", mslt_point_name[MP_CLEANUP]);
    mslt_release(MP_CLEANUP);
    mslt_join(c);
  }

  /* T1 gets stuck in msl_get_partial_head() with H1 and H1->next == H2 */
  mslt_arm(MP_PICK, ID_T1, 1);
  t1 = mslt_start(ID_T1, s, mslt_do_alloc, t1b, 1);
  if (!mslt_wait(MPB(MP_PICK), t1, 5000))
    bug("T1 did not reach %s", mslt_point_name[MP_PICK]);

  /* T2 takes H1, allocates its last free block and ends, pushing H1 to full_heads */
  mslt_run(ID_T2, s, mslt_do_alloc, t2b, 1);
  bt_assert(MSL_GET_HEAD(t2b[0]) == st.h1);
  mslt_run(ID_T2, s, mslt_do_thread_end, NULL, 0);

  /* One block of H1 gets freed, so the cleanup moves H1 to partial_heads */
  mslt_free_blocks(t2b, 1);

  /* The cleanup walks full_heads and exchanges partial_heads.
   * If it waits for T1 first, it does not get to MP_SYNC; that is fine. */
  mslt_arm(MP_SYNC, ID_C, 1);
  if (early_phase)
    mslt_release(MP_CLEANUP);
  else
    c = mslt_start(ID_C, s, mslt_do_cleanup, NULL, 0);

  mslt_wait(MPB(MP_SYNC), c, 1000);

  /* T1 finishes its CAS */
  mslt_release(MP_PICK);
  mslt_join(t1);

  /* The cleanup finishes */
  mslt_release(MP_SYNC);
  mslt_join(c);

  if (!mslt_check_lists(s))
    return 0;

  mslt_free_blocks(b, 2 * objs + 1);
  mslt_free_blocks(t1b, 1);
  rfree(s);

  return 1;
}

/*
 * Scenario: num_full overshoot.
 *
 * msl_free() clears the bit in the head and only then decrements num_full.
 * If the owning thread refreshes its bitfield inbetween, it counts the block
 * as free and adds it to num_full, while the decrement is still pending.
 * The head may then get to full_heads with num_full > objs_per_slab for a while,
 * and the cleanup must not choke on that.
 */
MSLT_SCENARIO(t_free_vs_refresh)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  uint objs = s->objs_per_slab;
  void *b[objs], *c[3] = {};

  /* W1 fills one head H completely, H is still W1's head */
  mslt_run(ID_W1, s, mslt_do_alloc, b, objs);
  msl_head *h = MSL_GET_HEAD(b[0]);
  for (uint i = 0; i < objs; i++)
    bt_assert(MSL_GET_HEAD(b[i]) == h);
  bt_assert(atomic_load(&s->full_heads) == &slh_dummy_last_full);

  /* One block is freed completely */
  mslt_free_blocks(&b[0], 1);

  /* Another free stops between clearing the bit and decrementing num_full */
  struct mslt_worker *f;
  mslt_arm(MP_FREE, ID_F, 1);
  f = mslt_start(ID_F, s, mslt_do_free, &b[1], 1);
  if (!mslt_wait(MPB(MP_FREE), f, 5000))
    bug("Free did not reach %s", mslt_point_name[MP_FREE]);

  /* W1 refreshes its bitfield, reuses both blocks and pushes H to full_heads */
  mslt_run(ID_W1, s, mslt_do_alloc, c, 3);
  bt_assert(MSL_GET_HEAD(c[0]) == h);
  bt_assert(MSL_GET_HEAD(c[1]) == h);
  bt_assert(atomic_load(&s->full_heads) == h);

  uint nf = atomic_load(&h->num_full);
  if (nf > objs)
    bt_debug("Head in full_heads has num_full %u > objs_per_slab %u\n", nf, objs);

  /* The cleanup runs while the free is still pending */
  mslt_run(ID_C, s, mslt_do_cleanup, NULL, 0);

  mslt_release(MP_FREE);
  mslt_join(f);

  if (!mslt_check_lists(s))
    return 0;

  mslt_free_blocks(b, objs);
  mslt_free_blocks(c, 3);
  rfree(s);

  return 1;
}

/*
 * Scenario: an empty head in full_heads.
 *
 * The cleanup moves it to partial_heads but does not free it, because it may
 * not free a head it has just taken from full_heads. The head is freed by
 * the next cleanup, which is not scheduled immediately.
 */
MSLT_SCENARIO(t_drained_full_head)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  uint objs = s->objs_per_slab;
  void *b[objs + 1];

  /* W1 fills H and pushes it to full_heads */
  mslt_run(ID_W1, s, mslt_do_alloc, b, objs + 1);
  msl_head *h = MSL_GET_HEAD(b[0]);
  bt_assert(atomic_load(&s->full_heads) == h);

  /* Everything in H is freed, this schedules the cleanup */
  mslt_free_blocks(b, objs);
  bt_assert(ev_active(&s->event_clean));

  mslt_settle(s);
  if (mslt_page_live(h))
    bt_debug("Empty head kept after all scheduled cleanups have run\n");

  if (!mslt_check_lists(s))
    return 0;

  /* Any later cleanup must free it */
  msl_cleanup(s);
  bt_assert_msg(!mslt_page_live(h), "Empty head kept after another cleanup");

  if (!mslt_check_lists(s))
    return 0;

  mslt_free_blocks(b, objs + 1);
  rfree(s);

  return 1;
}

/*
 * Scenario: a thread ends with a head where some blocks were never handed out.
 *
 * The head goes to full_heads with free blocks and no cleanup is scheduled.
 * Freeing the last allocated block from it must schedule the cleanup, and
 * the head must be freed eventually.
 */
MSLT_SCENARIO(t_thread_end_partial_head)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(MSLT_SIZE);
  void *b[1];

  mslt_run(ID_W1, s, mslt_do_alloc, b, 1);
  msl_head *h = MSL_GET_HEAD(b[0]);

  mslt_run(ID_W1, s, mslt_do_thread_end, NULL, 0);
  bt_assert(atomic_load(&s->full_heads) == h);
  bt_assert(atomic_load(&h->num_full) == 1);
  if (!ev_active(&s->event_clean))
    bt_debug("Thread end pushed a head with free blocks to full_heads without scheduling cleanup\n");

  /* The last free from the head schedules the cleanup */
  mslt_free_blocks(b, 1);
  bt_assert_msg(ev_active(&s->event_clean), "Last free from a head did not schedule cleanup");

  mslt_settle(s);
  bt_assert(atomic_load(&s->full_heads) == &slh_dummy_last_full);

  /* The head is now empty in partial_heads, any later cleanup must free it */
  msl_cleanup(s);
  bt_assert_msg(!mslt_page_live(h), "Empty head kept after another cleanup");

  if (!mslt_check_lists(s))
    return 0;

  rfree(s);

  return 1;
}

/*
 * Stress test: several threads allocate and free blocks (also blocks allocated
 * by other threads) while another thread runs the cleanup in a loop.
 * The hook points add random delays to make the race windows wider.
 */
#define STRESS_THREADS	4
#define STRESS_SLOTS	512
#define STRESS_SIZE	200

static void * _Atomic stress_slot[STRESS_SLOTS];
static _Atomic bool stress_stop;

static void
stress_store(void *p, uint i)
{
  /* Mark the block with its slot index to detect double allocation */
  memset(p, i & 0xff, STRESS_SIZE);
  *((u32 *) p) = i;
}

static void
stress_check(void *p, uint i)
{
  if (*((u32 *) p) != i)
    bug("Stress: block %p in slot %u marked %u", p, i, *((u32 *) p));

  for (uint j = sizeof(u32); j < STRESS_SIZE; j++)
    if (((byte *) p)[j] != (i & 0xff))
      bug("Stress: block %p in slot %u corrupted at %u", p, i, j);
}

static void
stress_worker(struct mslt_worker *w)
{
  while (!atomic_load_explicit(&stress_stop, memory_order_acquire))
  {
    uint i = mslt_rnd() % STRESS_SLOTS;
    void *p = atomic_exchange_explicit(&stress_slot[i], NULL, memory_order_acq_rel);

    if (p)
    {
      stress_check(p, i);
      msl_free(p);
    }
    else
    {
      p = msl_alloc(w->s);
      stress_store(p, i);

      void *exp = NULL;
      if (!atomic_compare_exchange_strong_explicit(&stress_slot[i], &exp, p,
	    memory_order_acq_rel, memory_order_acquire))
	msl_free(p);
    }
  }
}

static void
stress_cleaner(struct mslt_worker *w)
{
  while (!atomic_load_explicit(&stress_stop, memory_order_acquire))
  {
    msl_cleanup(w->s);
    usleep(mslt_rnd() % 100);
  }
}

MSLT_SCENARIO(t_stress)
{
  mslt_reset_gates();

  mslab *s = mslt_new_slab(STRESS_SIZE);
  for (uint i = 0; i < STRESS_THREADS; i++)
    mslt_prepare(s, ID_STRESS + i);

  atomic_store(&stress_stop, 0);
  atomic_store(&mslt_jitter, 1);

  struct mslt_worker *w[STRESS_THREADS], *c;
  for (uint i = 0; i < STRESS_THREADS; i++)
    w[i] = mslt_start(ID_STRESS + i, s, stress_worker, NULL, 0);
  c = mslt_start(ID_C, s, stress_cleaner, NULL, 0);

  sleep(bt_is_extended ? 60 : 3);

  atomic_store(&stress_stop, 1);
  for (uint i = 0; i < STRESS_THREADS; i++)
    mslt_join(w[i]);
  mslt_join(c);
  atomic_store(&mslt_jitter, 0);

  for (uint i = 0; i < STRESS_SLOTS; i++)
  {
    void *p = atomic_exchange(&stress_slot[i], NULL);
    if (p)
    {
      stress_check(p, i);
      msl_free(p);
    }
  }

  if (!mslt_check_lists(s))
    return 0;

  rfree(s);
  return 1;
}


/*
 * Single-threaded tests
 */

static const int sizes[] = {
  8, 12, 18, 27, 41, 75, 131, 269,
};

//#define TEST_SIZE	1024 * 128 * (bt_is_extended ? 1024 : 1)
#define TEST_SIZE	1024 * 128 * (bt_is_extended ? 64 : 1)
#define ITEMS(sz)	TEST_SIZE / ( (sz) >> u32_log2((sz))/2 )

#define REPS		(bt_is_extended ? 32 : 1)

struct test_request {
  int size;
  enum strategy {
    TEST_NONE,
    TEST_FORWARDS,
    TEST_BACKWARDS,
    TEST_RANDOM,
    TEST_MIXED,
    TEST__MAX,
  } strategy;
};

const char * const strategy_name[TEST__MAX] = {
  [TEST_FORWARDS] = "forwards",
  [TEST_BACKWARDS] = "backwards",
  [TEST_RANDOM] = "random",
  [TEST_MIXED] = "mixed",
};

static inline byte *test_alloc(mslab *s, int sz, struct resmem *sliz)
{
  byte *out = msl_alloc(s);

  for (int p=0; p < sz; p++)
    out[p] = p & 0xff;

  struct resmem ns = rmemsize((resource *) s);
  if (sliz->effective + sz != ns.effective)
    bug("bt_assert(sliz->effective + sz == ns.effective) %i %i %i", sliz->effective, sz, ns.effective);
  bt_assert(sliz->effective + sz == ns.effective);
  if ((sliz->overhead - sz - ns.overhead) % page_size)
    bug("(sliz->overhead - sz - ns.overhead) mod page_size %i %i %i %i", sliz->overhead, sz, ns.overhead, page_size);
  bt_assert((sliz->overhead - sz - ns.overhead) % page_size == 0);

  *sliz = ns;

  return out;
}

static inline void test_free(mslab *s, byte *block, int sz, struct resmem *sliz)
{
  for (int p=0; p < sz; p++)
  {
    bt_assert(block[p] == (p & 0xff));
    block[p]++;
  }

  msl_free(block);

  struct resmem ns = rmemsize((resource *) s);

  if (sliz->effective - sz != ns.effective)
    bug("bt_assert(sliz->effective - sz == ns.effective) %i %i %i", sliz->effective, sz, ns.effective);
  bt_assert(sliz->effective - sz == ns.effective);
  if ((sliz->overhead + sz - ns.overhead) % page_size)
    bug("(sliz->overhead + sz - ns.overhead) mod page_size %i %i %i %i", sliz->overhead, sz, ns.overhead, page_size);
  bt_assert((sliz->overhead + sz - ns.overhead) % page_size == 0);

  *sliz = ns;
}

static inline struct resmem get_memsize(mslab *s)
{
  struct resmem sz = rmemsize((resource *) s);
  bt_assert(sz.effective == 0);
  return sz;
}

static int
t_mslab(const void *data)
{
  const struct test_request *tr = data;
  int sz = tr->size;

  mslab *s = msl_new(&root_pool, birdloop_event_list(&main_birdloop), sz);
  struct resmem sliz = get_memsize(s);

  int n = ITEMS(sz);
  byte **block = mb_alloc(&root_pool, n * sizeof(*block));

  switch (tr->strategy) {
    case TEST_FORWARDS:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = 0; i < n; i++)
	test_free(s, block[i], sz, &sliz);

      }
      break;

    case TEST_BACKWARDS:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = n - 1; i >= 0; i--)
	test_free(s, block[i], sz, &sliz);

      }
      break;
    case TEST_RANDOM:
      for (int rep = 0; rep < REPS; rep++)
      {
      for (int i = 0; i < n; i++)
	block[i] = test_alloc(s, sz, &sliz);

      for (int i = 0; i < n; i++)
      {
	int pos = bt_random() % (n - i);
	test_free(s, block[pos], sz, &sliz);
	if (pos != n - i - 1)
	  block[pos] = block[n - i - 1];
      }

      }
      break;
    case TEST_MIXED:
      {
	int cur = 0;
	int pending = n;
	int recycle = n * (REPS-1);

	while (cur + pending > 0) {
	  int action = bt_random() % (cur + pending);

	  if (action < cur) {
	    test_free(s, block[action], sz, &sliz);
	    if (action != --cur)
	      block[action] = block[cur];

	    if (recycle-- > 0)
	      pending++;
	  } else {
	    block[cur++] = test_alloc(s, sz, &sliz);
	    pending--;
	  }
	}

	break;
      }

    default: bug("This shouldn't happen");
  }

  mb_free(block);
  rfree(s);
  return 1;
}
int main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  struct test_request tr;

  for (uint i = 0; i < sizeof(sizes) / sizeof(*sizes); i++){
      for (uint strategy = TEST_FORWARDS; strategy < TEST__MAX; strategy++)
      {
	tr = (struct test_request) {
	  .size = sizes[i],
	  .strategy = strategy,
	};
	bt_test_suite_arg(t_mslab, &tr, "mslab allocator test, size=%d, strategy=%s",
	    tr.size, strategy_name[strategy]);
      }
      }

  bt_test_suite(t_pick_vs_cleanup, "Head picker vs. cleanup freeing an empty head");
  bt_test_suite(t_pick_vs_thread_end, "Head picker vs. thread end freeing an empty head");
  bt_test_suite(t_cleanup_phase_vs_pick, "Head picker locking RCU after cleanup took its phase");
  bt_test_suite(t_free_vs_refresh, "Free vs. bitfield refresh, num_full overshoot");
  bt_test_suite(t_drained_full_head, "Empty head from full_heads freed by a later cleanup");
  bt_test_suite(t_thread_end_partial_head, "Head left by thread end freed after its last free");
  bt_test_suite(t_stress, "Multithreaded alloc/free/cleanup stress");

  return bt_exit_value();
}

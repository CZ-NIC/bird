#undef LOCAL_DEBUG
//#define LOCAL_DEBUG
#undef DEBUG_STATELOG
//#define DEBUG_STATELOG

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "nest/bird.h"
#include "lib/macro.h"
#include "lib/worker.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "conf/conf.h"

#include "lib/atomic.h"

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <unistd.h>

#include "sysdep/arch/asm.h"

/*
void cpu_stat_begin(void);
u64 cpu_stat_end(void);
void cpu_stat_init(void);
void cpu_stat_destroy(void);
*/

#define cpu_stat_init()

static volatile _Atomic u64 max_worker_id = 1;
static _Thread_local u64 worker_id;

#define WDBG(x, y...) DBG("(W%4lu): " x, worker_id, ##y)
#define wdie(x, y...) die("(W%4lu): " x, worker_id, ##y)
#define wbug(x, y...) bug("(W%4lu): " x, worker_id, ##y)
#define wdebug(x, y...) debug("(W%4lu): " x, worker_id, ##y)
#define wimpossible() wbug("This shall never happen: %s:%d", __FILE__, __LINE__)
#define WASSERT(what) do { if (!(what)) wbug("This shall never happen: " #what " at %s:%d", __FILE__, __LINE__); } while (0)

#ifdef DEBUG_STATELOG
#define STATELOG_SIZE_ (1 << 14)
static const uint STATELOG_SIZE = STATELOG_SIZE_;
#endif

static struct worker_queue {
  sem_t waiting;		/* Workers wait on this semaphore to get work */
  sem_t stopped;		/* Posted on worker stopped */
  sem_t yield;			/* Keeps the right number of workers running */
  sem_t available;		/* How many workers are currently free */
  _Atomic uint running;		/* How many workers are really running */
  _Atomic uint workers;		/* Allowed number of concurrent workers */
  _Atomic uint max_workers;	/* Maximum count of workers incl. sleeping */
  uint queue_size;		/* How many items can be in queue before blocking */
  _Atomic uint stop;		/* Stop requests */
  _Atomic uint blocked;		/* How many workers are blocked by full queue */
  _Atomic uint postponed;	/* How many available sem_post's have been postponed */
  _Atomic u64 lock;		/* Simple spinlock */
  list pending;			/* Tasks pending */
#ifdef DEBUG_STATELOG
  _Atomic u64 statelog_pos;	/* Current position in statelog */
  struct worker_queue_state {
    u64 worker_id;
    PACKED enum {
      WQS_NOTHING = 0,
      WQS_LOCK,
      WQS_UNLOCK,
      WQS_YIELD,
      WQS_CONTINUE,
      WQS_SEM_POST,
      WQS_SEM_WAIT_REQUEST,
      WQS_SEM_WAIT_SUCCESS,
      WQS_SEM_TRYWAIT_SUCCESS,
      WQS_SEM_TRYWAIT_BLOCKED,
      WQS_DOMAIN_WRLOCK_REQUEST,
      WQS_DOMAIN_RDLOCK_REQUEST,
      WQS_DOMAIN_WRLOCK_SUCCESS,
      WQS_DOMAIN_RDLOCK_SUCCESS,
      WQS_DOMAIN_WRLOCK_BLOCKED,
      WQS_DOMAIN_RDLOCK_BLOCKED,
      WQS_DOMAIN_RDUNLOCK_REQUEST,
      WQS_DOMAIN_WRUNLOCK_REQUEST,
      WQS_DOMAIN_RDUNLOCK_DONE,
      WQS_DOMAIN_WRUNLOCK_DONE,
    } what;
    union {
      struct {
	uint running;
	uint workers;
	uint max_workers;
	uint stop;
	uint pending;
      } queue;
      sem_t *sem;
      struct {
	u64 lock;
	uint rdsem_n, wrsem_n, rdtasks_n, wrtasks_n;
	struct domain *domain;
	struct task *task;
      } domain;
    };
  } statelog[STATELOG_SIZE_];
#endif
} wq_, *wq = &wq_;

#ifdef DEBUG_STATELOG
#define WQ_STATELOG(what_, ...) \
  wq->statelog[atomic_fetch_add(&wq->statelog_pos, 1) % STATELOG_SIZE] = \
  (struct worker_queue_state) { .what = what_, .worker_id = worker_id, __VA_ARGS__ }
#else
#define WQ_STATELOG(...)
#endif

#define ADL(what) atomic_load_explicit(&what, memory_order_relaxed)

#define WQ_STATELOG_QUEUE(what_, locked) \
  WQ_STATELOG(what_, .queue = { .running = ADL(wq->running), .workers = ADL(wq->workers), .max_workers = ADL(wq->max_workers), .stop = ADL(wq->stop), .pending = locked ? list_length(&wq->pending) : 0 })


#define NOWORKER (~0ULL)

#ifdef SPINLOCK_STATS
#define WORKER_CPU_RELAX(var) do { var++; CPU_RELAX(); } while (0)
#define WORKER_CPU_RELAX_STORE_COUNT(var) do { \
  u64 spin_max_local = atomic_load_explicit(&spin_max, memory_order_relaxed); \
  while (spin_max_local < var) \
    if (atomic_compare_exchange_weak_explicit(&spin_max, &spin_max_local, var, memory_order_relaxed, memory_order_relaxed)) \
      break; \
} while (0)
_Atomic u64 spin_max = 0;
_Atomic u64 spin_stats[65536];
_Atomic u64 wql_max = 0;
_Atomic u64 wql_sum = 0;
_Atomic u64 wql_cnt = 0;

#else
#define WORKER_CPU_RELAX(var) do { var++; CPU_RELAX(); } while (0)
#endif

static _Thread_local int worker_sleeping = 1;

#define WQ_LOCK_PREFETCH(ptr) do { \
  __builtin_prefetch(&wq->lock); \
  __builtin_prefetch(ptr); \
} while (0)

static inline void WQ_LOCK(void)
{
  WASSERT(!worker_sleeping);

  u64 spin_count = 0;
  while (1)
  {
    u64 noworker = NOWORKER;
    if (atomic_compare_exchange_weak_explicit(&wq->lock, &noworker, worker_id, memory_order_acquire, memory_order_relaxed))
      break;

    WORKER_CPU_RELAX(spin_count);
  }

#ifdef SPINLOCK_STATS
  cpu_stat_begin();

  if (spin_count > 65534)
    atomic_fetch_add(&spin_stats[65535], 1);
  else
    atomic_fetch_add(&spin_stats[spin_count], 1);

  WORKER_CPU_RELAX_STORE_COUNT(spin_count);
#endif

  WQ_STATELOG_QUEUE(WQS_LOCK, 1);
}

#if DEBUGGING
static inline void WQ_ASSERT_UNLOCKED(void)
{
  if (atomic_load(&wq->lock) == worker_id)
    wbug("The spinlock shan't be locked by us!");
}
#else
#define WQ_ASSERT_UNLOCKED()
#endif

static inline void WQ_UNLOCK(void)
{
  WQ_STATELOG_QUEUE(WQS_UNLOCK, 1);

  u64 expected = worker_id;
  if (!atomic_compare_exchange_strong_explicit(&wq->lock, &expected, NOWORKER, memory_order_release, memory_order_relaxed))
    wbug("The spinlock is locked by %lu but shall be locked by %lu!", expected, worker_id);

#ifdef SPINLOCK_STATS
  u64 stat = cpu_stat_end();
  u64 wql_max_local = atomic_load_explicit(&wql_max, memory_order_relaxed);
  while (wql_max_local < stat)
    if (atomic_compare_exchange_weak_explicit(&wql_max, &wql_max_local, stat, memory_order_relaxed, memory_order_relaxed))
      break;

  atomic_fetch_add_explicit(&wql_sum, stat, memory_order_relaxed);
  atomic_fetch_add_explicit(&wql_cnt, 1, memory_order_relaxed);
#endif
}

static inline void SEM_INIT(sem_t *s, uint val)
{
  if (sem_init(s, 0, val) < 0)
    wbug("sem_init() failed: %m");
}

#define SEM_WAIT(_s) do { \
  sem_t *s = _s; \
  WQ_STATELOG(WQS_SEM_WAIT_REQUEST, .sem = s); \
  while (sem_wait(s) < 0) { \
    if (errno == EINTR) \
      continue; \
    wdie("sem_wait: %m"); \
  } \
  WQ_STATELOG(WQS_SEM_WAIT_SUCCESS, .sem = s); \
} while (0)

static inline int SEM_TRYWAIT(sem_t *s)
{
  while (sem_trywait(s) < 0) {
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN)
    {
      WQ_STATELOG(WQS_SEM_TRYWAIT_BLOCKED, .sem = s);
      return 0;
    }

    wdie("sem_trywait: %m");
  }

  WQ_STATELOG(WQS_SEM_TRYWAIT_SUCCESS, .sem = s);
  return 1;
}

#define SEM_POST(_s) do { \
  sem_t *s = _s; \
  if (sem_post(s) < 0) \
    wbug("sem_post: %m"); \
  WQ_STATELOG(WQS_SEM_POST, .sem = s); \
} while (0)

static inline void SEM_DESTROY(sem_t *s)
{
  if (sem_destroy(s) < 0)
    wbug("sem_post: %m");
}

static int worker_start(void);

#define WORKER_DO_YIELD() do { \
  SEM_POST(&wq->yield); \
  worker_sleeping = 1; \
} while (0)

static _Atomic int enough_workers = 0;

static inline void WORKER_YIELD(void)
{
  WQ_ASSERT_UNLOCKED();
  WASSERT(!worker_sleeping);
  WQ_STATELOG_QUEUE(WQS_YIELD, 0);
  
  /* No, there is enough workers (stored value) */
  if (atomic_load_explicit(&enough_workers, memory_order_relaxed))
  {
    WORKER_DO_YIELD();
    return;
  }

  uint max_workers = atomic_load_explicit(&wq->max_workers, memory_order_relaxed);
  uint running = atomic_load_explicit(&wq->running, memory_order_relaxed);

  /* No, there is enough workers (computed for now) */
  if (running >= max_workers)
  {
    atomic_store(&enough_workers, 1);
    WORKER_DO_YIELD();
    return;
  }

  /* Yes, start it. */
  running = atomic_fetch_add_explicit(&wq->running, 1, memory_order_acq_rel);

  /* If we're over the limit now. */
  if (running >= max_workers)
    goto bad;

  /* It is unreasonable, there is a sleeping worker just now, */
  if (SEM_TRYWAIT(&wq->available))
  {
    SEM_POST(&wq->available);
    goto bad;
  }

  /* Yes, all workers are doing something, start a new one */
  int e = worker_start();
  if (e == 0)
  {
    WORKER_DO_YIELD();
    return;
  }

  log(L_WARN "Failed to start a worker on yield: %M", e);

bad:
  /* Revert the running counter */
  atomic_fetch_sub_explicit(&wq->running, 1, memory_order_acquire);
  WORKER_DO_YIELD();
}

static inline void WORKER_CONTINUE(void)
{
  WQ_ASSERT_UNLOCKED();
  WASSERT(worker_sleeping);
  SEM_WAIT(&wq->yield);
  worker_sleeping = 0;
  WQ_STATELOG_QUEUE(WQS_CONTINUE, 0);
}

static _Thread_local struct timeloop worker_timeloop;

struct domain {
  resource r;
  sem_t rdsem;		/* Wait semaphore for readers */
  sem_t wrsem;		/* Wait semaphore for writers */
  list rdtasks;		/* Reader tasks blocked */
  list wrtasks;		/* Writer tasks blocked */
  uint rdsem_n;		/* How many secondary readers waiting */
  uint wrsem_n;		/* How many secondary writers waiting */
  uint rdtasks_n;	/* How many reader tasks waiting */
  uint wrtasks_n;	/* How many writer tasks waiting */
  _Atomic u64 lock;	/* Lock state:
			   bit 63: 1 = spinlock, don't do anything on this state
			   bit 62: 1 = writer locked
			   bit 61: 1 = there are readers waiting (rdsem_n + rdtasks_n > 0)
			   bit 60: 1 = there are writers waiting (wrsem_n + wrtasks_n > 0)
			   bit 30-59: number of prepended tasks
			   bit 0-29: number of concurrently locked readers */
};

#define DOMAIN_LOCK_PREPENDED(lock)	(((lock) >> 30) & ((1U << 30) - 1))
#define DOMAIN_LOCK_RDLOCKED(lock)	((lock) & ((1U << 30) - 1))
#define DOMAIN_LOCK_WRITERS_BIT		(1ULL << 60)
#define DOMAIN_LOCK_READERS_BIT		(1ULL << 61)
#define DOMAIN_LOCK_WRLOCKED_BIT	(1ULL << 62)
#define DOMAIN_LOCK_SPINLOCK_BIT	(1ULL << 63)

#define DOMAIN_LOCK_PREPENDED_ONE	(1U << 30)
#define DOMAIN_LOCK_RDLOCKED_ONE	1

#define DOMAIN_LOCK_LOAD_() lock = atomic_load_explicit(&d->lock, memory_order_acquire)
#define DOMAIN_LOCK_LOAD() \
  u64 lock, spin_count = 0; DOMAIN_LOCK_LOAD_(); \
retry: do { \
  if (lock & DOMAIN_LOCK_SPINLOCK_BIT) { \
    WORKER_CPU_RELAX(spin_count); \
    DOMAIN_LOCK_LOAD_(); \
    goto retry; \
  } \
} while (0)

#define DOMAIN_LOCK_STORE(what) do { \
  if (!atomic_compare_exchange_strong_explicit( \
	&d->lock, &lock, what, memory_order_acq_rel, memory_order_acquire)) \
    goto retry; \
} while (0)

#define DOMAIN_LOCK_ENTER_SLOWPATH() DOMAIN_LOCK_STORE(lock | DOMAIN_LOCK_SPINLOCK_BIT)
#define DOMAIN_LOCK_EXIT_SLOWPATH(what) do { \
  u64 slock = lock | DOMAIN_LOCK_SPINLOCK_BIT; \
  if (!atomic_compare_exchange_strong_explicit( \
	&d->lock, &slock, what, memory_order_acq_rel, memory_order_acquire)) \
    bug("Lock state value shall never change while in slowpath"); \
} while (0)

#define TASK_STOP_WORKER do { \
  atomic_fetch_add_explicit(&wq->stop, 1, memory_order_acquire); \
  SEM_POST(&wq->waiting); \
} while (0);

void
domain_free(resource *r)
{
  struct domain *d = SKIP_BACK(struct domain, r, r);
  sem_destroy(&d->rdsem);
  sem_destroy(&d->wrsem);
}

void
domain_dump(resource *r)
{
  struct domain *d = SKIP_BACK(struct domain, r, r);
  DOMAIN_LOCK_LOAD();
  DOMAIN_LOCK_ENTER_SLOWPATH();
  wdebug("Locking domain: WP:%u WS:%u RP:%u RS:%u RL:%u PREP:%u WL:%u\n",
      d->wrtasks_n, d->wrsem_n, d->rdtasks_n, d->rdsem_n,
      DOMAIN_LOCK_RDLOCKED(lock), DOMAIN_LOCK_PREPENDED(lock),
      !!(lock & DOMAIN_LOCK_WRLOCKED_BIT));
  DOMAIN_LOCK_EXIT_SLOWPATH(lock);
}

static struct resclass domain_resclass = {
  .name = "Domain",
  .size = sizeof(struct domain),
  .free = domain_free,
  .dump = domain_dump,
  .lookup = NULL,
  .memsize = NULL
};

static _Thread_local struct locked_domain {
  struct domain *domain;
  int write;
} *locked_domains = NULL;
static _Thread_local uint locked_max = 0, locked_cnt = 0;

struct domain *
domain_new(pool *p)
{
  struct domain *d = ralloc(p, &domain_resclass);

  SEM_INIT(&d->rdsem, 0);
  SEM_INIT(&d->wrsem, 0);

  init_list(&d->rdtasks);
  init_list(&d->wrtasks);

  return d;
}

static inline int
domain_assert_locked(struct domain *d, int write)
{
  if (!locked_cnt)
    wbug("Completely unlocked");

  for (uint i=0; i<locked_cnt; i++)
    if ((locked_domains[i].domain == d) && locked_domains[i].write == write)
      return 0;

  return 1;
}

void
domain_assert_write_locked(struct domain *d)
{
  if (domain_assert_locked(d, 1))
    wbug("Domain not locked for writing");
}

void
domain_assert_read_locked(struct domain *d)
{
  if (domain_assert_locked(d, 0))
    wbug("Domain not locked for reading");
}

void domain_assert_unlocked(struct domain *d)
{
  if (!locked_cnt)
    return;

  for (uint i=0; i<locked_cnt; i++)
    if (locked_domains[i].domain == d)
      wbug("Domain locked.");
}

static inline void
domain_push_lock(struct domain *d, int write)
{
  if (!locked_max)
  {
    locked_domains = xmalloc(sizeof(*locked_domains) * (locked_max = 32));
    locked_cnt = 0;
  }
  
  if (locked_cnt == locked_max)
    locked_domains = xrealloc(locked_domains, sizeof(*locked_domains) * (locked_max *= 2));

  locked_domains[locked_cnt++] = (struct locked_domain) { .domain = d, .write = write };
}

static inline void
domain_pop_lock(struct domain *d UNUSED)
{ locked_cnt--; }

#define DOMAIN_STATLOG(what_, dom, task_) \
  WQ_STATELOG(what_, .domain = { .rdsem_n = dom->rdsem_n, .wrsem_n = dom->wrsem_n, .rdtasks_n = dom->rdtasks_n, .wrtasks_n = dom->wrtasks_n, .lock = atomic_load(&dom->lock), .domain = dom, .task = task_ })

static inline int
domain_read_lock_primary(struct domain *d, struct task *t)
{
  domain_assert_unlocked(d);
  WDBG("Primary read lock: domain %p, task %p\n", d, t);
  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_REQUEST, d, t);

  DOMAIN_LOCK_LOAD();

  /* Fast path for prepended tasks */
  if (t->flags & TF_PREPENDED)
  {
    if (DOMAIN_LOCK_PREPENDED(lock) == 0)
      wbug("Got a pending task with pending count zero");

    if (lock & DOMAIN_LOCK_WRLOCKED_BIT)
      wbug("Got a prepended reader task with writer locked");

    if (DOMAIN_LOCK_RDLOCKED(lock) == 0)
      wbug("Reader shall be already locked");

    DOMAIN_LOCK_STORE(lock - DOMAIN_LOCK_PREPENDED_ONE);

    WDBG("-> Forcibly acquiring prepended lock.\n");
/*    d->rdlocked++;  is called by the prepender */

    domain_push_lock(d, 0);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, t);
    return 1;
  }

  /* Slow path if locked for writing */
  if (lock & (DOMAIN_LOCK_WRLOCKED_BIT | DOMAIN_LOCK_WRITERS_BIT))
  {
    /* Task is blocked */
    DOMAIN_LOCK_ENTER_SLOWPATH();
    add_tail(&(d->rdtasks), &(t->n));
    d->rdtasks_n++;
    DOMAIN_LOCK_EXIT_SLOWPATH(lock | DOMAIN_LOCK_READERS_BIT);

    WDBG("-> Blocked (n=%u)\n", d->rdtasks_n);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_BLOCKED, d, t);
    return 0;
  }
  else
  {
    DOMAIN_LOCK_STORE(lock + DOMAIN_LOCK_RDLOCKED_ONE);

    WDBG("-> Instantly locked (n=%u)\n", DOMAIN_LOCK_RDLOCKED(lock));

    domain_push_lock(d, 0);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, t);
    return 1;
  }
}

void
domain_read_lock(struct domain *d)
{
  domain_assert_unlocked(d);
  WDBG("Secondary read lock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_REQUEST, d, NULL);

  DOMAIN_LOCK_LOAD();

  if (lock & (DOMAIN_LOCK_WRLOCKED_BIT | DOMAIN_LOCK_WRITERS_BIT))
  {
    /* Blocked */
    DOMAIN_LOCK_ENTER_SLOWPATH();
    d->rdsem_n++;
    DOMAIN_LOCK_EXIT_SLOWPATH(lock | DOMAIN_LOCK_READERS_BIT);

    WDBG("-> Blocked (n=%u)\n", d->rdsem_n);

    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_BLOCKED, d, NULL);
    WORKER_YIELD();

    /* Wait until somebody unblocks us.
     * That thread also locks the lock for us
     * before running SEM_POST(&d->rdsem), */
    SEM_WAIT(&d->rdsem);
    WORKER_CONTINUE();
  }
  else
  {
    DOMAIN_LOCK_STORE(lock + DOMAIN_LOCK_RDLOCKED_ONE);

    WDBG("-> Instantly locked (n=%u)\n", DOMAIN_LOCK_RDLOCKED(lock));
  }

  domain_push_lock(d, 0);
  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, NULL);
}

static inline int
domain_write_lock_primary(struct domain *d, struct task *t)
{
  domain_assert_unlocked(d);
  WDBG("Primary write lock: domain %p, task %p\n", d, t);
  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_REQUEST, d, t);

  DOMAIN_LOCK_LOAD();

  /* Fast path for prepended tasks */
  if (t->flags & TF_PREPENDED)
  {
    if (DOMAIN_LOCK_PREPENDED(lock) != 1)
      wbug("Got a pending task without pending count set to 1");

    if (DOMAIN_LOCK_RDLOCKED(lock) > 0)
      wbug("Got a prepended writer task with reader locked");

    if (!(lock & DOMAIN_LOCK_WRLOCKED_BIT))
      wbug("Writer shall be already locked here");

    DOMAIN_LOCK_STORE(lock - DOMAIN_LOCK_PREPENDED_ONE);

    WDBG("-> Forcibly acquiring prepended lock.\n");
/*    d->wrlocked = 1;  is called by the prepender */

    domain_push_lock(d, 1);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, t);
    return 1;
  }

  /* Slow path if locked */
  if ((lock & (DOMAIN_LOCK_WRLOCKED_BIT | DOMAIN_LOCK_WRITERS_BIT))
      || (DOMAIN_LOCK_RDLOCKED(lock) > 0))
  {
    /* Task is blocked */
    DOMAIN_LOCK_ENTER_SLOWPATH();
    add_tail(&(d->wrtasks), &(t->n));
    d->wrtasks_n++;
    DOMAIN_LOCK_EXIT_SLOWPATH(lock | DOMAIN_LOCK_WRITERS_BIT);

    WDBG("-> Blocked (n=%u)\n", d->wrtasks_n);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_BLOCKED, d, t);
    return 0;
  }
  else
  {
    DOMAIN_LOCK_STORE(lock | DOMAIN_LOCK_WRLOCKED_BIT);

    WDBG("-> Instantly locked\n");

    domain_push_lock(d, 1);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, t);
    return 1;
  }
}

void
domain_write_lock(struct domain *d)
{
  domain_assert_unlocked(d);
  WDBG("Secondary write lock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_REQUEST, d, NULL);

  DOMAIN_LOCK_LOAD();

  /* Slow path if locked */
  if ((lock & (DOMAIN_LOCK_WRLOCKED_BIT | DOMAIN_LOCK_WRITERS_BIT))
      || (DOMAIN_LOCK_RDLOCKED(lock) > 0))
  {
    /* Blocked */
    DOMAIN_LOCK_ENTER_SLOWPATH();
    d->wrsem_n++;
    DOMAIN_LOCK_EXIT_SLOWPATH(lock | DOMAIN_LOCK_WRITERS_BIT);

    WDBG("-> Blocked (n=%u)\n", d->wrsem_n);

    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_BLOCKED, d, NULL);
    WORKER_YIELD();

    /* Wait until somebody unblocks us.
     * That thread also locks the lock for us
     * before running SEM_POST(&d->rdsem), */
    SEM_WAIT(&d->wrsem);
    WORKER_CONTINUE();
  }
  else
  {
    DOMAIN_LOCK_STORE(lock | DOMAIN_LOCK_WRLOCKED_BIT);

    WDBG("-> Instantly locked\n");
  }

  domain_push_lock(d, 1);
  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, NULL);
}

/* This function has to be called after DOMAIN_LOCK_ENTER_SLOWPATH() is called */
static inline void
domain_unlock_writers(struct domain *d, u64 lock, u64 ulock)
{
  WASSERT(DOMAIN_LOCK_RDLOCKED(ulock) == 0);
  WASSERT(!(ulock & DOMAIN_LOCK_WRLOCKED_BIT));
  WASSERT(DOMAIN_LOCK_PREPENDED(ulock) == 0);

  if (d->wrtasks_n)
  {
    WQ_LOCK_PREFETCH(wq->pending.head);

    WDBG("-> There is a writer task waiting for us (n=%u)\n", d->wrtasks_n);
    if ((ulock & DOMAIN_LOCK_WRLOCKED_BIT) || DOMAIN_LOCK_PREPENDED(ulock))
      wimpossible();

    /* Get the task */
    struct task *t = HEAD(d->wrtasks);
    rem_node(&t->n);

    /* Lower the wrtasks_n counter */
    d->wrtasks_n--;

    /* Unlock the spinlock */
    DOMAIN_LOCK_EXIT_SLOWPATH(DOMAIN_LOCK_PREPENDED_ONE + DOMAIN_LOCK_WRLOCKED_BIT +
      ((d->wrtasks_n || d->wrsem_n) ? DOMAIN_LOCK_WRITERS_BIT : 0) +
      ((d->rdtasks_n || d->rdsem_n) ? DOMAIN_LOCK_READERS_BIT : 0));

    /* Prepend the task */
    t->flags |= TF_PREPENDED;
    WQ_LOCK();
    add_head(&wq->pending, &((t)->n));
    WQ_UNLOCK();
    SEM_POST(&wq->waiting);

    return;
  }

  if (d->wrsem_n)
  {
    WDBG("-> There is a secondary writer waiting for us (n=%u)\n", d->wrsem_n);
    
    /* Will wake up that thread */
    d->wrsem_n--;

    /* Unlock the spinlock */
    DOMAIN_LOCK_EXIT_SLOWPATH(DOMAIN_LOCK_WRLOCKED_BIT +
      ((d->wrtasks_n || d->wrsem_n) ? DOMAIN_LOCK_WRITERS_BIT : 0) +
      ((d->rdtasks_n || d->rdsem_n) ? DOMAIN_LOCK_READERS_BIT : 0));

    /* Do the wakeup itself */
    SEM_POST(&d->wrsem);

    return;
  }

  wimpossible();
}

void
domain_read_unlock(struct domain *d)
{
  domain_assert_read_locked(d);
  WDBG("Read unlock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_RDUNLOCK_REQUEST, d, NULL);

  DOMAIN_LOCK_LOAD();

  if (DOMAIN_LOCK_RDLOCKED(lock) == 0)
    wbug("Read lock count underflow");

  if (DOMAIN_LOCK_RDLOCKED(lock) > 1)
  {
    DOMAIN_LOCK_STORE(lock - DOMAIN_LOCK_RDLOCKED_ONE);
    WDBG("-> Unlocked leaving other readers behind (n=%u)\n", DOMAIN_LOCK_RDLOCKED(lock));
  }
  else if (lock & DOMAIN_LOCK_WRITERS_BIT)
  {
    DOMAIN_LOCK_ENTER_SLOWPATH();
    domain_unlock_writers(d, lock, lock - DOMAIN_LOCK_RDLOCKED_ONE);
  }
  else
  {
    /* Writing the completely unlocked state */
    WASSERT(lock == DOMAIN_LOCK_RDLOCKED_ONE);
    DOMAIN_LOCK_STORE(0);
    WDBG("-> Unlocked leaving the lock unlocked\n");
  }

  domain_pop_lock(d);
  DOMAIN_STATLOG(WQS_DOMAIN_RDUNLOCK_DONE, d, NULL);
}

void
domain_write_unlock(struct domain *d)
{
  domain_assert_write_locked(d);
  WDBG("Write unlock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_WRUNLOCK_REQUEST, d, NULL);

  DOMAIN_LOCK_LOAD();

  if (!(lock & DOMAIN_LOCK_WRLOCKED_BIT))
    wbug("Write lock already unlocked");

  if (DOMAIN_LOCK_PREPENDED(lock))
    wbug("Nothing shall be prepended on writer locked");

  if (!(lock & (DOMAIN_LOCK_WRITERS_BIT | DOMAIN_LOCK_READERS_BIT)))
  {
    /* Nobody is waiting on the lock */
    if (lock != DOMAIN_LOCK_WRLOCKED_BIT)
      wbug("Write unlock fast path triggered by mistake with state %lu", lock);

    /* Writing the completely unlocked state */
    DOMAIN_LOCK_STORE(0);
    domain_pop_lock(d);
    DOMAIN_STATLOG(WQS_DOMAIN_WRUNLOCK_DONE, d, NULL);
    return;
  }

  DOMAIN_LOCK_ENTER_SLOWPATH();

  uint w = d->wrtasks_n + d->wrsem_n;
  uint r = d->rdtasks_n + d->rdsem_n;

/* Magical condition to when we have to flush readers.
 * The rwlock has strict writer preference over readers. No reader
 * is allowed to lock when there are enough writers. This may lead
 * to a situation where two writers are blocking all readers.
 * So we sometimes flush the readers instead of locking another pending writer. */
  if (r && (!w || (r > 3*w)))
  {
    list tmp_rdtasks;

    WQ_LOCK_PREFETCH(wq->pending.head);

    WDBG("-> Flushing readers: WP=%u WS=%u RP=%u RS=%u\n",
	d->wrtasks_n, d->wrsem_n, d->rdtasks_n, d->rdsem_n);

    /* We shall flush the readers */
    u64 rdtasks_n = d->rdtasks_n;
    u64 rdsem_n = d->rdsem_n;

    /* No reader will be waiting after we're finished */
    d->rdtasks_n = 0;
    d->rdsem_n = 0;

    /* Move the tasks to a temporary list */
    if (rdtasks_n)
      move_list(&tmp_rdtasks, &d->rdtasks);

    DOMAIN_LOCK_EXIT_SLOWPATH(
	/* Lock all the pending readers */
	DOMAIN_LOCK_RDLOCKED_ONE * (rdtasks_n + rdsem_n) +
	/* Pending tasks are also going to be prepended */
	DOMAIN_LOCK_PREPENDED_ONE * rdtasks_n +
	/* If writers are remaining, block other writers */
	((d->wrtasks_n || d->wrsem_n) ? DOMAIN_LOCK_WRITERS_BIT : 0));

    if (rdtasks_n)
    {
      /* Put the prepended tasks into queue */
      u64 prepend_check = 0;
      struct task *t;
      WALK_LIST(t, tmp_rdtasks)
      {
	t->flags |= TF_PREPENDED;
	prepend_check++;
      }
   
      /* Check the right number of waiting tasks */   
      if (prepend_check != rdtasks_n)
	wimpossible();

      WQ_LOCK();
      add_head_list(&wq->pending, &tmp_rdtasks);
      WQ_UNLOCK();

      for (uint i=0; i<prepend_check; i++)
	SEM_POST(&wq->waiting);
    }

    /* Unlock the waiting secondary readers */
    for ( ; rdsem_n; rdsem_n--)
      SEM_POST(&d->rdsem);
  }
  else
    domain_unlock_writers(d, lock, lock & ~DOMAIN_LOCK_WRLOCKED_BIT);

  domain_pop_lock(d);
  DOMAIN_STATLOG(WQS_DOMAIN_WRUNLOCK_DONE, d, NULL);
}

extern _Thread_local struct timeloop *timeloop_current;

static void *
worker_loop(void *_data UNUSED)
{
  /* Overall thread initialization */
  times_init(&worker_timeloop);
  timeloop_current = &worker_timeloop;

  /* It shall be completely impossible to count up to 2**64 workers */
  worker_id = atomic_fetch_add(&max_worker_id, 1);
  WASSERT(worker_id < NOWORKER);

  cpu_stat_init();

  /* Obtain the yield-semaphore before being available */
  WORKER_CONTINUE();

  WDBG("Worker started\n");

  _Bool prepended = 0;
 
  /* Run the loop */
  while (1) {
    WQ_LOCK_PREFETCH(wq->pending.head);

    /* First of all, there must be some task. If there is no task,
     * the thread shall sleep.
     * Then, if there is any task but maximum concurrent workers is reached,
     * the thread shall also sleep.
     * Only if we are allowed to run and there is a task, we shall run.
     */

    if (!SEM_TRYWAIT(&wq->waiting))
    {
      /* There is no worker waiting. Slow path! */
      WDBG("Worker will wait\n");

      /* Yield. There may be others waiting for release */
      WORKER_DO_YIELD();

      if (SEM_TRYWAIT(&wq->yield))
      {
	/* Free worker with no work! Releasing the worker. */
	SEM_POST(&wq->yield);

	/* Sleep until some task is available */
	SEM_WAIT(&wq->waiting);

	/* But first let it to others */
	SEM_POST(&wq->waiting);
      }

      /* Now wait for our turn */
      WORKER_CONTINUE();
      continue;
    }

    WQ_LOCK();

    /* Is there a pending task? */
    if (!EMPTY_LIST(wq->pending))
    {
      /* Retrieve that task */
      struct task *t = HEAD(wq->pending);
      rem_node(&t->n);

      /* Check worker queue for emptiness */
      int empty = EMPTY_LIST(wq->pending);

      /* No more operations on worker queue */
      WQ_UNLOCK();

      /* Flush the postponed available semaphores if the queue is empty */
      if (empty)
      {
	uint postponed = atomic_exchange_explicit(&wq->postponed, 0, memory_order_relaxed) + !prepended;
	for (uint i=0; i<postponed; i++)
	  SEM_POST(&wq->available);
      }
      else if (!prepended)
	atomic_fetch_add_explicit(&wq->postponed, 1, memory_order_relaxed);

      /* Store the old flags and domain */
      struct domain *d = t->domain;
      enum task_flags tf = t->flags;

      /* Store the current prepended state */
      prepended = tf & TF_PREPENDED;

      /* Does the task need a lock? */
      if (!d)
	/* No. Just run it. */
	t->execute(t);
      /* It needs a lock. Is it available? */
      else if (tf & TF_EXCLUSIVE ?
	    domain_write_lock_primary(d, t) :
	    domain_read_lock_primary(d, t))
      {
	/* Yes. Run it! */
	t->execute(t);

	/* And unlock to let others to the domain */
	tf & TF_EXCLUSIVE ?
	  domain_write_unlock(d) :
	  domain_read_unlock(d);
      }
      else if (prepended)
	wbug("The prepended task shall never block on lock");

      /* Else: Unavailable. The task has been stored
       * into the blocked list and will be released
       * when the lock is available. */
    }
    else
    {
      WQ_UNLOCK();

      /* There must be a request to stop then */
      uint stop = atomic_load_explicit(&wq->stop, memory_order_acquire);
      WASSERT(stop > 0);

      /* Requested to stop */
      WDBG("Worker stopping\n");
      atomic_fetch_sub_explicit(&wq->stop, 1, memory_order_release);
      atomic_fetch_sub_explicit(&wq->running, 1, memory_order_release);

      /* Let others work instead of us */
      WORKER_DO_YIELD();

      /* Notify the stop requestor */
      SEM_POST(&wq->stopped);

      /* Finished */
      return NULL;
    }
  }
 
  wimpossible(); 
}

static int
worker_start(void)
{
  /* Run the thread */
  pthread_t id;
  int e = pthread_create(&id, NULL, worker_loop, NULL);
  if (e < 0)
    return e;

  /* Detach the thread; we don't want to join the threads */
  e = pthread_detach(id);
  if (e < 0)
    wbug("pthread_detach() failed: %M", e);

  return 0;
}

void
worker_queue_init(void)
{
  SEM_INIT(&wq->waiting, 0);
  SEM_INIT(&wq->stopped, 0);
  SEM_INIT(&wq->yield, 0);
  SEM_INIT(&wq->available, 0);

  init_list(&wq->pending);

  atomic_store(&wq->lock, NOWORKER);
#ifdef DEBUG_STATELOG
  atomic_store(&wq->statelog_pos, 0);
#endif
  atomic_store(&wq->running, 0);
  atomic_store(&wq->workers, 1);
  atomic_store(&wq->max_workers, 0);
  atomic_store(&wq->stop, 0);
  
  wq->queue_size = 0;

  worker_sleeping = 0;

  cpu_stat_init();
}

void
worker_queue_destroy(void)
{
  /* First stop all the workers. */
  atomic_store(&wq->max_workers, 0);

  while (atomic_load(&wq->running) > 0)
  {
    TASK_STOP_WORKER;

    WORKER_DO_YIELD();
    SEM_WAIT(&wq->stopped);
    WORKER_CONTINUE();
  }

  WASSERT(atomic_load(&wq->stop) == 0);

  /* Worker stops only when there is no task so now there
   * should be no task pending at all. */
  WQ_LOCK();
  WASSERT(EMPTY_LIST(wq->pending));
  WQ_UNLOCK();

  /* All the workers but one should also have yielded. The last one is us. */
  uint workers = atomic_load(&wq->workers);
  for (uint i=1; i<workers; i++)
    WASSERT(SEM_TRYWAIT(&wq->yield));

  /* Nobody is using the queue now. Cleanup the resources. */
  SEM_DESTROY(&wq->waiting);
  SEM_DESTROY(&wq->stopped);
  SEM_DESTROY(&wq->yield);
  SEM_DESTROY(&wq->available);
}

/* Configured worker pool change */
void
worker_queue_update(const struct config *c)
{
  static int exclusive_lock = 0;
  WASSERT(!exclusive_lock);
  exclusive_lock = 1;
#define RETURN do { exclusive_lock = 0; return; } while (0)

  /* Check whether the values are sane */
  WASSERT(c->max_workers >= c->workers);
  WASSERT(c->workers > 0);

  if ((c->workers == atomic_load(&wq->workers))
      && (c->max_workers == atomic_load(&wq->max_workers))
      && (c->queue_size == wq->queue_size))
    /* No change at all */
    RETURN;

  /* Reduction of concurrent running workers */
  for (uint i=c->workers; i<atomic_load(&wq->workers); i++)
    /* Wait until a worker yields */
    SEM_WAIT(&wq->yield);

  /* Set the new maximum */
  atomic_store(&wq->max_workers, c->max_workers);

  /* Clear the cached value if needed */
  atomic_store(&enough_workers, 0);

  /* Reduction of really running workers */
  while (atomic_load(&wq->max_workers) < atomic_load(&wq->running))
  {
    TASK_STOP_WORKER;
    SEM_WAIT(&wq->stopped);
  }

  /* Increase of concurrent running workers */
  for (uint i=atomic_load(&wq->workers); i<c->workers; i++)
    SEM_POST(&wq->yield);

  atomic_store(&wq->workers, c->workers);

  /* Queue size change */
  for ( ; wq->queue_size < c->queue_size; wq->queue_size++)
    SEM_POST(&wq->available);

  for ( ; wq->queue_size > c->queue_size; wq->queue_size--)
    SEM_WAIT(&wq->available);

  /* On startup, start at least one worker */
  if (atomic_load(&wq->running) > 0)
    RETURN;

  int e = worker_start();
  if (!e)
  {
    atomic_fetch_add(&wq->running, 1);
    RETURN;
  }

  wbug("Failed to start a worker on startup: %M", e);
}

#define TASK_APPEND(t) do { \
  SEM_POST(&wq->waiting); \
} while (0)

static void
task_push_available(struct task *t)
{
  WDBG("Waited for an available worker succesfully\n");
  WQ_LOCK();

  /* Idempotency. */
  if (t->n.prev && t->n.next)
  {
    /* If already pushed, do nothing. */
    WQ_UNLOCK();
    return;
  }

  /* Check that the node is clean */
  WASSERT(!t->n.prev && !t->n.next);

  /* Use only public flags */
  t->flags &= TF_PUBLIC_MASK;

  /* Then we have a task for it. */
  add_tail(&wq->pending, &((t)->n));
  WQ_UNLOCK();
  SEM_POST(&wq->waiting);
}

static void
task_push_block(struct task *t)
{
  WDBG("Blocking until a worker is available\n");

  WQ_LOCK();

  /* Idempotency. */
  if (t->n.prev && t->n.next)
  {
    /* If already pushed, do nothing. */
    WQ_UNLOCK();
    return;
  }

  /* Check that the node is clean */
  WASSERT(!t->n.prev && !t->n.next);

  /* Use only public flags */
  t->flags &= TF_PUBLIC_MASK;

  /* No available worker. We're going to sleep.
   * Anyway, the task still exists in the queue. */
  add_tail(&wq->pending, &((t)->n));
  WQ_UNLOCK();

  /* Indicate that there is a blocked task pusher */
  atomic_fetch_add_explicit(&wq->blocked, 1, memory_order_relaxed);

  SEM_POST(&wq->waiting);
  WORKER_YIELD();

  /* Wait until somebody picks the task up */
  SEM_WAIT(&wq->available);

  atomic_fetch_sub_explicit(&wq->blocked, 1, memory_order_relaxed);
  WORKER_CONTINUE();
}

void
task_push(struct task *t)
{
  WDBG("Task push\n");

  /* Will add_tail to the pending tasks list */
  WQ_LOCK_PREFETCH(wq->pending.tail);

  /* Task must have an executor */
  WASSERT(t->execute);

  /* Is there an available worker right now? */
  if (SEM_TRYWAIT(&wq->available))
    return task_push_available(t);
  else
    return task_push_block(t);
}


struct io_ping_handle {
  int fd[2];
  void (*hook)(struct io_ping_handle *);
  sock *reader;
};

static int
io_ping_rx(struct birdsock *sk, uint size UNUSED)
{
  struct io_ping_handle *h = sk->data;
  while (1) {
    char buf[256];
    ssize_t sz = read(sk->fd, buf, 256);
    if (sz > 0)
      continue;
    if (sz == 0)
      break;
    if (sz < 0 && errno == EINTR)
      continue;
    if (sz < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
      break;
    wdie("No read error on io_ping (%p) shall ever happen: %m", sk);
  }
  h->hook(h);
  return 1;
}

static void
io_ping_err(struct birdsock *sk, int e)
{
  wdie("No poll error on io_ping shall ever happen, got %d on socket %p", e, sk);
}

struct io_ping_handle *
io_ping_new(void (*hook)(struct io_ping_handle *))
{
  struct io_ping_handle *h = mb_allocz(&root_pool, sizeof(struct io_ping_handle));

  h->hook = hook;

  if (pipe(h->fd) < 0)
    die("pipe: %m");

  if (fcntl(h->fd[0], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");

  if (fcntl(h->fd[1], F_SETFL, O_NONBLOCK) < 0)
    die("fcntl(O_NONBLOCK): %m");

  sock *sk = sk_new(&root_pool);
  sk->type = SK_MAGIC;
  sk->rx_hook = io_ping_rx;
  sk->err_hook = io_ping_err;
  sk->fd = h->fd[0];
  sk->data = h;

  h->reader = sk;

  if (sk_open(sk) < 0)
    die("io_ping: sk_open failed");

  return h;
}

void
io_ping(struct io_ping_handle *h)
{
  /* Write to the pipe */
  ssize_t sz = write(h->fd[1], "@", 1);

  /* Written OK. Done. */
  if (sz > 0)
    return;

  /* Interrupted. Try once more. */
  if (sz < 0 && errno == EINTR)
    return io_ping(h);

  /* Pipe is full, no further write needed. */
  if (sz < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
    return;

  /* No write error on io_ping shall ever happen. */
  wimpossible();
}

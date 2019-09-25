#undef LOCAL_DEBUG
//#define LOCAL_DEBUG
#undef DEBUG_STATELOG
#define DEBUG_STATELOG

#include "nest/bird.h"
#include "lib/macro.h"
#include "lib/worker.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "conf/conf.h"

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <pthread.h>
#include <unistd.h>

static _Atomic u64 max_worker_id = 1;
static _Thread_local u64 worker_id;

#define WDBG(x, y...) DBG("(W%4lu): " x, worker_id, ##y)
#define WQLDUMP WDBG("WQ:T%4lu|S%4lu\n", list_length(&wq->pending), wq->stop)
#define WQDUMP do { WQ_LOCKED WQLDUMP; } while (0)
#define wdie(x, y...) die("(W%4lu): " x, worker_id, ##y)
#define wbug(x, y...) bug("(W%4lu): " x, worker_id, ##y)
#define wdebug(x, y...) debug("(W%4lu): " x, worker_id, ##y)

#ifdef DEBUG_STATELOG
#define STATELOG_SIZE_ (1 << 14)
static const uint STATELOG_SIZE = STATELOG_SIZE_;
#endif

static struct worker_queue {
  sem_t waiting;		/* Workers wait on this semaphore to get work */
  sem_t stopped;		/* Posted on worker stopped */
  sem_t yield;			/* Keeps the right number of workers running */
  sem_t available;		/* How many workers are currently free */
  pthread_spinlock_t lock;	/* Lock for the following values */
  list pending;			/* Tasks pending */
  uint running;			/* How many workers are really running */
  uint workers;			/* Allowed number of concurrent workers */
  uint max_workers;		/* Maximum count of workers incl. sleeping */
  uint stop;			/* Stop requests */
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
	uint pending;
	uint running;
	uint stop;
      } queue;
      sem_t *sem;
      struct {
	uint rdsem_n, wrsem_n, rdtasks_n, wrtasks_n, rdlocked, prepended;
	struct domain *domain;
	struct task *task;
      } domain;
    };
  } statelog[STATELOG_SIZE_];
#endif
  _Atomic u64 spinlock_owner;
} wq_, *wq = &wq_;

#ifdef DEBUG_STATELOG
#define WQ_STATELOG(what_, ...) \
  wq->statelog[atomic_fetch_add(&wq->statelog_pos, 1) % STATELOG_SIZE] = \
  (struct worker_queue_state) { .what = what_, .worker_id = worker_id, __VA_ARGS__ }
#else
#define WQ_STATELOG(...)
#endif

const u64 noworker = ~0ULL;
static inline void WQ_LOCK(void)
{
  pthread_spin_lock(&(wq->lock));

  if (!atomic_compare_exchange_strong(&wq->spinlock_owner, &noworker, worker_id))
    wbug("The spinlock shall be unlocked!");

  WQ_STATELOG(WQS_LOCK,
      .queue = {
	.pending = list_length(&wq->pending),
	.running = wq->running,
	.stop = wq->stop,
      });
}

static inline void WQ_ASSERT_LOCKED(void)
{
  if (atomic_load(&wq->spinlock_owner) != worker_id)
    wbug("The spinlock shall be locked!");
}

static inline void WQ_ASSERT_UNLOCKED(void)
{
  if (atomic_load(&wq->spinlock_owner) == worker_id)
    wbug("The spinlock shan't be locked by us!");
}

static inline void WQ_UNLOCK(void)
{
  WQ_STATELOG(WQS_UNLOCK,
      .queue = {
	.pending = list_length(&wq->pending),
	.running = wq->running,
	.stop = wq->stop,
      });

  if (!atomic_compare_exchange_strong(&wq->spinlock_owner, &worker_id, noworker))
    wbug("The spinlock shall be locked!");

  pthread_spin_unlock(&(wq->lock));
}

#define WQ_LOCKED MACRO_PACK_BEFORE_AFTER(WQ_LOCK(), WQ_UNLOCK())
#define WQ_LOCKED_BOOL(...) (WQ_LOCK(), !!(__VA_ARGS__) + (WQ_UNLOCK(), 0))

static inline void SEM_INIT(sem_t *s, uint val)
{
  if (sem_init(s, 0, val) < 0)
    wbug("sem_init() failed: %m");
}

static inline void SEM_WAIT(sem_t *s)
{
  WQ_STATELOG(WQS_SEM_WAIT_REQUEST, .sem = s);
  while (sem_wait(s) < 0) {
    if (errno == EINTR)
      continue;
    wdie("sem_wait: %m");
  }

  WQ_STATELOG(WQS_SEM_WAIT_SUCCESS, .sem = s);
}

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

static inline void SEM_POST(sem_t *s)
{
  if (sem_post(s) < 0)
    wbug("sem_post: %m");

  WQ_STATELOG(WQS_SEM_POST, .sem = s);
}

static inline void SEM_DESTROY(sem_t *s)
{
  if (sem_destroy(s) < 0)
    wbug("sem_post: %m");
}

static void worker_start(void);

static _Thread_local int worker_sleeping = 1;

static inline void WORKER_YIELD(void)
{
  WQ_ASSERT_LOCKED();
  ASSERT(!worker_sleeping);
  WQ_STATELOG(WQS_YIELD);

  /* We may want to start another worker */
  if (wq->running < wq->max_workers)
  {
    /* Is it reasonable? */
    if (SEM_TRYWAIT(&wq->available))
      /* No, there is an available worker right now */
      SEM_POST(&wq->available);
    else
      /* Yes, all workers are doing something */
      worker_start();
  }

  SEM_POST(&wq->yield);
  worker_sleeping = 1;
}

static inline void WORKER_CONTINUE(void)
{
  WQ_ASSERT_UNLOCKED();
  ASSERT(worker_sleeping);
  SEM_WAIT(&wq->yield);
  worker_sleeping = 0;
  WQ_STATELOG(WQS_CONTINUE);
}

static _Thread_local struct timeloop worker_timeloop;

struct domain {
  resource r;
  sem_t rdsem;		/* Wait semaphore for readers */
  sem_t wrsem;		/* Wait semaphore for writers */
  list rdtasks;		/* Reader tasks blocked */
  list wrtasks;		/* Writer tasks blocked */
  uint rdsem_n;		/* How many secondary readers waiting */
  uint wrsem_n;		/* How many secondary writers waiting + locked */
  uint rdtasks_n;	/* How many reader tasks waiting */
  uint wrtasks_n;	/* How many writer tasks waiting + locked */
  uint rdlocked;	/* How many readers are locked */
  uint prepended;	/* How many tasks have been prepended */
  uint wrlocked:1;	/* If a writer is locked */
};

#define TASK_PREPEND(d, t) do { \
  t->flags |= TF_PREPENDED; \
  add_head(&wq->pending, &((t)->n)); \
  SEM_POST(&wq->waiting); \
  d->prepended++; \
} while (0)

#define TASK_APPEND(t) do { \
  add_tail(&wq->pending, &((t)->n)); \
  SEM_POST(&wq->waiting); \
} while (0)

#define TASK_STOP_WORKER do { \
  wq->stop++; \
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
  WQ_LOCK();
  wdebug("Locking domain: WP:%u WS:%u RP:%u RS:%u RL:%u PREP:%u WL:%u\n",
      d->wrtasks_n, d->wrsem_n, d->rdtasks_n, d->rdsem_n,
      d->rdlocked, d->prepended, d->wrlocked);
  WQ_UNLOCK();
}

static struct resclass domain_resclass = {
  .name = "Domain",
  .size = sizeof(struct domain),
  .free = domain_free,
  .dump = domain_dump,
  .lookup = NULL,
  .memsize = NULL
};

_Thread_local static struct locked_domain {
  struct domain *domain;
  int write;
} *locked_domains = NULL;
_Thread_local static uint locked_max = 0, locked_cnt = 0;

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
  WQ_STATELOG(what_, .domain = { .rdsem_n = dom->rdsem_n, .wrsem_n = dom->wrsem_n, .rdtasks_n = dom->rdtasks_n, .wrtasks_n = dom->wrtasks_n, .rdlocked = dom->rdlocked, .prepended = dom->prepended, .domain = dom, .task = task_ })


static int
domain_read_lock_primary(struct domain *d, struct task *t)
{
  domain_assert_unlocked(d);
  WDBG("Primary read lock: domain %p, task %p\n", d, t);
  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_REQUEST, d, t);
  
  WQ_LOCK();
  if (t->flags & TF_PREPENDED)
  {
    if (!d->prepended--)
      wbug("Got a pending task without pending bit set");

    if (d->wrlocked)
      wbug("Got a prepended reader task with writer locked");

    if (!d->rdlocked)
      wbug("Reader shall be already locked");

    WDBG("-> Forcibly acquiring prepended lock.\n");
/*    d->rdlocked++;  is called by the prepender */
    domain_push_lock(d, 0);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, t);
    WQ_UNLOCK();
    return 1;
  }
  else if (d->wrlocked || d->wrsem_n || d->wrtasks_n)
  {
    /* Blocked */
    add_tail(&(d->rdtasks), &(t->n));
    d->rdtasks_n++;
    WDBG("-> Blocked (n=%u)\n", d->rdtasks_n);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_BLOCKED, d, t);
    WQ_UNLOCK();
    return 0;
  }
  else
  {
    d->rdlocked++;
    domain_push_lock(d, 0);
    WDBG("-> Instantly locked (n=%u)\n", d->rdlocked);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, t);
    WQ_UNLOCK();
    return 1;
  }
}

void
domain_read_lock(struct domain *d)
{
  domain_assert_unlocked(d);
  WDBG("Secondary read lock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_REQUEST, d, NULL);

  WQ_LOCK();
  if (d->wrlocked || d->wrsem_n || d->wrtasks_n)
  {
    /* Blocked */
    d->rdsem_n++;
    WDBG("-> Blocked (n=%u)\n", d->rdsem_n);
    DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_BLOCKED, d, NULL);
    WORKER_YIELD();
    WQ_UNLOCK();

    /* Wait until somebody unblocks us.
     * That thread also locks the lock for us
     * before running SEM_POST(&d->rdsem), */
    SEM_WAIT(&d->rdsem);
    WORKER_CONTINUE();
  }
  else
  {
    d->rdlocked++;
    WDBG("-> Instantly locked (n=%u)\n", d->rdlocked);
    WQ_UNLOCK();
  }

  DOMAIN_STATLOG(WQS_DOMAIN_RDLOCK_SUCCESS, d, NULL);
  domain_push_lock(d, 0);
}

static int
domain_write_lock_primary(struct domain *d, struct task *t)
{
  domain_assert_unlocked(d);
  WDBG("Primary write lock: domain %p, task %p\n", d, t);
  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_REQUEST, d, t);

  WQ_LOCK();
  if (t->flags & TF_PREPENDED)
  {
    if (!d->prepended--)
      wbug("Got a pending task without pending bit set");

    if (d->rdlocked)
      wbug("Got a prepended writer task with reader locked");

    if (!d->wrlocked)
      wbug("Writer shall be already locked here");

    WDBG("-> Forcibly acquiring prepended lock.\n");
/*    d->wrlocked = 1;  is called by the prepender */
    domain_push_lock(d, 1);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, t);
    WQ_UNLOCK();
    return 1;
  }
  else if (d->wrlocked || d->rdlocked || d->wrtasks_n || d->wrsem_n)
  {
    /* Blocked */
    add_tail(&(d->wrtasks), &(t->n));
    d->wrtasks_n++;
    WDBG("-> Blocked (n=%u)\n", d->wrtasks_n);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_BLOCKED, d, t);
    WQ_UNLOCK();
    return 0;
  }
  else
  {
    if (d->rdtasks_n || d->rdsem_n || d->prepended)
      wbug("This shall never happen");

    d->wrlocked = 1;
    domain_push_lock(d, 1);
    WDBG("-> Instantly locked\n");
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, t);
    WQ_UNLOCK();
    return 1;
  }
}

void
domain_write_lock(struct domain *d)
{
  domain_assert_unlocked(d);
  WDBG("Secondary write lock: domain %p\n", d);
  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_REQUEST, d, NULL);

  WQ_LOCK();
  if (d->wrlocked || d->rdlocked || d->wrsem_n || d->wrtasks_n)
  {
    /* Blocked */
    d->wrsem_n++;
    WDBG("-> Blocked (n=%u)\n", d->wrsem_n);
    DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_BLOCKED, d, NULL);
    WORKER_YIELD();
    WQ_UNLOCK();

    /* Wait until somebody unblocks us.
     * That thread also locks the lock for us
     * before running SEM_POST(&d->rdsem), */
    SEM_WAIT(&d->wrsem);
    WORKER_CONTINUE();
  }
  else
  {
    if (d->rdtasks_n || d->rdsem_n || d->prepended) 
      wbug("This shall never happen");

    d->wrlocked = 1;
    WDBG("-> Instantly locked\n");
    WQ_UNLOCK();
  }

  DOMAIN_STATLOG(WQS_DOMAIN_WRLOCK_SUCCESS, d, NULL);
  domain_push_lock(d, 1);
}

static void
domain_unlock_common(struct domain *d)
{
  WQ_ASSERT_LOCKED();
  if (d->wrtasks_n)
  {
    WDBG("-> There is a writer task waiting for us (n=%u)\n", d->wrtasks_n);
    if (d->prepended || d->wrlocked)
      wbug("This shall never happen");

    /* Lock the domain now */
    d->wrlocked = 1;

    /* Get the task */
    struct task *t = HEAD(d->wrtasks);
    rem_node(&t->n);

    /* Prepend the task */
    TASK_PREPEND(d, t);

    /* Lower the wrtasks_n counter */
    d->wrtasks_n--;
  }
  else if (d->wrsem_n)
  {
    WDBG("-> There is a secondary writer waiting for us (n=%u)\n", d->wrsem_n);
    
    /* Lock the domain now */
    d->wrlocked = 1;
    
    /* Wake up that thread */
    d->wrsem_n--;
    SEM_POST(&d->wrsem);
  }
}

void
domain_read_unlock(struct domain *d)
{
  domain_assert_read_locked(d);
  WDBG("Read unlock: domain %p\n", d);

  WQ_LOCK();
  DOMAIN_STATLOG(WQS_DOMAIN_RDUNLOCK_REQUEST, d, NULL);
  if (!d->rdlocked)
    wbug("Read lock count underflow");

  d->rdlocked--;
  domain_pop_lock(d);

  if (d->rdlocked)
  {
    WDBG("-> Unlocked leaving other readers behind (n=%u)\n", d->rdlocked);
  }
  else
    domain_unlock_common(d);
  
  DOMAIN_STATLOG(WQS_DOMAIN_RDUNLOCK_DONE, d, NULL);
  WQ_UNLOCK();
}

void
domain_write_unlock(struct domain *d)
{
  domain_assert_write_locked(d);
  WDBG("Write unlock: domain %p\n", d);

  WQ_LOCK();
  DOMAIN_STATLOG(WQS_DOMAIN_WRUNLOCK_REQUEST, d, NULL);
  if (!d->wrlocked)
    wbug("Write lock already unlocked");

  d->wrlocked = 0;
  domain_pop_lock(d);

  uint w = d->wrtasks_n + d->wrsem_n;
  uint r = d->rdtasks_n + d->rdsem_n;

/* Magical condition to when we have to flush readers.
 * The rwlock has strict writer preference over readers. No reader
 * is allowed to lock when there are enough writers. This may lead
 * to a situation where two writers are blocking all readers.
 * So we sometimes flush the readers instead of locking another pending writer. */
  if (r && (!w || (r > 3*w)))
  {
    WDBG("-> Flushing readers: WP=%u WS=%u RP=%u RS=%u\n",
	d->wrtasks_n, d->wrsem_n, d->rdtasks_n, d->rdsem_n);
    /* We shall flush the readers */
    d->rdlocked = d->rdtasks_n + d->rdsem_n;

    /* Put the tasks into queue */
    uint check = 0;
    struct task *t, *tt;
    WALK_LIST_BACKWARDS_DELSAFE(t, tt, d->rdtasks)
    {
      rem_node(&t->n);
      TASK_PREPEND(d, t);
      check++;
    }

    if (check != d->rdtasks_n || !EMPTY_LIST(d->rdtasks))
      wbug("This shall never happen");

    d->rdtasks_n = 0;

    for ( ; d->rdsem_n; d->rdsem_n--)
      SEM_POST(&d->rdsem);
  }
  else
    domain_unlock_common(d);

  DOMAIN_STATLOG(WQS_DOMAIN_WRUNLOCK_DONE, d, NULL);
  WQ_UNLOCK();
}

extern _Thread_local struct timeloop *timeloop_current;

static void *
worker_loop(void *_data UNUSED)
{
  /* Overall thread initialization */
  times_init(&worker_timeloop);
  timeloop_current = &worker_timeloop;

  worker_id = atomic_fetch_add(&max_worker_id, 1);

  WDBG("Worker started\n");
  SEM_POST(&wq->available);
 
  /* Run the loop */
  while (1) {
    WDBG("Worker waiting\n");
    WQDUMP;
    SEM_WAIT(&wq->waiting);
    WDBG("Worker woken up\n");
    WORKER_CONTINUE();

    WQ_LOCK();
    WQLDUMP;
    /* Is there a pending task? */
    if (!EMPTY_LIST(wq->pending))
    {
      /* Retrieve that task */
      struct task *t = HEAD(wq->pending);
      rem_node(&t->n);
      WQ_UNLOCK();

      /* Store the old flags and domain */
      enum task_flags tf = t->flags;
      int prepended = tf & TF_PREPENDED;
      struct domain *d = t->domain;

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

      WDBG("Worker yielding\n");
      WQ_LOCKED
	WORKER_YIELD();

      /* If this task was prepended, the available semaphore was not waited for */
      if (!prepended)
      {
	WDBG("Worker available\n");
	SEM_POST(&wq->available);
      }
    }
    else
    {
      /* There must be a request to stop then */
      ASSERT(wq->stop > 0);

      /* Requested to stop */
      WDBG("Worker stopping\n");
      wq->stop--;
      wq->running--;

      /* Let others work instead of us */
      WORKER_YIELD();
      WQ_UNLOCK();

      /* This makes one worker less available */
      SEM_WAIT(&wq->available);

      /* Notify the stop requestor */
      SEM_POST(&wq->stopped);

      /* Finished */
      return NULL;
    }
  }
  
  wbug("This shall never happen");
}

static void
worker_start(void)
{
  WQ_ASSERT_LOCKED();
  ASSERT(wq->running < wq->max_workers);

  /* Run the thread */
  pthread_t id;
  int e = pthread_create(&id, NULL, worker_loop, NULL);
  if (e < 0)
  {
    if (wq->workers == 0) 
      wbug("Failed to start a worker: %M", e);
    else
      log(L_WARN "Failed to start a worker: %M", e);

    return;
  }

  /* Detach the thread; we don't want to join the threads */
  e = pthread_detach(id);
  if (e < 0)
    wbug("pthread_detach() failed: %M", e);

  wq->running++;
}

void
worker_queue_init(void)
{
  SEM_INIT(&wq->waiting, 0);
  SEM_INIT(&wq->stopped, 0);
  SEM_INIT(&wq->yield, 0);
  SEM_INIT(&wq->available, 0);

  pthread_spin_init(&wq->lock, 0);

  init_list(&wq->pending);

  atomic_store(&wq->spinlock_owner, ~0ULL);
#ifdef DEBUG_STATELOG
  atomic_store(&wq->statelog_pos, 0);
#endif

  worker_sleeping = 0;
  wq->workers = 1;
}

void
worker_queue_destroy(void)
{
  WQ_LOCK();

  /* First stop all the workers. */
  wq->max_workers = 0;
  while (wq->running)
  {
    TASK_STOP_WORKER;
    WORKER_YIELD();
    WQ_UNLOCK();
    SEM_WAIT(&wq->stopped);
    WORKER_CONTINUE();
    WQ_LOCK();
  }

  ASSERT(wq->stop == 0);

  /* Worker stops only when there is no task so now there
   * should be no task pending at all. */
  ASSERT(EMPTY_LIST(wq->pending));

  /* All the workers but one should also have yielded. The last one is us. */
  while (--wq->workers)
    ASSERT(SEM_TRYWAIT(&wq->yield));

  /* Nobody is using the queue now. Cleanup the resources. */
  SEM_DESTROY(&wq->waiting);
  SEM_DESTROY(&wq->stopped);
  SEM_DESTROY(&wq->yield);
  SEM_DESTROY(&wq->available);

  pthread_spin_destroy(&wq->lock);
}

/* Configured worker pool change */
void
worker_queue_update(const struct config *c)
{
  /* Check whether the values are sane */
  ASSERT(c->max_workers >= c->workers);
  ASSERT(c->workers > 0);

  WQ_LOCK();
  if ((c->workers == wq->workers) && (c->max_workers == wq->max_workers))
  {
    /* No change at all */
    WQ_UNLOCK();
    return;
  }

  /* Reduction of concurrent running workers */
  while (c->workers < wq->workers)
  {
    WQ_UNLOCK();
    /* Wait until a worker yields */
    SEM_WAIT(&wq->yield);
    WQ_LOCK();
    wq->workers--;
  }

  /* Set the new maximum */
  wq->max_workers = c->max_workers;

  /* Reduction of really running workers */
  while (wq->max_workers < wq->running)
  {
    TASK_STOP_WORKER;
    WQ_UNLOCK();
    SEM_WAIT(&wq->stopped);
    WQ_LOCK();
  }

  /* Increase of concurrent running workers */
  while (c->workers > wq->workers)
  {
    SEM_POST(&wq->yield);
    wq->workers++;
  }

  /* On startup, start at least one worker */
  worker_start();
  WQ_UNLOCK();
}

void
task_push(struct task *t)
{
  /* Task must have an executor */
  ASSERT(t->execute);

  WDBG("Task push\n");

  WQ_LOCK();

  /* Stopping, won't accept tasks */
  if (wq->max_workers == 0)
    return;

  /* Idempotency. */
  WQLDUMP;
  if (t->n.prev && t->n.next)
  {
    /* If already pushed, do nothing. */
    WQ_UNLOCK();
    return;
  }
  else
  {
    /* Check that the node is clean */
    ASSERT(!t->n.prev && !t->n.next);
  }

  /* Use only public flags */
  t->flags &= TF_PUBLIC_MASK;

  /* Is there an available worker right now? */
  if (SEM_TRYWAIT(&wq->available))
  {
    WDBG("Waited for an available worker succesfully\n");
    /* Then we have a task for it. */

    TASK_APPEND(t);

    /* And now we can continue freely. */
    WQ_UNLOCK();
    return;
  }
  else
  {
    /* No available worker. We're going to sleep.
     * Anyway, the task still exists in the queue. */
    TASK_APPEND(t);
    WORKER_YIELD();
    WQ_UNLOCK();

    /* Wait until somebody picks the task up */
    SEM_WAIT(&wq->available);
    WORKER_CONTINUE();
    return;
  }
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

  /* This shall not happen. */
  wdie("No write error on io_ping (%p) shall ever happen: %m", h);
}

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

static inline void SEM_INIT(sem_t *s, uint val)
{
  if (sem_init(s, 0, val) < 0)
    bug("sem_init() failed: %m");
}

static inline void SEM_WAIT(sem_t *s)
{
  while (sem_wait(s) < 0) {
    if (errno == EINTR)
      continue;
    die("sem_wait: %m");
  }
}

static inline int SEM_TRYWAIT(sem_t *s)
{
  while (sem_trywait(s) < 0) {
    if (errno == EINTR)
      continue;
    if (errno == EAGAIN)
      return 0;

    die("sem_trywait: %m");
  }

  return 1;
}

static inline void SEM_POST(sem_t *s)
{
  if (sem_post(s) < 0)
    bug("sem_post: %m");
}

#define WQ_LOCK pthread_spin_lock(&(wq->lock))
#define WQ_UNLOCK pthread_spin_unlock(&(wq->lock))
#define WQ_LOCKED MACRO_PACK_BEFORE_AFTER(WQ_LOCK, WQ_UNLOCK)

static _Thread_local struct timeloop worker_timeloop;

static struct worker_queue {
  sem_t waiting;		/* Workers wait on this semaphore to get work */
  sem_t stopped;		/* Posted on worker stopped */
  sem_t available;		/* How many workers are currently free */
  pthread_spinlock_t lock;	/* Lock for the following values */
  list pending;			/* Tasks pending */
  uint running;			/* How many workers are running */
  uint prefork;			/* Default count of workers */
  uint stop;			/* Stop requests */
} wq_, *wq = &wq_;

static int worker_start(void);

struct domain {
  resource r;
  sem_t rdsem;			/* Wait semaphore for readers */
  sem_t wrsem;			/* Wait semaphore for writers */
  _Atomic u64 state;		/* State value of rwlock */
  list blocked;			/* These tasks are blocked by the rwlock */
};

void
domain_free(resource *r)
{
  struct domain *d = SKIP_BACK(struct domain, r, r);
  sem_destroy(&d->rdsem);
  sem_destroy(&d->wrsem);
}

void
task_dump(struct task *t)
{
  debug("D:%p E:%p F:0x%x    ", t->domain, t->execute, t->flags);
}

void
domain_dump(resource *r)
{
  struct domain *d = SKIP_BACK(struct domain, r, r);
  WQ_LOCK;
  debug("Locking domain with blocked tasks: ");
  struct task *t;
  WALK_LIST(t, d->blocked)
    task_dump(t);
  debug("\n");
  WQ_UNLOCK;
}

static struct resclass domain_resclass = {
  .name = "Domain",
  .size = sizeof(struct domain),
  .free = domain_free,
  .dump = domain_dump,
  .lookup = NULL,
  .memsize = NULL
};

_Thread_local struct domain *worker_domain;
_Thread_local enum task_flags worker_task_flags;

struct domain *
domain_new(pool *p)
{
  struct domain *d = ralloc(p, &domain_resclass);

  SEM_INIT(&d->rdsem, 0);
  SEM_INIT(&d->wrsem, 0);
  atomic_store(&d->state, 0);

  init_list(&d->blocked);

  return d;
}

/*
 * The lock state consists (bitwise) of these values:
 *
 * Bits MSB to LSB:
 *  66665555 55555544 44444444 33333333 33222222 22221111 11111100 00000000
 *  32109876 54321098 76543210 98765432 10987654 32109876 54321098 76543210
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 * |BPWQwwww|wwwwwwww|wwwwwwww|bbbbbbbb|bbbbbbbb|bbbbrrrr|rrrrrrrr|rrrrrrrr|
 * +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 * bit 63: B = a blocked task is in domain queue waiting for unlock
 * bit 62: P = a pending task is in global queue waiting for a thread
 * bit 61: W = the blocked task needs a write lock
 * bit 60: Q = reserved for future use
 * bits 40-59: w..w = number of writers registered
 * bits 20-39: b..b = number of readers blocked by writers
 * bits 0-19: r..r = number of readers locked
 *
 */

#define STATE_TASK_BLOCKED	(1ULL << 63)
#define STATE_TASK_PENDING	(1ULL << 62)
#define STATE_TASK_WRITE	(1ULL << 61)
#define STATE_OFFSET		20
#define STATE_MASK		((1ULL << STATE_OFFSET) - 1)

#define STATE_READERS(s)	((s) & STATE_MASK)
#define STATE_BLOCKED(s)	((s) >> (STATE_OFFSET) & STATE_MASK)
#define STATE_WRITERS(s)	(((s) >> (STATE_OFFSET*2)) & STATE_MASK)

#define STATE_ONE_READER	1ULL
#define STATE_ONE_BLOCKED	(1ULL << STATE_OFFSET)
#define STATE_ONE_WRITER	(1ULL << (STATE_OFFSET * 2))

#define STATE_CHANGE(s)  atomic_compare_exchange_strong_explicit(&d->state, &state, (s), memory_order_acq_rel, memory_order_acquire)
  
static int
domain_read_lock_internal(struct domain *d, struct task *t)
{
  while (1)
  {
    /* Get current state */
    u64 state = atomic_load_explicit(&d->state, memory_order_acquire);

    /* Priority locking: This task has reserved the lock */
    if (t && (t->flags & TF_PREPENDED))
    {
      if (!(state & STATE_TASK_PENDING))
	bug("Got a pending task without pending bit set");

      if (state & STATE_TASK_WRITE)
	bug("Pending lock type mismatch");

      if (STATE_READERS(state) == STATE_MASK)
	bug("Too many readers");

      /* Lock read for this task and go on */
      if (STATE_CHANGE((state & ~STATE_TASK_PENDING) + STATE_ONE_READER))
	return 1;
      else
	continue;
    }

    /* There are writers, they have priority over readers */
    if (STATE_WRITERS(state) || (state & STATE_TASK_WRITE))
    {
      /* If we have to block the task */
      if (t)
      {
	WQ_LOCK;
	/* No blocked task yet? Set the bit. */
	if (!(state & STATE_TASK_BLOCKED) && !STATE_CHANGE((state | STATE_TASK_BLOCKED)))
	{
	  WQ_UNLOCK;
	  continue;
	}

	add_tail(&d->blocked, &t->n);
	WQ_UNLOCK;
	return 0;
      }

      /* We'll block ourselves */
      if (STATE_BLOCKED(state) == STATE_MASK)
	bug("Too many blocked readers");

      /* Marked that we are waiting on rdsem */
      if (!STATE_CHANGE((state + STATE_ONE_BLOCKED)))
	continue;

      /* Start another worker to work instead of us for now */
      if (!worker_start())
	bug("Failed to start a temporary worker: %m");
      SEM_WAIT(&d->rdsem);

      /* Now we have the lock, stop one thread to continue */
      WQ_LOCKED wq->stop++;
      SEM_POST(&wq->waiting);
      SEM_WAIT(&wq->stopped);

      /* Thread stopped, come on now */
      return 1;
    }

    /* There is no writer, lock for reading */
    if (!STATE_CHANGE(state + STATE_ONE_READER))
      continue;
    else
      return 1;
  }
}

void domain_read_lock(struct domain *d)
{ domain_read_lock_internal(d, NULL); }

static int
domain_write_lock_internal(struct domain *d, struct task *t)
{
  while (1)
  {
    /* Get current state */
    u64 state = atomic_load_explicit(&d->state, memory_order_acquire);

    /* Priority locking: This task has reserved the lock */
    if (t && (t->flags & TF_PREPENDED))
    {
      if (!(state & STATE_TASK_PENDING))
	bug("Got a pending task without pending bit set");

      if (!(state & STATE_TASK_WRITE))
	bug("Pending lock type mismatch");

      if (STATE_WRITERS(state) == STATE_MASK)
	bug("Too many writers");

      /* Lock write for this task and go on */
      if (STATE_CHANGE((state & ~STATE_TASK_PENDING & ~STATE_TASK_WRITE) + STATE_ONE_WRITER))
	return 1;
      else
	continue;
    }

    /* The only other possibility to get through is that the lock is completely unlocked */
    if (state == 0)
      if (STATE_CHANGE(STATE_ONE_WRITER))
	return 1;
      else
	continue;

    /* If we have to block the task */
    if (t)
    {
      WQ_LOCK;
      /* No blocked task yet? Set the bit. */
      if (!(state & STATE_TASK_BLOCKED) && !STATE_CHANGE((state | STATE_TASK_BLOCKED)))
      {
	WQ_UNLOCK;
	continue;
      }

      add_tail(&d->blocked, &t->n);
      WQ_UNLOCK;
      return 0;
    }

    /* We'll block ourselves */
    if (STATE_WRITERS(state) == STATE_MASK)
      bug("Too many blocked writers");

    /* Marked that we are waiting on wrsem */
    if (!STATE_CHANGE(state + STATE_ONE_WRITER))
      continue;

    /* Start another worker to work instead of us for now */
    if (!worker_start())
      bug("Failed to start a temporary worker: %m");
    SEM_WAIT(&d->wrsem);

    /* Now we have the lock, stop one thread to continue */
    WQ_LOCKED wq->stop++;
    SEM_POST(&wq->waiting);
    SEM_WAIT(&wq->stopped);

    /* Thread stopped, come on now */
    return 1;
  }
}

void domain_write_lock(struct domain *d)
{ domain_write_lock_internal(d, NULL); }

static void
domain_read_unlock_internal(struct domain *d)
{
  while (1)
  {
    u64 state = atomic_load_explicit(&d->state, memory_order_acquire);

    if (!STATE_READERS(state))
      bug("Can't unlock read when not locked", d);

    /* Check for priority boarding */
    if (    (state & STATE_TASK_BLOCKED)	/* There is a blocked task */
	&& !(state & STATE_TASK_PENDING)	/* No task is currently pending */
	&& (STATE_READERS(state) == 1))		/* And we are the last reader to open the lock for writing */
    {
      WQ_LOCK;
      if (HEAD(d->blocked) == TAIL(d->blocked))
      {
	/* Block the lock for the task, no other blocked task remains */
	if (!STATE_CHANGE((state - STATE_ONE_READER) & ~STATE_TASK_BLOCKED | STATE_TASK_PENDING))
	{
	  WQ_UNLOCK;
	  continue;
	}

	/* Schedule the task */
	struct task *t = HEAD(d->blocked);
	t->flags |= TF_PREPENDED;
	rem_node(&t->n);
	add_head(&wq->pending, &t->n);
	WQ_UNLOCK;

	SEM_POST(&wq->waiting);
	return;
      }
      else
      {
	/* CONTINUE HERE */



	

    if (STATE_READERS(state) == 1 
    /* Mark the state change */
    if (!STATE_CHANGE(state-1))
      continue;



    if (state < LOCK_WRITER - 1) /* Only readers */
      return;

    if ((state & LOCK_STATE_MASK) > 1) /* Not the last reader */
      return;

    if (!(state & (LOCK_STATE_MASK << WRITER_OFFSET)))
      bug("No writer pending (state 0x%lx)", state);

    /* There is at least one writer pending, wake it up */
    SEM_POST(&d->wrsem);
    return;
  }
}

static void
domain_write_unlock_internal(struct domain *d)
{
  while (1)
  {
    u64 state = atomic_load_explicit(&d->state, memory_order_acquire);

    if (state & LOCK_STATE_MASK)
      bug("Trying to unlock write when readers are running");

    u64 ws = state >> WRITER_OFFSET;
    if (!(ws & LOCK_STATE_MASK))
      bug("Not locked write");
 
    if ((ws & LOCK_STATE_MASK) > 1)
    {
      /* Another writer waiting. Pass the lock to that writer. */
      if (!atomic_compare_exchange_strong_explicit(&d->state, &state, state-LOCK_WRITER,
	    memory_order_acq_rel, memory_order_acquire))
	/* Race */
	continue;

      SEM_POST(&d->wrsem);
      return;
    }

    /* We're the last writer. */
    u64 rs = state >> READER_OFFSET;
    if (rs == 0)
    {
      /* Also no reader at all here. */
      if (atomic_compare_exchange_strong_explicit(&d->state, &state, 0,
	    memory_order_acq_rel, memory_order_acquire))
	return;
      else
	continue;
    }
    else
    {
      /* Some readers are waiting. Convert them to active locks. */
      if (!atomic_compare_exchange_strong_explicit(&d->state, &state, rs,
	    memory_order_acq_rel, memory_order_acquire))
	continue; /* Race */

      for (u64 i = 0; i<rs; i++)
	SEM_POST(&d->rdsem);
      return;
    }
  }
}

extern _Thread_local struct timeloop *timeloop_current;

static void *
worker_loop(void *_data UNUSED)
{
  /* Overall thread initialization */
  times_init(&worker_timeloop);
  timeloop_current = &worker_timeloop;

  debug("Worker started\n");
 
  /* Run the loop */
  while (1) {
    SEM_POST(&wq->available);
    SEM_WAIT(&wq->waiting);
    SEM_WAIT(&wq->available);
    
    WQ_LOCK;
    /* Is there a pending task? */
    if (!EMPTY_LIST(wq->pending))
    {
      /* Retrieve that task */
      struct task *t = HEAD(wq->pending);
      rem_node(&t->n);
      WQ_UNLOCK;

      /* Does the task need a lock? */
      if (!t->domain)
	/* No. Just run it. */
	t->execute(t);
      /* It needs a lock. Is it available? */
      else if (t->flags & TF_EXCLUSIVE ?
	    domain_write_trylock(t->domain, t) :
	    domain_read_trylock(t->domain, t))
      {
	/* Yes. Run it! */
	t->execute(t);

	/* And unlock to let others to the domain */
	t->flags & TF_EXCLUSIVE ?
	  domain_write_unlock_internal(t->domain) :
	  domain_read_unlock_internal(t->domain);
      }
      else
	/* Unavailable. The task has been stored
	 * into the blocked list and will be released
	 * when the lock is available. */
	continue;
    }
    else
    {
      /* There must be a request to stop then */
      ASSERT(wq->stop > 0);

      /* Requested to stop */
      debug("Worker stopping\n");
      wq->stop--;
      wq->running--;
      WQ_UNLOCK;

      /* Notify the stop requestor */
      SEM_POST(&wq->stopped);

      /* Finished */
      return NULL;
    }
  }
  
  bug("This shall never happen");
}

static int
worker_start(void)
{
  /* Run the thread */
  pthread_t id;
  int e = pthread_create(&id, NULL, worker_loop, NULL);
  if ((wq->prefork == 0) && (e < 0))
    bug("Failed to start a worker: %m");

  if (e < 0)
    return e;

  /* Detach the thread; we don't want to join the threads */
  e = pthread_detach(id);
  if (e < 0)
    bug("pthread_detach() failed: %m");

  WQ_LOCKED
    wq->running++;
  return 0;
}

/* Start a thread */
static void
workers_start(uint count)
{
  uint i;
  for (i=0; i<count; i++)
    if (worker_start() != 0)
      break;

  WQ_LOCKED
    wq->prefork += i;

  /* If started only partially, log a warning */
  if (i < count)
    log(L_WARN "Failed to start a worker (%u of %u): %m", i, count);
}

/* Stop a number of threads. */
static void
workers_stop(uint count)
{
  WQ_LOCKED
    wq->stop += count;

  for (uint i=0; i<count; i++)
    SEM_POST(&wq->waiting);

  for (uint i=0; i<count; i++)
    SEM_WAIT(&wq->stopped);

  WQ_LOCKED
    wq->prefork -= count;
}

void
worker_queue_init(void)
{
  SEM_INIT(&wq->waiting, 0);
  SEM_INIT(&wq->stopped, 0);

  pthread_spin_init(&wq->lock, 0);

  init_list(&wq->pending);
}

void
worker_queue_update(struct config *c)
{

  if (c->workers > wq->prefork)
    workers_start(c->workers - wq->prefork);
  else if (c->workers < wq->prefork)
    workers_stop(wq->prefork - c->workers);
  else /* c->workers == wq->prefork */
    debug("Worker count kept the same");
}

void
task_push(struct task *t)
{
  /* Task must have an executor */
  ASSERT(t->execute);

  /* Idempotency. */
  WQ_LOCK;
  if (t->n.prev && t->n.next)
  {
    /* If already pushed, do nothing. */
    WQ_UNLOCK;
    return;
  }
  else
  {
    /* Check that the node is clean */
    ASSERT(!t->n.prev && !t->n.next);
    WQ_UNLOCK;
  }

  /* Use only public */
  t->flags &= TF_PUBLIC_MASK;
  
  /* We have a pending task */
  WQ_LOCKED
    add_tail(&wq->pending, &t->n);

  /* Is there an available worker right now? */
  if (SEM_TRYWAIT(&wq->available))
  {
    /* Then we have a task for it. */
    SEM_POST(&wq->waiting);
    SEM_POST(&wq->available);
    return;
  }
  else
  {
    /* No available worker. We're going to sleep.
     * Anyway, the task still exists in the queue. */
    SEM_POST(&wq->waiting);

    /* Let's start another worker to keep the number of active workers. */
    if (worker_start() != 0)
      die("Failed to start a temporary worker: %m");

    /* Order one worker stop */
    WQ_LOCKED
      wq->stop++;
    SEM_POST(&wq->waiting);

    /* And wait until it really stops to continue */
    SEM_WAIT(&wq->stopped);
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
    die("No read error on io_ping (%p) shall ever happen: %m", sk);
  }
  h->hook(h);
  return 1;
}

static void
io_ping_err(struct birdsock *sk, int e)
{
  die("No poll error on io_ping shall ever happen, got %d on socket %p", e, sk);
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
  die("No write error on io_ping (%p) shall ever happen: %m", h);
}

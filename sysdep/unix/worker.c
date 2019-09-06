#include "nest/bird.h"
#include "lib/macro.h"
#include "lib/worker.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include "conf/conf.h"

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
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

struct domain {
  resource r;
  pthread_rwlock_t lock;
  list blocked;			/* These tasks are blocked by the rwlock */
};

void
domain_free(resource *r)
{
  struct domain *d = SKIP_BACK(struct domain, r, r);
  pthread_rwlock_destroy(&d->lock);
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

  int e = pthread_rwlock_init(&d->lock, NULL);
  if (e != 0)
    die("Domain init failed: %M", e);

  init_list(&d->blocked);

  return d;
}

static int
domain_read_trylock(struct domain *d)
{
  ASSERT(!worker_domain);
  int e = pthread_rwlock_tryrdlock(&d->lock);
  switch (e)
  {
    case 0:
      worker_domain = d;
      worker_task_flags &= ~TF_EXCLUSIVE;
      return 1;
    case EBUSY:
      return 0;
    default:
      bug("pthread_rwlock_tryrdlock() returned %m");
  }
}

static int
domain_write_trylock(struct domain *d)
{
  ASSERT(!worker_domain);
  int e = pthread_rwlock_trywrlock(&d->lock);
  switch (e)
  {
    case 0:
      worker_domain = d;
      worker_task_flags |= TF_EXCLUSIVE;
      return 1;
    case EBUSY:
      return 0;
    default:
      bug("pthread_rwlock_tryrdlock() returned %m");
  }
}

static void domain_read_unlock_internal(struct domain *d)
{
  ASSERT(worker_domain == d);
  ASSERT(!(worker_task_flags & TF_EXCLUSIVE));
  worker_domain = NULL;
  pthread_rwlock_unlock(&d->lock);
}

static void domain_write_unlock_internal(struct domain *d)
{
  ASSERT(worker_domain == d);
  ASSERT(worker_task_flags & TF_EXCLUSIVE);
  worker_domain = NULL;
  pthread_rwlock_unlock(&d->lock);
}

void
domain_read_lock(struct domain *d)
{
  while (!domain_read_trylock(d))
    worker_suspend();
}

void
domain_write_lock(struct domain *d)
{
  while (!domain_write_trylock(d))
    worker_suspend();
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
      else
	/* Yes. And is it available? */
	if (t->flags & TF_EXCLUSIVE ?
	    domain_write_trylock(t->domain) :
	    domain_read_trylock(t->domain))
	{
	  /* Yes. Run it! */
	  t->execute(t);

	  /* And unlock to let others to the domain */
	  t->flags & TF_EXCLUSIVE ?
	    domain_write_unlock_internal(t->domain) :
	    domain_read_unlock_internal(t->domain);
	}
	else
	{
	  /* Unavailable. Store this task into the blocked list */
	  WQ_LOCKED
	    if (t->flags & TF_PREPENDED)
	      add_head(&t->domain->blocked, &t->n);
	    else
	      add_tail(&t->domain->blocked, &t->n);
	}
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

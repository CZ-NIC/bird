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

struct worker_queue {
  sem_t waiting;		/* Workers wait on this semaphore to get work */
  sem_t stopped;		/* Posted on worker stopped */
  pthread_spinlock_t lock;	/* Lock for the following values */
  list pending;			/* Pending tasks */
  list sendmore;		/* Pending sendmore requests */
  int available;		/* How many workers are waiting */
  uint running;			/* How many workers are running */
  uint prefork;			/* Default count of workers */
  uint stop;			/* Stop requests */
};

extern _Thread_local struct timeloop *timeloop_current;

static void *
worker_loop(void *_wq)
{
  struct worker_queue *wq = _wq;
  
  /* Overall thread initialization */
  times_init(&worker_timeloop);
  timeloop_current = &worker_timeloop;

  debug("Worker started for worker queue %p\n", wq);
 
  /* Run the loop */
  while (1) {
    WQ_LOCK;
    wq->available++;
    WQ_UNLOCK;
    SEM_WAIT(&wq->waiting);
    
    WQ_LOCK;
    /* Is there a request to stop? */
    if (wq->stop)
    {
      wq->stop--;
      WQ_UNLOCK;
      break;
    }

    if (!EMPTY_LIST(wq->pending)) {
      /* Get first pending task out of the list */
      struct task *t = HEAD(wq->pending);
      rem_node(&t->n);
      WQ_UNLOCK;

      /* Execute the task */
      ASSERT(t->state == TS_PENDING);
      t->state = TS_INPROGRESS;
      t->receiver(t);
      t->state = TS_SENDMORE;

      /* Order more tasks */
      WQ_LOCKED add_tail(&wq->sendmore, &t->n);

      /* We have added an item into a queue */
      SEM_POST(&wq->waiting);
      continue;
    }

    if (!EMPTY_LIST(wq->sendmore)) {
      /* Get first sendmore task */
      struct task *t = HEAD(wq->sendmore);
      rem_node(&t->n);
      WQ_UNLOCK;

      /* Ask for more work */
      ASSERT(t->state == TS_SENDMORE);
      t->state = TS_SENDING;
      t->sender(t);

      continue;
    }

    WQ_UNLOCK;
  }

  /* Requested to stop */
  debug("Worker stopping\n");
  SEM_POST(&wq->stopped);
  return NULL;
}

/* Start a thread */
static int
worker_start(struct worker_queue *wq)
{
  /* Run the thread */
  pthread_t id;
  int e = pthread_create(&id, NULL, worker_loop, wq);
  if (e < 0)
    return e;

  /* Detach the thread; we don't want to join the threads */
  e = pthread_detach(id);
  if (e < 0)
    bug("pthread_detach() failed: %m");

  WQ_LOCKED wq->running++;
  return 0;
}

/* Stop a number of threads */
static void
worker_stop(struct worker_queue *wq, uint count)
{
  WQ_LOCKED wq->stop += count;

  for (uint i=0; i<count; i++)
    SEM_POST(&wq->waiting);

  for (uint i=0; i<count; i++)
    SEM_WAIT(&wq->stopped);
}

struct worker_queue *
worker_queue_new(void)
{
  struct worker_queue *wq = mb_allocz(&root_pool, sizeof(struct worker_queue));

  if (sem_init(&wq->waiting, 0, 0) < 0)
    bug("sem_init() failed: %m");
  if (sem_init(&wq->stopped, 0, 0) < 0)
    bug("sem_init() failed: %m");

  pthread_spin_init(&wq->lock, 0);

  init_list(&wq->pending);
  init_list(&wq->sendmore);

  return wq;
}

void
worker_queue_update(struct worker_queue *wq, struct config *c)
{
  while (c->workers > wq->prefork)
  {
    if (worker_start(wq) == 0)
      wq->prefork++;
    else if (wq->prefork)
      return log(L_WARN "Failed to start a worker: %m");
    else
      bug("Failed to start a worker: %m");
  }

  if (c->workers < wq->prefork)
    worker_stop(wq, wq->prefork - c->workers);
}

int
worker_push(struct worker_queue *wq, struct task *t)
{
  ASSERT(t->state == TS_DIRECT);
  ASSERT(t->sender);
  ASSERT(t->receiver);

  WQ_LOCK;
  t->state = TS_PENDING;
  add_tail(&wq->pending, &t->n);
  int direct = wq->available-- > 0;
  WQ_UNLOCK;

  SEM_POST(&wq->waiting);
  return direct;
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

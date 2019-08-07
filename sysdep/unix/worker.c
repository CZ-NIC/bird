#include "nest/bird.h"
#include "lib/worker.h"
#include "lib/timer.h"
#include "lib/socket.h"

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <unistd.h>

#define SEM_WAIT(s) do { \
  while (sem_wait(s) < 0) { \
    if (errno == EINTR) \
      continue; \
    die("sem_wait: %m"); \
  } \
} while (0)

#define SEM_POST(s) do { if (sem_post(s) < 0) bug("sem_post: %m"); } while (0)

#define WQ_LOCK pthread_mutex_lock(&worker_queue_mutex);
#define WQ_UNLOCK pthread_mutex_unlock(&worker_queue_mutex);

static pthread_mutex_t worker_queue_mutex = PTHREAD_MUTEX_INITIALIZER;

static _Thread_local struct timeloop worker_timeloop;

struct worker {
  struct worker *next;
  struct worker_queue *feed;
  pthread_t thread_id;
  volatile uint stop:1;
};

struct worker_queue {
  resource r;
  struct worker *workers;
  int (*loop)(struct worker_queue *);
  sem_t pending;
  sem_t available;
  u16 end;
  u16 begin;
  u16 total;
};

static void
worker_queue_free(struct resource *_wq)
{
  struct worker_queue *wq = SKIP_BACK(struct worker_queue, r, _wq);

  WQ_LOCK;
  for (struct worker *w = wq->workers; w; w = w->next)
    w->stop = 1;
  WQ_UNLOCK;

  /* Let the underlying workers finish their work. */
  for (struct worker *w = wq->workers; w; w = w->next)
    if (pthread_join(w->thread_id, NULL) < 0)
      log(L_WARN "pthread_join() failed: %m");

  WQ_LOCK;

  for (struct worker *w = wq->workers, *wn; w; w = wn) {
    wn = w->next;
    mb_free(w);
  }

  if (sem_destroy(&wq->pending) < 0)
    log(L_WARN "sem_destroy() failed: %m");
  if (sem_destroy(&wq->pending) < 0)
    log(L_WARN "sem_destroy() failed: %m");
  
  WQ_UNLOCK;
}

static struct resclass worker_queue_class = {
  .name = "worker queue",
  .size = sizeof(struct worker_queue),
  .free = worker_queue_free,
  .dump = NULL,
  .lookup = NULL,
  .memsize = NULL,
};

struct worker_queue *
worker_queue_new(uint len, int (*loop)(struct worker_queue *))
{
  ASSERT(len <= 0xffff);

  WQ_LOCK;

  struct worker_queue *wq = ralloc(&root_pool, &worker_queue_class);

  wq->workers = NULL;
  wq->loop = loop;

  if (sem_init(&wq->pending, 0, 0) < 0)
    bug("sem_init() failed: %m");
  if (sem_init(&wq->available, 0, len) < 0)
    bug("sem_init() failed: %m");

  wq->total = len;
  wq->begin = wq->end = 0;

  WQ_UNLOCK;

  return wq;
}

u16
worker_queue_push_lock(struct worker_queue *wq)
{
  /* Wait for an empty place in queue */
  debug("WQP: waiting for semaphore %p\n", &wq->available);
  SEM_WAIT(&wq->available);

  /* We may change this to a lockless data structure in future. */
  debug("WQP: waiting for lock\n");
  WQ_LOCK;

  /* Here is your data */
  return wq->end;
}

void
worker_queue_push_unlock(struct worker_queue *wq)
{
  /* Move the pointer */
  wq->end = (wq->end + 1) % wq->total;

  /* Unlock */
  debug("WQP: unlock\n");
  WQ_UNLOCK;

  /* Release the item for waiting processes */
  debug("WQP: semaphore post %p\n", &wq->pending);
  SEM_POST(&wq->pending);
}

u16
worker_queue_get_lock(struct worker_queue *wq)
{
  /* Wait until we have any item in queue */
  debug("WQG: waiting for semaphore %p\n", &wq->pending);
  SEM_WAIT(&wq->pending);

  debug("WQG: waiting for lock\n");
  /* We may change this to a lockless data structure in future. */
  WQ_LOCK;

  /* Here is your data */
  return wq->begin;
}

void
worker_queue_get_unlock(struct worker_queue *wq)
{
  /* Move the pointer */
  wq->begin = (wq->begin + 1) % wq->total;

  /* Unlock */
  debug("WQG: unlock\n");
  WQ_UNLOCK;

  /* Mark the field available */
  debug("WQG: semaphore post %p\n", &wq->available);
  SEM_POST(&wq->available);
}

extern _Thread_local struct timeloop *timeloop_current;

void *
worker_loop(void *data)
{
  struct worker *worker = data;
  struct worker_queue *feed = worker->feed;
  int (*loop)(struct worker_queue *) = feed->loop;
  
  /* Overall thread initialization */
  times_init(&worker_timeloop);
  timeloop_current = &worker_timeloop;

  debug("Worker started with loop: %p\n", loop);

  /* Register this thread */
  WQ_LOCK;
  worker->next = feed->workers;
  feed->workers = worker;
  WQ_UNLOCK;
  
  debug("Worker registered in the main list\n", loop);
  
  /* Run the loop */
  while (!worker->stop && loop(feed))
    debug("Worker loop done\n");

  /* Requested to stop */
  debug("Worker stoppping, waiting for join\n");
  return NULL;
}

/* Shall be called only from main thread. */
int
worker_start(struct worker_queue *feed)
{
  WQ_LOCK;
  struct worker *worker = mb_allocz(&root_pool, sizeof(struct worker));
  WQ_UNLOCK;
  worker->feed = feed;

  return pthread_create(&worker->thread_id, NULL, worker_loop, worker);
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

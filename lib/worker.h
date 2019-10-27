/*
 *	BIRD Library -- Worker threads
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_WORKER_H_
#define _BIRD_WORKER_H_

#include "lib/birdlib.h"
#include "lib/atomic.h"

struct config;

struct domain *domain_new(pool *p);
void domain_read_lock(struct domain *);
void domain_read_unlock(struct domain *);
void domain_write_lock(struct domain *);
void domain_write_unlock(struct domain *);

extern _Thread_local struct domain *worker_domain;
extern _Thread_local enum task_flags worker_task_flags;

void domain_assert_write_locked(struct domain *);
void domain_assert_read_locked(struct domain *);
void domain_assert_unlocked(struct domain *);

enum task_flags {
  /* These flags can be set by the user */
  TF_EXCLUSIVE = 0x1,		/* Lock the domain exclusively */
  TF_PUBLIC_MASK = 0xff,	/* Flags are masked by this value on task push */
  /* These flags are private for worker queue */
  TF_PREPENDED = 0x100,		/* Task is waiting for the first free worker */
} PACKED;

struct task {
  node n;				/* Init this to zero. */
  enum task_flags flags;		/* Task flags */
  atomic_flag enqueued;			/* Is in queue */
  struct domain *domain;		/* Task's primary domain */
  void (*execute)(struct task *);	/* This will be called to execute the task */
};

/* Always initialize the task by task_init() */
static inline void task_init(struct task *t, enum task_flags tf, struct domain *domain, void (*execute)(struct task *))
{
  ASSERT(execute);
  *t = (struct task) {
    .n = { },
    .flags = tf & TF_PUBLIC_MASK,
    .enqueued =	ATOMIC_FLAG_INIT,
    .domain = domain,
    .execute = execute,
  };
}

/* Sometimes it is needed to know the worker ID.
 * Don't rely on it unless you know what you are doing. */
#define NOWORKER (~((u64) 0))
extern _Thread_local u64 worker_id;

/* Initialize the worker queue. Run once and never more. */
void worker_queue_init(void);

/* Flush and cleanup the worker queue. Run only in tests. */
void worker_queue_destroy(void);

void worker_queue_init(void);

/* Update configuration for worker queue
 * @c: new config
 */
void worker_queue_update(const struct config *c);

/* Push some work to the queue.
 * @t: task to push
 *
 * The execute callback should dispose of the task.
 * May block if no worker is available to pick the task.
 */
void task_push(struct task *t);

struct io_ping_handle;
/* Init a handle for main thread wakeup. Must be run from the main thread.
 * @hook: run this when ping is received in IO (main) thread.
 *
 * Returns the io ping handle.
 */
struct io_ping_handle *io_ping_new(void (*hook)(struct io_ping_handle *));

/* Issue the ping. Run from a worker thread. */
void io_ping(struct io_ping_handle *);

#endif

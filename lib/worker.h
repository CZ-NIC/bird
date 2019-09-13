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
  TF_PREPENDED = 0x100,		/* Task is the first in domain blocked-queue */
} PACKED;

struct task {
  node n;				/* Init this to zero. */
  enum task_flags flags;		/* Task flags */
  struct domain *domain;		/* Task's primary domain */
  void (*execute)(struct task *);	/* This will be called to execute the task */
};

/* Initialize the worker queue. Run once and never more. */
void worker_queue_init(void);

/* Update configuration for worker queue
 * @c: new config
 */
void worker_queue_update(struct config *c);

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

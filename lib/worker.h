/*
 *	BIRD Library -- Worker threads
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"

struct config;

struct worker_queue;
extern struct worker_queue *main_queue;

enum task_state {
  TS_DIRECT = 0,
  TS_PENDING = 1,
  TS_INPROGRESS = 2,
  TS_SENDMORE = 3,
  TS_SENDING = 4,
} PACKED;

struct task {
  node n;				/* Init this to zero. */
  enum task_state state;		/* Init this to TS_DIRECT. */
  void (*sender)(struct task *);	/* This will be called to push more tasks */
  void (*receiver)(struct task *);	/* This will be called to execute the task */
};

/* Fixed-size worker queue. Must be run from the main thread.
 *
 * Returns the worker queue pointer.
 */
struct worker_queue *worker_queue_new(void);

/* Set the right number of workers in worker queue.
 * @wq: worker queue
 * @prefork: how many workers shall run
 */
void worker_queue_update(struct worker_queue *wq, struct config *c);

/* Push some work to the queue.
 * @wq: queue to push to
 * @t: task to push
 *
 * Returns 1 if the direct path was available and another work may be pushed,
 * otherwise 0 is returned and the t->sender callback will be called.
 *
 * Sender callback should always dispose of the task or reuse it.
 * Receiver callback should dispose of the task if its state is TS_DIRECT.
 */
int worker_push(struct worker_queue *wq, struct task *t);

struct io_ping_handle;
/* Init a handle for main thread wakeup. Must be run from the main thread.
 * @hook: run this when ping is received in IO (main) thread.
 *
 * Returns the io ping handle.
 */
struct io_ping_handle *io_ping_new(void (*hook)(struct io_ping_handle *));

/* Issue the ping. Run from a worker thread. */
void io_ping(struct io_ping_handle *);

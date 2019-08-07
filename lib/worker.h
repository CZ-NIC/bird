/*
 *	BIRD Library -- Worker threads
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"

struct worker_queue;

/* Fixed-size worker queue. Must be run from the main thread.
 * @len: size of the queue
 * @loop: task handler; return 0 to stop the worker, 1 to take another task
 *
 * Returns the worker queue pointer.
 */
struct worker_queue *worker_queue_new(uint len, int (*loop)(struct worker_queue *));

/* Start a new worker thread bound to the given worker queue.
 * Must be run from the main thread. */
int worker_start(struct worker_queue *);

/* Get the first pending work from the queue.
 * @array must be allocated by the caller to (typeof(item)[length of queue])
 * and never accessed in any other way than these two macros.
 * */
#define WORKER_QUEUE_GET(feed, array, item) do { \
  item = array[worker_queue_get_lock(feed)]; \
  worker_queue_get_unlock(feed); \
} while (0)

/* Push a work into a queue */
#define WORKER_QUEUE_PUSH(feed, array, item) do { \
  array[worker_queue_push_lock(feed)] = item; \
  worker_queue_push_unlock(feed); \
} while (0)

/* Auxiliary functions. To be used strictly in pair.
 * Use WORKER_QUEUE_GET macro. */
u16 worker_queue_get_lock(struct worker_queue *wq);
void worker_queue_get_unlock(struct worker_queue *wq);

/* Auxiliary functions. To be used strictly in pair.
 * Use WORKER_QUEUE_PUSH macro. */
u16 worker_queue_push_lock(struct worker_queue *wq);
void worker_queue_push_unlock(struct worker_queue *wq);

struct io_ping_handle;
/* Init a handle for main thread wakeup. Must be run from the main thread.
 * @hook: run this when ping is received in IO (main) thread.
 *
 * Returns the io ping handle.
 */
struct io_ping_handle *io_ping_new(void (*hook)(struct io_ping_handle *));

/* Issue the ping. Run from a worker thread. */
void io_ping(struct io_ping_handle *);

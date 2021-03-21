/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *	(c) 2020 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CORO_H_
#define _BIRD_CORO_H_

#include "lib/resource.h"

/* A completely opaque coroutine handle. */
struct coroutine;

/* Coroutines are independent threads bound to pools.
 * You request a coroutine by calling coro_run().
 * It is forbidden to free a running coroutine from outside.
 * The running coroutine must free itself by rfree() before returning.
 */
struct coroutine *coro_run(pool *, void (*entry)(void *), void *data);

/* Semaphores are handy to sleep and wake worker threads. */
struct bsem;

/* Create a semaphore. Be sure to choose such a pool that happens to be freed
 * only when the semaphore can't be waited for or posted. */
struct bsem *bsem_new(pool *);

/* Post a semaphore (wake the worker). */
void bsem_post(struct bsem *);

/* Wait for a semaphore. Never do this within a locked context. */
void bsem_wait(struct bsem *);

#endif

/*
 *	BIRD Coroutines
 *
 *	(c) 2017 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_COROUTINE_H_
#define _BIRD_COROUTINE_H_

// The structure is completely opaque, implemented by sysdep
typedef struct coroutine coroutine;

coroutine *coro_new(struct pool *pool, void (*entry_point)(void *arg), void *arg);
void coro_suspend(void);
void coro_resume(coroutine *c);

struct birdsock;
int coro_sk_read(struct birdsock *s);
void coro_sk_write(struct birdsock *s, unsigned len);

#endif

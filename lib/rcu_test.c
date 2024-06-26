/*
 *	BIRD Library -- Auto storage attribute cleanup test
 *
 *	(c) 2023 Maria Matejka <mq@jmq.cz>
 *	(c) 2023 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

#include "lib/rcu.h"
#include "lib/io-loop.h"

#include <pthread.h>

#define WRITERS		3
#define READERS		28

#define WRITER_ROUNDS	20

static struct block {
  struct block * _Atomic next;
  u64 value;
} ball[WRITERS][WRITER_ROUNDS];

static struct block *_Atomic bin;
static _Atomic uint seen = 0;

static void *
t_rcu_basic_reader(void *_ UNUSED)
{
  rcu_thread_start();

  while (atomic_load_explicit(&bin, memory_order_acquire) == NULL)
    birdloop_yield();

  atomic_fetch_add_explicit(&seen, 1, memory_order_release);

  while (atomic_load_explicit(&bin, memory_order_acquire))
  {
    rcu_read_lock();

    uint mod = 0;
    for (struct block * _Atomic *bp = &bin, *b;
	b = atomic_load_explicit(bp, memory_order_acquire);
	bp = &b->next)
    {
      uint val = b->value % WRITERS + 1;
      ASSERT_DIE(val > mod);
      mod = val;
    }

    ASSERT_DIE(mod <= WRITERS);

    rcu_read_unlock();
  }

  rcu_thread_stop();
  return NULL;
}

static _Atomic uint spinlock = 0;

static inline void
spin_lock(void)
{
  while (atomic_exchange_explicit(&spinlock, 1, memory_order_acq_rel))
    birdloop_yield();
}

static inline void
spin_unlock(void)
{
  ASSERT_DIE(atomic_exchange_explicit(&spinlock, 0, memory_order_acq_rel));
}

static void *
t_rcu_basic_writer(void *order_ptr)
{
  rcu_thread_start();

  uint order = (uintptr_t) order_ptr;
  struct block *cur = &ball[order][0];

  /* Insert the object */
  spin_lock();
  for (struct block * _Atomic *bp = &bin; bp; )
  {
    struct block *b = atomic_load_explicit(bp, memory_order_acquire);
    if (b && ((b->value % WRITERS) < order))
      bp = &b->next;
    else
    {
      ASSERT_DIE(cur->value == 0xbabababababababa);
      cur->value = order;
      atomic_store_explicit(&cur->next, b, memory_order_relaxed);
      atomic_store_explicit(bp, cur, memory_order_release);
      break;
    }
  }
  spin_unlock();

  /* Wait for readers */
  while (atomic_load_explicit(&seen, memory_order_acquire) != READERS)
    birdloop_yield();

  /* Update the object */
  for (uint i=1; i<WRITER_ROUNDS; i++)
  {
    struct block *next = &ball[order][i];
    ASSERT_DIE(next->value == 0xbabababababababa);
    next->value = order + i*WRITERS;

    spin_lock();
    bool seen = 0;
    for (struct block * _Atomic *bp = &bin, *b;
	b = atomic_load_explicit(bp, memory_order_acquire);
	bp = &b->next)
      if (b == cur)
      {
	struct block *link = atomic_load_explicit(&b->next, memory_order_relaxed);
	atomic_store_explicit(&next->next, link, memory_order_relaxed);
	atomic_store_explicit(bp, next, memory_order_release);
	seen = 1;
	break;
      }
    ASSERT_DIE(seen);
    spin_unlock();

    synchronize_rcu();

    ASSERT_DIE(cur->value + WRITERS == next->value);
    cur->value = 0xd4d4d4d4d4d4d4d4;
    atomic_store_explicit(&cur->next, ((void *) 0xd8d8d8d8d8d8d8d8), memory_order_relaxed);

    cur = next;
  }

  /* Remove the object */
  spin_lock();
  bool seen = 0;
  for (struct block * _Atomic *bp = &bin, *b;
      b = atomic_load_explicit(bp, memory_order_acquire);
      bp = &b->next)
    if (b == cur)
    {
      struct block *link = atomic_load_explicit(&b->next, memory_order_relaxed);
      atomic_store_explicit(bp, link, memory_order_relaxed);
      seen = 1;
      break;
    }
  ASSERT_DIE(seen);
  spin_unlock();

  synchronize_rcu();

  cur->value = 0xd4d4d4d4d4d4d4d4;
  atomic_store_explicit(&cur->next, ((void *) 0xd8d8d8d8d8d8d8d8), memory_order_relaxed);

  rcu_thread_stop();
  return NULL;
}

static int
t_rcu_basic(void)
{
  memset(ball, 0xba, sizeof ball);

  pthread_t readers[READERS];
  pthread_t writers[WRITERS];

  for (uint i=0; i<READERS; i++)
    pthread_create(&readers[i], NULL, t_rcu_basic_reader, NULL);

  for (uintptr_t i=0; i<WRITERS; i++)
    pthread_create(&writers[i], NULL, t_rcu_basic_writer, (void *) i);

  for (uintptr_t i=0; i<WRITERS; i++)
    pthread_join(writers[i], NULL);

  for (uintptr_t i=0; i<READERS; i++)
    pthread_join(readers[i], NULL);

  for (uint w = 0; w < WRITERS; w++)
    for (uint r = 0; r < WRITER_ROUNDS; r++)
    {
      ASSERT_DIE(ball[w][r].value == 0xd4d4d4d4d4d4d4d4);
      ASSERT_DIE(atomic_load_explicit(&ball[w][r].next, memory_order_relaxed) == (void *) 0xd8d8d8d8d8d8d8d8);
    }

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);

  bt_test_suite(t_rcu_basic, "Basic RCU check");

  return bt_exit_value();
}

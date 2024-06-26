#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/locking.h"
#include <stdatomic.h>
#include <pthread.h>

#define FOO_PUBLIC \
  const char *name;	\
  _Atomic uint counter;	\
  DOMAIN(proto) lock;	\

struct foo_private {
  struct { FOO_PUBLIC; };
  struct foo_private **locked_at;
  uint private_counter;
};

typedef union foo {
  struct { FOO_PUBLIC; };
  struct foo_private priv;
} foo;

LOBJ_UNLOCK_CLEANUP(foo, proto);
#define FOO_LOCK(_foo, _fpp)	LOBJ_LOCK(_foo, _fpp, foo, proto)
#define FOO_LOCKED(_foo, _fpp)	LOBJ_LOCKED(_foo, _fpp, foo, proto)
#define FOO_IS_LOCKED(_foo)	LOBJ_IS_LOCKED(_foo, proto)

static uint
inc_public(foo *f)
{
  return atomic_fetch_add_explicit(&f->counter, 1, memory_order_relaxed) + 1;
}

static uint
inc_private(foo *f)
{
  FOO_LOCKED(f, fp) return ++fp->private_counter;
  bug("Returning always");
}

#define BLOCKCOUNT  4096
#define THREADS	    16
#define REPEATS	    128

static void *
thread_run(void *_foo)
{
  foo *f = _foo;

  for (int i=0; i<REPEATS; i++)
    if (i % 2)
      for (int j=0; j<BLOCKCOUNT; j++)
	inc_public(f);
    else
      for (int j=0; j<BLOCKCOUNT; j++)
	inc_private(f);

  return NULL;
}

static int
t_locking(void)
{
  pthread_t thr[THREADS];
  foo f = { .lock = DOMAIN_NEW(proto), };

  for (int i=0; i<THREADS; i++)
    bt_assert(pthread_create(&thr[i], NULL, thread_run, &f) == 0);

  for (int i=0; i<THREADS; i++)
    bt_assert(pthread_join(thr[i], NULL) == 0);

  bt_assert(f.priv.private_counter == atomic_load_explicit(&f.counter, memory_order_relaxed));
  bt_assert(f.priv.private_counter == THREADS * BLOCKCOUNT * REPEATS / 2);

  return 1;
}

#define RWS_DATASIZE	333
#define RWS_THREADS	128

struct rws_test_data {
  int data[RWS_DATASIZE];
  rw_spinlock rws[RWS_DATASIZE];
};

static void *
rwspin_thread_run(void *_rtd)
{
  struct rws_test_data *d = _rtd;

  for (bool sorted = 0; !sorted++; )
  {
    for (int i=0; (i<RWS_DATASIZE-1) && sorted; i++)
    {
      rws_read_lock(&d->rws[i]);
      rws_read_lock(&d->rws[i+1]);

      ASSERT_DIE(d->data[i] >= 0);
      ASSERT_DIE(d->data[i+1] >= 0);
      if (d->data[i] > d->data[i+1])
	sorted = 0;

      rws_read_unlock(&d->rws[i+1]);
      rws_read_unlock(&d->rws[i]);
    }

    for (int i=0; (i<RWS_DATASIZE-1); i++)
    {
      rws_write_lock(&d->rws[i]);
      rws_write_lock(&d->rws[i+1]);

      int first = d->data[i];
      int second = d->data[i+1];

      ASSERT_DIE(first >= 0);
      ASSERT_DIE(second >= 0);

      d->data[i] = d->data[i+1] = -1;

      if (first > second)
      {
	d->data[i] = second;
	d->data[i+1] = first;
      }
      else
      {
	d->data[i] = first;
	d->data[i+1] = second;
      }

      rws_write_unlock(&d->rws[i+1]);
      rws_write_unlock(&d->rws[i]);
    }
  }

  return NULL;
}

static int
t_rwspin(void)
{
  struct rws_test_data d;

  /* Setup an array to sort */
  for (int i=0; i<RWS_DATASIZE; i++)
    d.data[i] = RWS_DATASIZE-i-1;

  /* Spinlock for every place */
  for (int i=0; i<RWS_DATASIZE; i++)
    rws_init(&d.rws[i]);

  /* Start the threads */
  pthread_t thr[RWS_THREADS];
  for (int i=0; i<RWS_THREADS; i++)
    bt_assert(pthread_create(&thr[i], NULL, rwspin_thread_run, &d) == 0);

  /* Wait for the threads */
  for (int i=0; i<RWS_THREADS; i++)
    bt_assert(pthread_join(thr[i], NULL) == 0);

  for (int i=0; i<RWS_DATASIZE; i++)
    bt_assert(d.data[i] == i);

  return 1;
}


int
main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_locking, "Testing locks");
  bt_test_suite(t_rwspin, "Testing rw spinlock");

  return bt_exit_value();
}

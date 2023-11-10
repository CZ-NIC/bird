#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/locking.h"
#include <stdatomic.h>
#include <pthread.h>

DEFINE_DOMAIN(proto);

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

int
main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();

  bt_test_suite(t_locking, "Testing locks");

  return bt_exit_value();
}

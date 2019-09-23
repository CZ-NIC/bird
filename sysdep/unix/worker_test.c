#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define TEST_MAX (1 << 16)

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/worker.h"
#include "conf/conf.h"

#include <stdatomic.h>

struct t_rwlock_task {
  struct task task;
  struct domain *domain;
  enum { T_READ, T_WRITE } howtolock;
  _Atomic uint *total_counter;
  _Atomic uint *sink;
  _Atomic uint *allocated;
};

static void t_rwlock_execute(struct task *task)
{
  struct t_rwlock_task *t = SKIP_BACK(struct t_rwlock_task, task, task);
  switch (t->howtolock) {
    case T_READ: domain_read_lock(t->domain);
		 break;
    case T_WRITE: domain_write_lock(t->domain);
  }

  uint tot = atomic_fetch_add(t->total_counter, 1);

  /* Spin for some time to mimic some reasonable work */
  for (int i=0; i<4096; i++)
    tot += i;

  atomic_store(t->sink, tot);

  switch (t->howtolock) {
    case T_READ: domain_read_unlock(t->domain);
		 break;
    case T_WRITE: domain_write_unlock(t->domain);
  }

  bt_info("Total counter: %u\n", tot);
  uint prev = atomic_fetch_sub(t->allocated, 1);
  bt_info("Prev allocated: %u\n", prev);
  xfree(t);
}

struct t_rwlock_class {
  uint workers, max_workers;
  uint readers, writers;
};

static int
t_rwlock(const void *data_)
{
  const struct t_rwlock_class *class = data_;
  const struct config conf = {
    .workers = class->workers,
    .max_workers = class->max_workers,
  };

  worker_queue_init();
  worker_queue_update(&conf);

  struct domain *domain = domain_new(&root_pool);
  _Atomic uint total_counter = 0;
  _Atomic uint allocated = 0;
  _Atomic uint sink;
  for (int i=0; i<TEST_MAX; i++)
  {
    int write = (i % (class->readers + class->writers) >= class->readers);

    atomic_fetch_add(&allocated, 1);
    struct t_rwlock_task *t = xmalloc(sizeof(struct t_rwlock_task));
    *t = (struct t_rwlock_task) {
      .task = {
	.execute = t_rwlock_execute,
      },
      .domain = domain,
      .total_counter = &total_counter,
      .allocated = &allocated,
      .sink = &sink,
      .howtolock = write ? T_WRITE : T_READ,
    };
    bt_info("Task pushed (before)\n");
    task_push(&t->task);
    bt_info("Task pushed (after)\n");
  }

  worker_queue_destroy();
  rfree(domain);

  bt_assert(atomic_load(&total_counter) == TEST_MAX);
  bt_assert(atomic_load(&allocated) == 0);

  bt_info("Returning 1\n");
  return 1;
}

int main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

#define TEST(workers_, max_workers_, readers_, writers_) \
  do { \
    struct t_rwlock_class class = { \
      .workers = workers_, .max_workers = max_workers_, \
      .readers = readers_, .writers = writers_, \
    }; \
    bt_test_suite_base(t_rwlock, "t_rwlock workers=" #workers_ " max_workers=" #max_workers_ \
       " readers=" #readers_ " writers=" #writers_, &class, BT_FORKING, BT_TIMEOUT, "t_rwlock"); \
  } while (0)

  TEST(1, 1, 1, 0);
  TEST(1, 1, 0, 1);
  TEST(1, 5, 1, 0);
  TEST(1, 5, 0, 1);
  TEST(2, 2, 1, 0);
  TEST(2, 2, 0, 1);
  TEST(2, 2, 1, 1);
  TEST(2, 8, 1, 7);
  TEST(2, 8, 7, 1);
  TEST(8, 16, 1, 0);
  TEST(8, 16, 0, 1);

  TEST(8, 16, 1, 1);
  TEST(8, 16, 1, 7);
  TEST(8, 16, 7, 1);

  return bt_exit_value();
}


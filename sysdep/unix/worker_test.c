#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/worker.h"
#include "lib/atomic.h"
#include "conf/conf.h"

#ifdef DEBUGGING
#define TEST_MAX (1 << 16)
#else
#define TEST_MAX (1 << 12)
#endif

struct t_rwlock_task {
  struct task task;
  struct domain *domain;
  enum { T_READ, T_WRITE } howtolock;
  _Atomic uint *total_counter;
  _Atomic uint *allocated;
  uint sink;
  uint frobnicator[42];
};

static void t_rwlock_execute(struct task *task)
{
  struct t_rwlock_task *t = SKIP_BACK(struct t_rwlock_task, task, task);

  if (t->domain)
    switch (t->howtolock) {
      case T_READ: domain_read_lock(t->domain);
		   break;
      case T_WRITE: domain_write_lock(t->domain);
    }

  uint tot = atomic_fetch_add(t->total_counter, 1);

  /* Spin for some time to mimic some reasonable work */
  for (uint i=0; i<42; i++)
    t->frobnicator[i] = (i+1) * (2*i + 1) * 3535353559;

  for (uint i=0; i<42; i++)
    for (uint j=0; j<42; j++)
      t->sink += (t->frobnicator[i] ^= -t->frobnicator[j]) * 3535353559;

  if (t->domain)
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
  uint workers, max_workers, queue_size;
  uint rp, wp, rs, ws;
};

static int
t_rwlock(const void *data_)
{
  const struct t_rwlock_class *class = data_;
  const struct config conf = {
    .workers = class->workers,
    .max_workers = class->max_workers,
    .queue_size = class->queue_size,
  };

  worker_queue_init();
  worker_queue_update(&conf);

  struct domain *domain = domain_new(&root_pool);
  _Atomic uint total_counter = 0;
  _Atomic uint allocated = 0;
  uint ws = class->ws;
  uint rs = ws + class->rs;
  uint wp = rs + class->wp;
  uint rp = wp + class->rp;

  for (uint i=0; i<TEST_MAX; i++)
  {
    atomic_fetch_add(&allocated, 1);
    struct t_rwlock_task *t = xmalloc(sizeof(struct t_rwlock_task));

    uint pivot = ((i*1234568579) % rp);
    uint primary = pivot >= rs;
    uint write = (pivot < ws) || (primary && pivot < wp);

    *t = (struct t_rwlock_task) {
      .task = {
	.execute = t_rwlock_execute,
	.domain = primary ? domain : NULL,
	.flags = write ? TF_EXCLUSIVE : 0,
      },
      .domain = primary ? NULL : domain,
      .total_counter = &total_counter,
      .allocated = &allocated,
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

#ifdef SPINLOCK_STATS
extern _Atomic u64 spin_max;
extern _Atomic u64 spin_stats[65536];
extern _Atomic u64 wql_max, wql_sum, wql_cnt;
#endif

int main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

#define TEST(workers_, max_workers_, rp_, wp_, rs_, ws_) \
  do { \
    TESTQ(workers_, max_workers_, 64, rp_, wp_, rs_, ws_); \
  } while (0)

#define TESTQ(workers_, max_workers_, queue_size_, rp_, wp_, rs_, ws_) \
  do { \
    struct t_rwlock_class class = { \
      .workers = workers_, .max_workers = max_workers_, \
      .queue_size = queue_size_, \
      .rs = rs_, .ws = ws_, .wp = wp_, .rp = rp_, \
    }; \
    bt_test_suite_base(t_rwlock, "t_rwlock workers=" #workers_ " max_workers=" #max_workers_ \
       " queue_size=" #queue_size_ \
       " rp=" #rp_ " wp=" #wp_ " rs=" #rs_ " ws=" #ws_, \
       &class, BT_FORKING, BT_TIMEOUT, "t_rwlock"); \
  } while (0)

#define TEST_ALL_ONES(workers_, max_workers_) \
  do { \
    TEST(workers_, max_workers_, 1, 0, 0, 0); \
    TEST(workers_, max_workers_, 0, 1, 0, 0); \
    TEST(workers_, max_workers_, 0, 0, 1, 0); \
    TEST(workers_, max_workers_, 0, 0, 0, 1); \
    TEST(workers_, max_workers_, 1, 1, 0, 0); \
    TEST(workers_, max_workers_, 0, 1, 1, 0); \
    TEST(workers_, max_workers_, 0, 0, 1, 1); \
    TEST(workers_, max_workers_, 1, 0, 0, 1); \
    TEST(workers_, max_workers_, 0, 1, 0, 1); \
    TEST(workers_, max_workers_, 1, 0, 1, 0); \
    TEST(workers_, max_workers_, 0, 1, 1, 1); \
    TEST(workers_, max_workers_, 1, 0, 1, 1); \
    TEST(workers_, max_workers_, 1, 1, 0, 1); \
    TEST(workers_, max_workers_, 1, 1, 1, 0); \
    TEST(workers_, max_workers_, 1, 1, 1, 1); \
  } while (0)

  TEST_ALL_ONES(1, 1);
  TEST_ALL_ONES(1, 5);
  TEST_ALL_ONES(2, 2);
  TEST_ALL_ONES(2, 8);
  TEST_ALL_ONES(4, 4);
  TEST_ALL_ONES(4, 6);
  TEST_ALL_ONES(4, 8);
  TEST_ALL_ONES(4, 16);
  TEST_ALL_ONES(4, 32);

#ifdef SPINLOCK_STATS
  printf("spin_max %lu\n", atomic_load(&spin_max));
  for (uint i=0; i<sizeof(spin_stats)/sizeof(spin_stats[0]); i++)
    printf("spin_stats[%u] = %lu\n", i, atomic_load(&spin_stats[i]));

  printf("wql max %lu avg %lf cnt %lu\n",
      atomic_load(&wql_max),
      atomic_load(&wql_sum)/((double) atomic_load(&wql_cnt)),
      atomic_load(&wql_cnt));
#endif

  return bt_exit_value();
}


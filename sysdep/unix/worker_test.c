#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define TEST_MAX (1 << 12)
#define THREAD_NUM  11

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/worker.h"
#include "conf/conf.h"

#include <stdatomic.h>

struct t_rwlock_task_read {
  struct task task;
  struct domain *domain;
  _Atomic uint *total_counter;
  _Atomic uint *allocated;
};

struct t_rwlock_task_write {
  struct task task;
  struct domain *domain;
  uint *total_counter;
  _Atomic uint *allocated;
};

static void t_rwlock_execute_write(struct task *task)
{
  struct t_rwlock_task_write *t = SKIP_BACK(struct t_rwlock_task_write, task, task);
  domain_write_lock(t->domain);
  uint tot = (*t->total_counter)++;
  domain_write_unlock(t->domain);
  bt_info("Total counter: %u\n", tot);
  uint prev = atomic_fetch_sub(t->allocated, 1);
  bt_info("Prev allocated: %u\n", prev);
  xfree(t);
}

static void t_rwlock_execute_read(struct task *task)
{
  struct t_rwlock_task_read *t = SKIP_BACK(struct t_rwlock_task_read, task, task);
  domain_read_lock(t->domain);
  uint tot = atomic_fetch_add(t->total_counter, 1);
  bt_info("Total counter: %u\n", tot);
  uint prev = atomic_fetch_sub(t->allocated, 1);
  bt_info("Prev allocated: %u\n", prev);
  domain_read_unlock(t->domain);
  xfree(t);
}

static int
t_rwlock_write(const void *data_)
{
  const struct config *conf = data_;

  worker_queue_init();
  worker_queue_update(conf);

  struct domain *domain = domain_new(&root_pool);

  uint total_counter = 0;
  _Atomic uint allocated = 0;
  for (int i=0; i<TEST_MAX; i++)
  {
    atomic_fetch_add(&allocated, 1);
    struct t_rwlock_task_write *t = xmalloc(sizeof(struct t_rwlock_task_write));
    *t = (struct t_rwlock_task_write) {
      .task = {
	.execute = t_rwlock_execute_write,
      },
      .domain = domain,
      .total_counter = &total_counter,
      .allocated = &allocated,
    };
    bt_info("Task pushed (before)\n");
    task_push(&t->task);
    bt_info("Task pushed (after)\n");
  }

  worker_queue_destroy();
  rfree(domain);

  bt_assert(total_counter == TEST_MAX);
  bt_assert(atomic_load(&allocated) == 0);

  bt_info("Returning 1\n");
  return 1;
}

static int
t_rwlock_read(const void *data_)
{
  const struct config *conf = data_;

  worker_queue_init();
  worker_queue_update(conf);

  struct domain *domain = domain_new(&root_pool);
  _Atomic uint total_counter = 0;
  _Atomic uint allocated = 0;
  for (int i=0; i<TEST_MAX; i++)
  {
    atomic_fetch_add(&allocated, 1);
    struct t_rwlock_task_read *t = xmalloc(sizeof(struct t_rwlock_task_read));
    *t = (struct t_rwlock_task_read) {
      .task = {
	.execute = t_rwlock_execute_read,
      },
      .domain = domain,
      .total_counter = &total_counter,
      .allocated = &allocated,
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

  struct config conf;

  conf.workers = 1; conf.max_workers = 1;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 1/1 worker");
  bt_test_suite_arg(t_rwlock_write, &conf, "rwlock concurrent write with 1/1 worker");

  conf.workers = 1; conf.max_workers = 5;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 1/5 worker");
  bt_test_suite_arg(t_rwlock_write, &conf, "rwlock concurrent write with 1/5 worker");

  conf.workers = 2; conf.max_workers = 2;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 2/2 workers");
  bt_test_suite_arg(t_rwlock_write, &conf, "rwlock concurrent write with 2/2 worker");

  conf.workers = 2; conf.max_workers = 42;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 2/42 workers");
  bt_test_suite_arg(t_rwlock_write, &conf, "rwlock concurrent write with 2/42 worker");

  conf.workers = THREAD_NUM; conf.max_workers = THREAD_NUM * 2;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with %u/%u workers", THREAD_NUM, THREAD_NUM * 2);
  bt_test_suite_arg(t_rwlock_write, &conf, "rwlock concurrent write with %u/%u workers", THREAD_NUM, THREAD_NUM * 2);

  return bt_exit_value();
}


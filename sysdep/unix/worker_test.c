#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#define TEST_MAX (1 << 20)
//#define THREAD_NUM  42
#define THREAD_NUM  4

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "lib/worker.h"
#include "conf/conf.h"

#include <stdatomic.h>

struct t_rwlock_task {
  struct task task;
  struct domain *domain;
  _Atomic uint *total_counter;
  _Atomic uint *allocated;
};

static void t_rwlock_execute(struct task *task)
{
  struct t_rwlock_task *t = SKIP_BACK(struct t_rwlock_task, task, task);
  domain_read_lock(t->domain);
  uint tot = atomic_fetch_add(t->total_counter, 1);
  bt_info("Total counter: %u\n", tot);
  uint prev = atomic_fetch_sub(t->allocated, 1);
  bt_info("Prev allocated: %u\n", prev);
  domain_read_unlock(t->domain);
  xfree(t);
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
    struct t_rwlock_task *t = xmalloc(sizeof(struct t_rwlock_task));
    *t = (struct t_rwlock_task) {
      .task = {
	.execute = t_rwlock_execute,
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

  bt_info("Returning 1\n");
  return 1;
}

int main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_bird_init();

  struct config conf;

  conf.workers = 1;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 1 worker");

  conf.workers = 2;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with 2 workers");

  conf.workers = THREAD_NUM;
  bt_test_suite_arg(t_rwlock_read, &conf, "rwlock concurrent read with %u workers", THREAD_NUM);

  return bt_exit_value();
}


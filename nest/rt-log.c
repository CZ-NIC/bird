/*
 *	BIRD -- Routing Table Live Logging
 *
 *	(c) 2025       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "sysdep/unix/unix.h"

struct rt_log_item {
  u32 where;
  u32 thread_id;
  u32 tab_id;
  u32 netindex;
  union {
    struct rt_import_request *ireq;
    struct rt_export_request *ereq;
  };
  u32 new_id, old_id;
};

static struct rt_log_item * _Atomic rt_log_block;
static _Atomic u64 rt_log_next_item, rt_log_modulo;
static struct rfile *rt_log_rfile;

extern pool *rt_table_pool;

static struct rt_log_item *
rt_log_prepare(void)
{
  rcu_read_lock();

  struct rt_log_item *block = atomic_load_explicit(&rt_log_block, memory_order_acquire);
  u64 modulo = atomic_load_explicit(&rt_log_modulo, memory_order_acquire);
  if (block && modulo)
  {
    u64 index = atomic_fetch_add_explicit(&rt_log_next_item, 1, memory_order_acq_rel);
    if (!(index % (modulo / 4)))
      log(L_INFO "Rtable binary log index: %lu (modulo %lu)", index, modulo);

    return &block[index % modulo];
  }
  else
  {
    rcu_read_unlock();
    return NULL;
  }
}

static void
rt_log_commit(void)
{
  rcu_read_unlock();
}

void
rt_log_open(const char *name, off_t size)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  rt_log_close();

  rt_log_rfile = rf_open(rt_table_pool, name, RF_FIXED, size);
  if (!rt_log_rfile)
  {
    log(L_ERR "Failed to open rtable binary log of size %zu at %s: %m", size, name);
    return;
  }

  atomic_exchange_explicit(&rt_log_modulo, (size / sizeof (struct rt_log_item)), memory_order_release);
  atomic_exchange_explicit(&rt_log_block, rf_mapping(rt_log_rfile), memory_order_release);

  synchronize_rcu();
}

void
rt_log_close(void)
{
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  if (!rt_log_rfile)
    return;

  ASSERT_DIE(rf_mapping(rt_log_rfile) == atomic_exchange_explicit(&rt_log_block, NULL, memory_order_acq_rel));
  atomic_store_explicit(&rt_log_modulo, 0, memory_order_release);

  synchronize_rcu();

  atomic_store_explicit(&rt_log_next_item, 0, memory_order_release);

  rfree(rt_log_rfile);
  rt_log_rfile = NULL;
}


#define RT_LOG_PUT(...)				\
  struct rt_log_item *item = rt_log_prepare();	\
  if (!item) return;				\
  *item = (struct rt_log_item) {		\
    .thread_id = THIS_THREAD_ID,		\
    .netindex = NET_TO_INDEX((new ?: old)->net)->index,	\
    .new_id = new ? new->id : 0,		\
    .old_id = old ? old->id : 0,		\
    .where = magic,				\
    __VA_ARGS__					\
  };						\
  rt_log_commit();				\

void
rt_log_import(struct rt_import_request *req, const rte *new, const rte *old, u32 magic)
{
  RT_LOG_PUT(
      .ireq = req,
      .tab_id = req->hook->table->id,
      );
}

void
rt_log_export_channel(struct channel *c, const rte *new, const rte *old, u32 magic)
{
  RT_LOG_PUT(
      .ereq = &c->out_req,
      .tab_id = c->table->id,
      );
}

/*
 *	CLI: Show threads
 */

#include "nest/bird.h"

#include "lib/io-loop.h"
#include "sysdep/unix/io-loop.h"
#include "nest/cli.h"
#include "conf/conf.h"


struct bird_thread_show_data {
  struct bird_thread_syncer sync;
  cli *cli;
  linpool *lp;
  u8 show_loops;
  uint line_pos;
  uint line_max;
  const char **lines;
};

#define tsd_append(...)		do { \
  if (!tsd->lines) \
    tsd->lines = mb_allocz(tsd->sync.pool, sizeof(const char *) * tsd->line_max); \
  if (tsd->line_pos >= tsd->line_max) \
    tsd->lines = mb_realloc(tsd->lines, sizeof (const char *) * (tsd->line_max *= 2)); \
  tsd->lines[tsd->line_pos++] = lp_sprintf(tsd->lp, __VA_ARGS__); \
} while (0)

static void
bird_thread_show_cli_cont(struct cli *c UNUSED)
{
  /* Explicitly do nothing to prevent CLI from trying to parse another command. */
}

static bool
bird_thread_show_cli_cleanup(struct cli *c UNUSED)
{
  /* Defer the cleanup until the writeout is finished. */
  return false;
}

static void
bird_thread_show_spent_time(struct bird_thread_show_data *tsd, const char *name, struct spent_time *st)
{
  char b[TIME_BY_SEC_SIZE * sizeof("1234567890, ")], *bptr = b, *bend = b + sizeof(b);
  uint cs = CURRENT_SEC;
  uint fs = NSEC_TO_SEC(st->last_written_ns);

  for (uint i = 0; i <= cs && i < TIME_BY_SEC_SIZE; i++)
    bptr += bsnprintf(bptr, bend - bptr, "% 10lu ",
	(cs - i > fs) ? 0 : st->by_sec_ns[(cs - i) % TIME_BY_SEC_SIZE]);
  bptr[-1] = 0; /* Drop the trailing space */

  tsd_append("    %s total time: % 9t s; last %d secs [ns]: %s", name, st->total_ns NS, MIN(CURRENT_SEC+1, TIME_BY_SEC_SIZE), b);
}

static void
bird_thread_show_loop(struct bird_thread_show_data *tsd, struct birdloop *loop)
{
  tsd_append("  Loop %s", domain_name(loop->time.domain));
  bird_thread_show_spent_time(tsd, "Working ", &loop->working);
  bird_thread_show_spent_time(tsd, "Locking ", &loop->locking);
}

static void
bird_thread_show(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_thread_show_data, tsd, sync, sync);

  if (!tsd->lp)
    tsd->lp = lp_new(tsd->sync.pool);

  if (tsd->show_loops)
    tsd_append("Thread %04x %s (busy counter %d)", THIS_THREAD_ID, this_thread->busy_active ? " [busy]" : "", this_thread->busy_counter);

  u64 total_time_ns = 0;
  struct birdloop *loop;
  WALK_LIST(loop, this_thread->loops)
  {
    if (tsd->show_loops)
      bird_thread_show_loop(tsd, loop);

    total_time_ns += loop->working.total_ns + loop->locking.total_ns;
  }

  if (tsd->show_loops)
  {
    tsd_append("  Total working time: %t", total_time_ns NS);
    bird_thread_show_spent_time(tsd, "Overhead", &this_thread->overhead);
    bird_thread_show_spent_time(tsd, "Idle    ", &this_thread->idle);
  }
  else
    tsd_append("%04x%s     % 9.3t s   % 9.3t s   % 9.3t s",
	THIS_THREAD_ID, this_thread->busy_active ? " [busy]" : "       ",
	total_time_ns NS, this_thread->overhead.total_ns NS,
	(ns_now() - this_thread->meta->last_transition_ns) NS);
}

static void
cmd_show_threads_done(struct bird_thread_syncer *sync)
{
  SKIP_BACK_DECLARE(struct bird_thread_show_data, tsd, sync, sync);
  ASSERT_DIE(birdloop_inside(&main_birdloop));

  /* The client lost their patience and dropped the session early. */
  if (!tsd->cli->sock)
  {
    mb_free(tsd);
    rp_free(tsd->cli->pool);
    return;
  }

  tsd->cli->cont = NULL;
  tsd->cli->cleanup = NULL;

  for (int i=0; i<2; i++)
  {
    struct birdloop_pickup_group *group = &pickup_groups[i];

    LOCK_DOMAIN(attrs, group->domain);
    uint count = 0;
    u64 total_time_ns = 0;
    if (!EMPTY_LIST(group->loops))
    {
      if (tsd->show_loops)
	tsd_append("Unassigned loops in group %d:", i);

      struct birdloop *loop;
      WALK_LIST(loop, group->loops)
      {
	if (tsd->show_loops)
	  bird_thread_show_loop(tsd, loop);

	total_time_ns += loop->working.total_ns + loop->locking.total_ns;
	count++;
      }

      if (tsd->show_loops)
	tsd_append("  Total working time: %t", total_time_ns NS);
      else
	tsd_append("Unassigned %d loops in group %d, total time %t", count, i, total_time_ns NS);
    }
    else
      tsd_append("All loops in group %d are assigned.", i);

    UNLOCK_DOMAIN(attrs, group->domain);
  }

  if (!tsd->show_loops)
    cli_printf(tsd->cli, -1027, "Thread ID       Working         Overhead        Last Pickup/Drop");

  for (uint i = 0; i < tsd->line_pos - 1; i++)
    cli_printf(tsd->cli, -1027, "%s", tsd->lines[i]);

  cli_printf(tsd->cli, 1027, "%s", tsd->lines[tsd->line_pos-1]);
  cli_write_trigger(tsd->cli);
  mb_free(tsd);
}

void
cmd_show_threads(int show_loops)
{
  struct bird_thread_show_data *tsd = mb_allocz(&root_pool, sizeof(struct bird_thread_show_data));
  tsd->cli = this_cli;
  tsd->show_loops = show_loops;
  tsd->line_pos = 0;
  tsd->line_max = 64;

  this_cli->cont = bird_thread_show_cli_cont;
  this_cli->cleanup = bird_thread_show_cli_cleanup;

  bird_thread_sync_all(&tsd->sync, bird_thread_show, cmd_show_threads_done, "Show Threads");
}

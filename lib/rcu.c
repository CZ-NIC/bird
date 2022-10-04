/*
 *	BIRD Library -- Read-Copy-Update Basic Operations
 *
 *	(c) 2021 Maria Matejka <mq@jmq.cz>
 *	(c) 2021 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *	Note: all the relevant patents shall be expired.
 *
 *	Using the Supplementary Material for User-Level Implementations of Read-Copy-Update
 *	by Matthieu Desnoyers, Paul E. McKenney, Alan S. Stern, Michel R. Dagenais and Jonathan Walpole
 *	obtained from https://www.efficios.com/pub/rcu/urcu-supp-accepted.pdf
 */

#include "lib/rcu.h"
#include "lib/io-loop.h"
#include "lib/locking.h"

_Atomic uint rcu_gp_ctl = RCU_NEST_CNT;
_Thread_local struct rcu_birdloop *this_rcu_birdloop = NULL;

static list rcu_birdloop_list;

static struct rcu_birdloop main_rcu_birdloop;

DEFINE_DOMAIN(resource);
static DOMAIN(resource) rcu_domain;

static int
rcu_gp_ongoing(_Atomic uint *ctl)
{
  uint val = atomic_load(ctl);
  return (val & RCU_NEST_CNT) && ((val ^ rcu_gp_ctl) & RCU_GP_PHASE);
}

static void
update_counter_and_wait(void)
{
  atomic_fetch_xor(&rcu_gp_ctl, RCU_GP_PHASE);
  struct rcu_birdloop *rc;
  WALK_LIST(rc, rcu_birdloop_list)
    while (rcu_gp_ongoing(&rc->ctl))
      birdloop_yield();
}

void
synchronize_rcu(void)
{
  LOCK_DOMAIN(resource, rcu_domain);
  update_counter_and_wait();
  update_counter_and_wait();
  UNLOCK_DOMAIN(resource, rcu_domain);
}

void
rcu_birdloop_start(struct rcu_birdloop *rc)
{
  LOCK_DOMAIN(resource, rcu_domain);
  add_tail(&rcu_birdloop_list, &rc->n);
  this_rcu_birdloop = rc;
  UNLOCK_DOMAIN(resource, rcu_domain);
}

void
rcu_birdloop_stop(struct rcu_birdloop *rc)
{
  LOCK_DOMAIN(resource, rcu_domain);
  this_rcu_birdloop = NULL;
  rem_node(&rc->n);
  UNLOCK_DOMAIN(resource, rcu_domain);
}

void
rcu_init(void)
{
  rcu_domain = DOMAIN_NEW(resource, "Read-Copy-Update");
  init_list(&rcu_birdloop_list);
  rcu_birdloop_start(&main_rcu_birdloop);
}

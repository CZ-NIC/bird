/*
 *	BIRD Library -- Event Processing Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include "test/birdtest.h"

#include "lib/net.h"
#include "lib/event.h"
#include "conf/conf.h"
#include "nest/locks.h"
#include "sysdep/unix/unix.h"
#include "nest/iface.h"
#include "nest/route.h"

#define MAX_NUM 4

int event_check_points[MAX_NUM];

#define event_hook_body(num)			\
  do { 						\
    bt_debug("Event Hook " #num "\n");		\
    event_check_points[num] = 1;		\
    bt_assert_msg(event_check_points[num-1], "Events should be run in right order"); \
  } while (0)

static void event_hook_1(void *data UNUSED) { event_hook_body(1); }
static void event_hook_2(void *data UNUSED) { event_hook_body(2); }
static void event_hook_3(void *data UNUSED) { event_hook_body(3); }

#define schedule_event(num)			\
    do {					\
      struct event *event_##num = ev_new(&root_pool); \
      event_##num->hook = event_hook_##num; 	\
      ev_schedule(event_##num);			\
    } while (0)

static void
init_event_check_points(void)
{
  int i;
  event_check_points[0] = 1;
  for (i = 1; i < MAX_NUM; i++)
    event_check_points[i] = 0;
}

static int
t_ev_run_list(void)
{
  int i;

  olock_init();
  timer_init();
  io_init();
  rt_init();
  if_init();
//  roa_init();
  config_init();
  config = config_alloc("");

  init_event_check_points();

  schedule_event(1);
  schedule_event(2);
  schedule_event(3);

  ev_run_list(&global_event_list);

  for (i = 1; i < MAX_NUM; i++)
    bt_assert(event_check_points[i]);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_ev_run_list, "Schedule and run 3 events in right order.");

  return bt_exit_value();
}


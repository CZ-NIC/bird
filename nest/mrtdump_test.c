/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/birdtest_support.h" /* REMOVE ME */
#include "nest/mrtdump.h"
#include "nest/mrtdump.c" /* REMOVE ME */

static void
show_mrt_msg(struct mrt_msg *msg)
{
  uint i;
  bt_debug("show_mrt_msg: \n  ");
  for(i = 0; i < msg->msg_length; i++)
  {
    if (i && (i % 16) == 0)
      bt_debug("\n  ");
    bt_debug("%02X ", msg->msg[i]);
  }
  bt_debug("\n");
}

static int
t_peer_index_table(void)
{
  resource_init();

  struct mrt_msg msg;
  mrt_msg_init(&msg, &root_pool);

  struct mrt_peer_index_table pit_msg = {
      .msg = &msg,
  };
  u32 collector_bgp_id = 0x12345678;
  const char *collector_name = "test";
  mrt_peer_index_table_init(&pit_msg, collector_bgp_id, collector_name);

  u32 i;
  for(i = 0; i < 50; i++)
  {
    ip_addr addr;
#ifdef IPV6
    ip6_pton("1234:5678::9abc:def0", &addr);
#else
    ip4_pton("12.34.56.78", &addr);
#endif
    mrt_peer_index_table_add_peer(&pit_msg, i | 0x30303030, &addr, i | 0x08080808);
  }

  show_mrt_msg(&msg);

  mrt_msg_free(&msg);

  return BT_SUCCESS;
}

static int
t_rib_table(void)
{
  resource_init();

  struct mrt_msg msg;
  mrt_msg_init(&msg, &root_pool);

  struct mrt_rib_table rt_msg = {
      .bgp_proto = NULL,
      .msg = &msg,
  };
  u32 sequence_number = 0x12345678;
  u8 prefix_len = 24;
  ip_addr prefix;
#ifdef IPV6
  rt_msg.type = RIB_IPV6_UNICAST;
  ip6_pton("1234:5678::9abc:def0", &prefix);
#else
  rt_msg.type = RIB_IPV4_UNICAST;
  ip4_pton("12.34.56.78", &prefix);
#endif
  mrt_rib_table_init(&rt_msg, sequence_number, prefix_len, &prefix);

  u32 i;

  for(i = 0; i < 50; i++)
  {
    struct mrt_rib_entry entry = {
	.peer_index =      i,
	.originated_time = i | 0x08080808,
	.attributes_length = 7,
	.attributes = "abcdefg",
    };
    mrt_rib_table_add_entry(&rt_msg, &entry);
  }

  show_mrt_msg(&msg);

  mrt_msg_free(&msg);

  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_peer_index_table, 	"TABLE_DUMP_V2: Peer index table");
  bt_test_suite(t_rib_table, 		"TABLE_DUMP_V2: RIB table");

  return bt_end();
}

/*
 *	BIRD Library -- IP address functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/birdtest_support.h"	/* REMOVE ME */

#include "lib/ip.h"

static u32
build_ip4(u8 a, u8 b, u8 c, u8 d)
{
  return ((u32)a << 24) + ((u32)b << 16) + ((u32)c << 8) + (u32)d;
}

static u32
ip4_pton_(char *s)
{
  ip4_addr ip;
  ip4_pton(s,&ip);
  return ip.addr;
}

static int
t_ip4_pton(void)
{
  struct in_out_data_ {
    char *in;
    u32 out;
  } in_out_data[] = {
      {
	  .in  = "192.168.1.128",
	  .out = build_ip4(192, 168, 1, 128),
      },
      {
	  .in  = "255.255.255.255",
	  .out = build_ip4(255, 255, 255, 255),
      },
      {
	  .in  = "0.0.0.0",
	  .out = build_ip4(0, 0, 0, 0),
      },
      {
	  .in  = "00.000.0000.00000",
	  .out = build_ip4(0, 0, 0, 0),
      },
      {
	  .in  = "00.000.0000.00000",
	  .out = build_ip4(0, 0, 0, 0),
      },
      {
	  .in  = "-1",
	  .out = build_ip4(0, 0, 0, 0),
      },
      {
	  .in  = "",
	  .out = build_ip4(0, 0, 0, 0),
      },
  };

  bt_assert_fn_in(ip4_pton_, in_out_data, "%s", "0x%08X");

  return bt_test_case_success;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_ip4_pton, "Converting IPv4 string to ip4_addr struct");

  return bt_end();
}


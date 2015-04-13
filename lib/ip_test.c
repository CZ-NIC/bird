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

static void
ip6_pton_(char *s, u32 (*addr)[4])
{
  static ip6_addr ip;
  ip6_pton(s, &ip);
  int i;
  for (i = 0; i < 4; i++)
    (*addr)[i] = ip.addr[i];
}

static int
t_ip6_pton(void)
{
  struct in_out_data_ {
    char *in;
    u32 out[4];
    u32 fn_out[4];
  } in_out_data[] = {
      {
	  .in  = "2001:0db8:0000:0000:0000:0000:1428:57ab",
	  .out = {0x20010DB8, 0x00000000, 0x00000000, 0x142857AB},
      },
      {
	  .in  = "2001:0db8:0000:0000:0000::1428:57ab",
	  .out = {0x20010DB8, 0x00000000, 0x00000000, 0x142857AB},
      },
      {
	  .in  = "2001:0db8::1428:57ab",
	  .out = {0x20010DB8, 0x00000000, 0x00000000, 0x142857AB},
      },
      {
	  .in  = "2001:db8::1428:57ab",
	  .out = {0x20010DB8, 0x00000000, 0x00000000, 0x142857AB},
      },
      {
	  .in  = "::1",
	  .out = {0x00000000, 0x00000000, 0x00000000, 0x00000001},
      },
      {
	  .in  = "2605:2700:0:3::4713:93e3",
	  .out = {0x26052700, 0x00000003, 0x00000000, 0x471393E3},
      },
  };

  bt_assert_fn_in_out_struct(ip6_pton_, in_out_data, "%s");

  return bt_test_case_success;
}

#define IP4_MAX_LEN	16

char *
ip4_ntop_(ip4_addr a, char (*b)[IP4_MAX_LEN])
{
  return ip4_ntop(a, (char *) b);
}

static int
t_ip4_ntop(void)
{
  struct in_out_data_ {
    ip4_addr in;
    char out[IP4_MAX_LEN];
    char fn_out[IP4_MAX_LEN];
  } in_out_data[] = {
      {
	  .in  = { .addr = build_ip4(192, 168, 1, 128) },
	  .out = "192.168.1.128",
      },
      {
	  .in  = { .addr = build_ip4(255, 255, 255, 255) },
	  .out = "255.255.255.255",
      },
      {
	  .in  = { .addr = build_ip4(0, 0, 0, 1) },
	  .out = "0.0.0.1",
      },

  };

  bt_assert_fn_in_out(ip4_ntop_, in_out_data, "0x%08X", "\"%s\"");

  return bt_test_case_success;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_ip4_pton, "Converting IPv4 string to ip4_addr struct");
  bt_test_suite(t_ip6_pton, "Converting IPv6 string to ip6_addr struct");
  bt_test_suite(t_ip4_ntop, "t_ip4_ntop");

  return bt_end();
}


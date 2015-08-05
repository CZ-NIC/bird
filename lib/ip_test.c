/*
 *	BIRD Library -- IP address functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/ip.h"

#define IP4_MAX_LEN	16

static int
t_ip4_pton(void)
{
  struct in_out {
    char in[IP4_MAX_LEN];
    ip4_addr out;
  } in_out[] = {
      {
	  .in  = "192.168.1.128",
	  .out = ip4_build(192, 168, 1, 128),
      },
      {
	  .in  = "255.255.255.255",
	  .out = ip4_build(255, 255, 255, 255),
      },
      {
	  .in  = "0.0.0.0",
	  .out = ip4_build(0, 0, 0, 0),
      },
  };

  bt_assert_fn_in_out(ip4_pton, in_out, "'%s'", NULL);

  return bt_test_suite_success;
}

static int
t_ip6_pton(void)
{
  struct in_out {
    char *in;
    ip6_addr out;
  } in_out[] = {
      {
	  .in  = "2001:0db8:0000:0000:0000:0000:1428:57ab",
	  .out = ip6_build(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
      },
      {
	  .in  = "2001:0db8:0000:0000:0000::1428:57ab",
	  .out = ip6_build(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
      },
      {
	  .in  = "2001:0db8::1428:57ab",
	  .out = ip6_build(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
      },
      {
	  .in  = "2001:db8::1428:57ab",
	  .out = ip6_build(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
      },
      {
	  .in  = "::1",
	  .out = ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000001),
      },
      {
	  .in  = "::",
	  .out = ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000000),
      },
      {
	  .in  = "2605:2700:0:3::4713:93e3",
	  .out = ip6_build(0x26052700, 0x00000003, 0x00000000, 0x471393E3),
      },
  };

  bt_assert_fn_in_out(ip6_pton, in_out, "'%s'", NULL);

  return bt_test_suite_success;
}

char *
ip4_ntop_(ip4_addr a, char (*b)[IP4_MAX_LEN])
{
  return ip4_ntop(a, (char *) b);
}

static int
t_ip4_ntop(void)
{
  struct in_out {
    ip4_addr in;
    char out[IP4_MAX_LEN];
  } in_out[] = {
      {
	  .in  = ip4_build(192, 168, 1, 128),
	  .out = "192.168.1.128",
      },
      {
	  .in  = ip4_build(255, 255, 255, 255),
	  .out = "255.255.255.255",
      },
      {
	  .in  = ip4_build(0, 0, 0, 1),
	  .out = "0.0.0.1",
      },

  };

  bt_assert_fn_in_out(ip4_ntop_, in_out, NULL, "'%s'");

  return bt_test_suite_success;
}

char *
ip6_ntop_(ip6_addr a, char (*b)[INET6_ADDRSTRLEN])
{
  return ip6_ntop(a, (char *) b);
}

static int
t_ip6_ntop(void)
{
  struct in_out {
    ip6_addr in;
    char out[INET6_ADDRSTRLEN];
  } in_out[] = {
      {
	  .in  = ip6_build(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
	  .out = "2001:db8::1428:57ab",
      },
      {
	  .in  = ip6_build(0x26052700, 0x00000003, 0x00000000, 0x471393E3),
	  .out = "2605:2700:0:3::4713:93e3",
      },
  };

  bt_assert_fn_in_out(ip6_ntop_, in_out, NULL, "'%s'");

  return bt_test_suite_success;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_ip4_pton, "Converting IPv4 string to ip4_addr struct");
  bt_test_suite(t_ip6_pton, "Converting IPv6 string to ip6_addr struct");
  bt_test_suite(t_ip4_ntop, "Converting ip4_addr struct to IPv4 string");
  bt_test_suite(t_ip6_ntop, "Converting ip6_addr struct to IPv6 string");

  return bt_end();
}


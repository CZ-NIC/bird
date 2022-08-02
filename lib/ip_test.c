/*
 *	BIRD Library -- IP address functions Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"

#include "lib/ip.h"

#define IP4_MAX_LEN		16

static int
test_ip4_pton(void *out_, const void *in_, const void *expected_out_)
{
  ip_addr *out = out_;
  const char *in = in_;
  const ip_addr *expected_out = expected_out_;
  ip4_addr ip4;

  if (expected_out)
  {
    bt_assert(ip4_pton(in, &ip4));
    *out = ipa_from_ip4(ip4);
    return ipa_equal(*out, *expected_out);
  }
  else
    return !ip4_pton(in, &ip4);

}

static int
test_ip6_pton(void *out_, const void *in_, const void *expected_out_)
{
  ip_addr *out = out_;
  const char *in = in_;
  const ip_addr *expected_out = expected_out_;

  if (expected_out)
  {
    bt_assert(ip6_pton(in, out));
    return ipa_equal(*out, *expected_out);
  }
  else
    return !ip6_pton(in, out);
}

static int
t_ip4_pton(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "192.168.1.128",
      .out = & ipa_build4(192, 168, 1, 128),
    },
    {
      .in  = "255.255.255.255",
      .out = & ipa_build4(255, 255, 255, 255),
    },
    {
      .in  = "0.0.0.0",
      .out = & ipa_build4(0, 0, 0, 0),
    },
  };

  return bt_assert_batch(test_vectors, test_ip4_pton, bt_fmt_str, bt_fmt_ipa);
}

static int
t_ip6_pton(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = "2001:0db8:0000:0000:0000:0000:1428:57ab",
      .out = & ipa_build6(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
    },
    {
      .in  = "2001:0db8:0000:0000:0000::1428:57ab",
      .out = & ipa_build6(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
    },
    {
      .in  = "2001:0db8::1428:57ab",
      .out = & ipa_build6(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
    },
    {
      .in  = "2001:db8::1428:57ab",
      .out = & ipa_build6(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
    },
    {
      .in  = "::1",
      .out = & ipa_build6(0x00000000, 0x00000000, 0x00000000, 0x00000001),
    },
    {
      .in  = "::",
      .out = & ipa_build6(0x00000000, 0x00000000, 0x00000000, 0x00000000),
    },
    {
      .in  = "2605:2700:0:3::4713:93e3",
      .out = & ipa_build6(0x26052700, 0x00000003, 0x00000000, 0x471393E3),
    },
    {
      .in = "2605:2700:0:3:4713:93e3",
      .out = NULL,
    },
    {
      .in = "2",
      .out = NULL,
    },
  };

  return bt_assert_batch(test_vectors, test_ip6_pton, bt_fmt_str, bt_fmt_ipa);
}

static int
test_ipa_ntop(void *out_, const void *in_, const void *expected_out_)
{
  char *out = out_;
  const ip_addr *in = in_;
  const char *expected_out = expected_out_;

  if (ipa_is_ip4(*in))
    ip4_ntop(ipa_to_ip4(*in), out);
  else
    ip6_ntop(ipa_to_ip6(*in), out);

  int result = strncmp(out, expected_out, ipa_is_ip4(*in) ? IP4_MAX_TEXT_LENGTH : IP6_MAX_TEXT_LENGTH) == 0;
  return result;
}

static int
t_ip4_ntop(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = & ipa_build4(192, 168, 1, 128),
      .out = "192.168.1.128",
    },
    {
      .in  = & ipa_build4(255, 255, 255, 255),
      .out = "255.255.255.255",
    },
    {
      .in  = & ipa_build4(0, 0, 0, 1),
      .out = "0.0.0.1",
    },
  };

  return bt_assert_batch(test_vectors, test_ipa_ntop, bt_fmt_ipa, bt_fmt_str);
}

static int
t_ip6_ntop(void)
{
  struct bt_pair test_vectors[] = {
    {
      .in  = & ipa_build6(0x20010DB8, 0x00000000, 0x00000000, 0x142857AB),
      .out = "2001:db8::1428:57ab",
    },
    {
      .in  = & ipa_build6(0x26052700, 0x00000003, 0x00000000, 0x471393E3),
      .out = "2605:2700:0:3::4713:93e3",
    },
  };

  return bt_assert_batch(test_vectors, test_ipa_ntop, bt_fmt_ipa, bt_fmt_str);
}

static int
t_ip4_prefix_equal(void)
{
  bt_assert( ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x1234ffff), 16));
  bt_assert(!ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x1234ffff), 17));
  bt_assert( ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x12345000), 21));
  bt_assert(!ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x12345000), 22));

  bt_assert( ip4_prefix_equal(ip4_from_u32(0x00000000), ip4_from_u32(0xffffffff),  0));
  bt_assert( ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x12345678),  0));

  bt_assert( ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x12345678),  32));
  bt_assert(!ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x12345679),  32));
  bt_assert(!ip4_prefix_equal(ip4_from_u32(0x12345678), ip4_from_u32(0x92345678),  32));

  return 1;
}

static int
t_ip6_prefix_equal(void)
{
  bt_assert( ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x1234ffff, 0xfefefefe, 0xdcdcdcdc),
			      48));

  bt_assert(!ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x1234ffff, 0xfefefefe, 0xdcdcdcdc),
			      49));

  bt_assert(!ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20020db8, 0x12345678, 0xfefefefe, 0xdcdcdcdc),
			      48));

  bt_assert( ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x12345678, 0xfefefefe, 0xdcdcdcdc),
			      64));

  bt_assert(!ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x1234567e, 0xfefefefe, 0xdcdcdcdc),
			      64));

  bt_assert( ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20002020),
			      ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      106));

  bt_assert(!ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20002020),
			      ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      107));

  bt_assert( ip6_prefix_equal(ip6_build(0xfeef0db8, 0x87654321, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x12345678, 0xfefefefe, 0xdcdcdcdc),
			      0));

  bt_assert( ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      128));

  bt_assert(!ip6_prefix_equal(ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202020),
			      ip6_build(0x20010db8, 0x12345678, 0x10101010, 0x20202021),
			      128));

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_ip4_pton, "Converting IPv4 string to ip4_addr struct");
  bt_test_suite(t_ip6_pton, "Converting IPv6 string to ip6_addr struct");
  bt_test_suite(t_ip4_ntop, "Converting ip4_addr struct to IPv4 string");
  bt_test_suite(t_ip6_ntop, "Converting ip6_addr struct to IPv6 string");
  bt_test_suite(t_ip4_prefix_equal, "Testing ip4_prefix_equal()");
  bt_test_suite(t_ip6_prefix_equal, "Testing ip6_prefix_equal()");

  return bt_exit_value();
}


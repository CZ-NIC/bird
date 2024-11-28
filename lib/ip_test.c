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

static int
t_ip6_shift_left(void)
{
  ip6_addr a = ip6_build(0x8D0D8BDC, 0x1F04DB92, 0xE5117673, 0x70E54449);

  struct { int n; ip6_addr val; } test_vectors[] = {
      0, ip6_build(0x8D0D8BDC, 0x1F04DB92, 0xE5117673, 0x70E54449),
      9, ip6_build(0x1B17B83E, 0x09B725CA, 0x22ECE6E1, 0xCA889200),
     18, ip6_build(0x2F707C13, 0x6E4B9445, 0xD9CDC395, 0x11240000),
     27, ip6_build(0xE0F826DC, 0x97288BB3, 0x9B872A22, 0x48000000),
     36, ip6_build(0xF04DB92E, 0x51176737, 0x0E544490, 0x00000000),
     45, ip6_build(0x9B725CA2, 0x2ECE6E1C, 0xA8892000, 0x00000000),
     54, ip6_build(0xE4B9445D, 0x9CDC3951, 0x12400000, 0x00000000),
     63, ip6_build(0x7288BB39, 0xB872A224, 0x80000000, 0x00000000),
     72, ip6_build(0x11767370, 0xE5444900, 0x00000000, 0x00000000),
     81, ip6_build(0xECE6E1CA, 0x88920000, 0x00000000, 0x00000000),
     90, ip6_build(0xCDC39511, 0x24000000, 0x00000000, 0x00000000),
     99, ip6_build(0x872A2248, 0x00000000, 0x00000000, 0x00000000),
    108, ip6_build(0x54449000, 0x00000000, 0x00000000, 0x00000000),
    117, ip6_build(0x89200000, 0x00000000, 0x00000000, 0x00000000),
    126, ip6_build(0x40000000, 0x00000000, 0x00000000, 0x00000000),
    128, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000000),
  };

  for (uint i = 0; i < ARRAY_SIZE(test_vectors); i++)
    bt_assert(ip6_equal(ip6_shift_left(a, test_vectors[i].n), test_vectors[i].val));

  return 1;
}

static int
t_ip6_shift_right(void)
{
  ip6_addr a = ip6_build(0x8D0D8BDC, 0x1F04DB92, 0xE5117673, 0x70E54449);

  struct { int n; ip6_addr val; } test_vectors[] = {
      0, ip6_build(0x8D0D8BDC, 0x1F04DB92, 0xE5117673, 0x70E54449),
      9, ip6_build(0x004686C5, 0xEE0F826D, 0xC97288BB, 0x39B872A2),
     18, ip6_build(0x00002343, 0x62F707C1, 0x36E4B944, 0x5D9CDC39),
     27, ip6_build(0x00000011, 0xA1B17B83, 0xE09B725C, 0xA22ECE6E),
     36, ip6_build(0x00000000, 0x08D0D8BD, 0xC1F04DB9, 0x2E511767),
     45, ip6_build(0x00000000, 0x0004686C, 0x5EE0F826, 0xDC97288B),
     54, ip6_build(0x00000000, 0x00000234, 0x362F707C, 0x136E4B94),
     63, ip6_build(0x00000000, 0x00000001, 0x1A1B17B8, 0x3E09B725),
     72, ip6_build(0x00000000, 0x00000000, 0x008D0D8B, 0xDC1F04DB),
     81, ip6_build(0x00000000, 0x00000000, 0x00004686, 0xC5EE0F82),
     90, ip6_build(0x00000000, 0x00000000, 0x00000023, 0x4362F707),
     99, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x11A1B17B),
    108, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x0008D0D8),
    117, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000468),
    126, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000002),
    128, ip6_build(0x00000000, 0x00000000, 0x00000000, 0x00000000),
  };

  for (uint i = 0; i < ARRAY_SIZE(test_vectors); i++)
    bt_assert(ip6_equal(ip6_shift_right(a, test_vectors[i].n), test_vectors[i].val));

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
  bt_test_suite(t_ip6_shift_left, "Testing ip6_shift_left()");
  bt_test_suite(t_ip6_shift_right, "Testing ip6_shift_right()");

  return bt_exit_value();
}


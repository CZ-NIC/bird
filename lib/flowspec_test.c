/*
 *	BIRD Library -- Flow specification (RFC 5575) Tests
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/flowspec.h"

#define NET_ADDR_FLOW4_(what,prefix,pxlen,data_)	\
  do 							\
  { 							\
    what = alloca(sizeof(net_addr_flow4) + 128);	\
    *what = NET_ADDR_FLOW4(prefix, pxlen, sizeof(data_)); \
    memcpy(what->data, &(data_), sizeof(data_));	\
  } while(0)

#define NET_ADDR_FLOW6_(what,prefix,pxlen,data_)	\
  do							\
  {							\
    what = alloca(sizeof(net_addr_flow6) + 128);	\
    *what = NET_ADDR_FLOW6(prefix, pxlen, sizeof(data_)); \
    memcpy(what->data, &(data_), sizeof(data_));	\
  } while(0)

static int
t_read_length(void)
{
  byte data[] = { 0xcc, 0xcc, 0xcc };

  for (uint expect = 0; expect < 0xf0; expect++)
  {
    *data = expect;
    uint get = flow_read_length(data);
    bt_assert_msg(get == expect, "Testing get length 0x%02x (get 0x%02x)", expect, get);
  }

  for (uint expect = 0; expect <= 0xfff; expect++)
  {
    put_u16(data, expect | 0xf000);
    uint get = flow_read_length(data);
    bt_assert_msg(get == expect, "Testing get length 0x%03x (get 0x%03x)", expect, get);
  }

  return 1;
}

static int
t_write_length(void)
{
  byte data[] = { 0xcc, 0xcc, 0xcc };

  for (uint expect = 0; expect <= 0xfff; expect++)
  {
    uint offset = flow_write_length(data, expect);

    uint set = (expect < 0xf0) ? *data : (get_u16(data) & 0x0fff);
    bt_assert_msg(set == expect, "Testing set length 0x%03x (set 0x%03x)", expect, set);
    bt_assert(offset == (expect < 0xf0 ? 1 : 2));
  }

  return 1;
}

static int
t_first_part(void)
{
  net_addr_flow4 *f;
  NET_ADDR_FLOW4_(f, ip4_build(10,0,0,1), 24, ((byte[]) { 0x00, 0x00, 0xab }));

  const byte *under240 = &f->data[1];
  const byte *above240 = &f->data[2];

  /* Case 0x00 0x00 */
  bt_assert(flow4_first_part(f) == NULL);

  /* Case 0x01 0x00 */
  f->data[0] = 0x01;
  bt_assert(flow4_first_part(f) == under240);

  /* Case 0xef 0x00 */
  f->data[0] = 0xef;
  bt_assert(flow4_first_part(f) == under240);

  /* Case 0xf0 0x00 */
  f->data[0] = 0xf0;
  bt_assert(flow4_first_part(f) == NULL);

  /* Case 0xf0 0x01 */
  f->data[1] = 0x01;
  bt_assert(flow4_first_part(f) == above240);

  /* Case 0xff 0xff */
  f->data[0] = 0xff;
  f->data[1] = 0xff;
  bt_assert(flow4_first_part(f) == above240);

  return 1;
}

static int
t_iterators4(void)
{
  net_addr_flow4 *f;
  NET_ADDR_FLOW4_(f, ip4_build(5,6,7,0), 24, ((byte[]) {
    25, /* Length */
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));

  const byte *start		= f->data;
  const byte *p1_dst_pfx	= &f->data[1];
  const byte *p2_src_pfx 	= &f->data[6];
  const byte *p3_ip_proto 	= &f->data[12];
  const byte *p4_port 		= &f->data[15];
  const byte *p5_tcp_flags 	= &f->data[23];
  const byte *end 		= &f->data[25];

  bt_assert(flow_read_length(f->data) == (end-start));
  bt_assert(flow4_first_part(f) == p1_dst_pfx);

  bt_assert(flow4_next_part(p1_dst_pfx, end) == p2_src_pfx);
  bt_assert(flow4_next_part(p2_src_pfx, end) == p3_ip_proto);
  bt_assert(flow4_next_part(p3_ip_proto, end) == p4_port);
  bt_assert(flow4_next_part(p4_port, end) == p5_tcp_flags);
  bt_assert(flow4_next_part(p5_tcp_flags, end) == NULL);

  return 1;
}

static int
t_iterators6(void)
{
  net_addr_flow6 *f;
  NET_ADDR_FLOW6_(f, ip6_build(0,0,0x12345678,0x9a000000), 0x68, ((byte[]) {
    26, /* Length */
    FLOW_TYPE_DST_PREFIX, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
    FLOW_TYPE_SRC_PREFIX, 0x08, 0x0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  }));

  const byte *start		= f->data;
  const byte *p1_dst_pfx	= &f->data[1];
  const byte *p2_src_pfx 	= &f->data[9];
  const byte *p3_next_header	= &f->data[13];
  const byte *p4_port 		= &f->data[16];
  const byte *p5_label		= &f->data[24];
  const byte *end 		= &f->data[26];

  bt_assert(flow_read_length(f->data) == (end-start));
  bt_assert(flow6_first_part(f) == p1_dst_pfx);

  bt_assert(flow6_next_part(p1_dst_pfx, end) == p2_src_pfx);
  bt_assert(flow6_next_part(p2_src_pfx, end) == p3_next_header);
  bt_assert(flow6_next_part(p3_next_header, end) == p4_port);
  bt_assert(flow6_next_part(p4_port, end) == p5_label);
  bt_assert(flow6_next_part(p5_label, end) == NULL);

  return 1;
}

static int
t_accessors4(void)
{
  net_addr_flow4 *f;
  NET_ADDR_FLOW4_(f, ip4_build(5,6,7,0), 24, ((byte[]) {
    25, /* Length */
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
  }));

  const byte *p1_dst_px		= &f->data[1];
  const ip4_addr p1_dst_addr	= ip4_build(5,6,7,0);

  const byte *p2_src_px		= &f->data[6];
  const ip4_addr p2_src_addr	= ip4_build(10,11,12,13);

  bt_assert(ip4_equal(flow_read_ip4_part(p1_dst_px), p1_dst_addr));
  bt_assert(ip4_equal(flow_read_ip4_part(p2_src_px), p2_src_addr));

  return 1;
}

static int
t_accessors6(void)
{
  net_addr_flow6 *f;
  NET_ADDR_FLOW6_(f, ip6_build(0,0,0x12345678,0x9a000000), 0x68, ((byte[]) {
    26, /* Length */
    FLOW_TYPE_DST_PREFIX, 0x68, 0x40, 0x12, 0x34, 0x56, 0x78, 0x9a,
    FLOW_TYPE_SRC_PREFIX, 0x08, 0x0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  }));

  const byte *p1_dst_px		= &f->data[1];
  const ip6_addr p1_dst_addr	= ip6_build(0,0,0x12345678,0x9a000000);

  const byte *p2_src_px 	= &f->data[9];
  const ip6_addr p2_src_addr	= ip6_build(0xc0000000, 0, 0, 0);

  bt_assert(ip6_equal(flow_read_ip6_part(p1_dst_px), p1_dst_addr));
  bt_assert(ip6_equal(flow_read_ip6_part(p2_src_px), p2_src_addr));

  return 1;
}

static int
t_validation4(void)
{
  enum flow_validated_state res;

  byte nlri1[] = {
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
  };

  /* Empty NLRI */
  res = flow4_validate(nlri1, 0);
  bt_assert(res == FLOW_ST_VALID);

  /* Valid / Not Complete testing */
  uint valid_sizes[] = {5, 11, 14, 22, 25, 0};
  uint valid_idx = 0;
  for (uint size = 1; size <= sizeof(nlri1); size++)
  {
    res = flow4_validate(nlri1, size);
    bt_debug("size %u, result: %s\n", size, flow_validated_state_str(res));
    if (size == valid_sizes[valid_idx])
    {
      valid_idx++;
      bt_assert(res == FLOW_ST_VALID);
    }
    else
    {
      bt_assert(res == FLOW_ST_NOT_COMPLETE);
    }
  }

  /* Misc err tests */

  struct tset {
    enum flow_validated_state expect;
    char *description;
    u16 size;
    byte *nlri;
  };

#define TS(type, msg, data) ((struct tset) {type, msg, sizeof(data), (data)})
  struct tset tset[] = {
    TS(
      FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
      "33-length IPv4 prefix",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 33, 5, 6, 7, 8, 9
      })
    ),
    TS(
      FLOW_ST_BAD_TYPE_ORDER,
      "Bad flowspec component type order",
      ((byte []) {
	FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
      })
    ),
    TS(
      FLOW_ST_BAD_TYPE_ORDER,
      "Doubled destination prefix component",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
      })
    ),
    TS(
      FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
      "The first numeric operator has set the AND bit",
      ((byte []) {
	FLOW_TYPE_PORT, 0x43, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
      })
    ),
    TS(
      FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
      "Set zero bit in operand to one",
      ((byte []) {
	FLOW_TYPE_IP_PROTOCOL, 0x89, 0x06,
      })
    ),
    TS(
      FLOW_ST_UNKNOWN_COMPONENT,
      "Unknown component of type number 13",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
	FLOW_TYPE_TCP_FLAGS, 0x80, 0x55,
	13 /*something new*/, 0x80, 0x55,
      })
    ),
  };
#undef TS

  for (uint tcase = 0; tcase < ARRAY_SIZE(tset); tcase++)
  {
    res = flow4_validate(tset[tcase].nlri, tset[tcase].size);
    bt_assert_msg(res == tset[tcase].expect, "Assertion (%s == %s) %s", flow_validated_state_str(res), flow_validated_state_str(tset[tcase].expect), tset[tcase].description);
  }

  return 1;
}

static int
t_validation6(void)
{
  enum flow_validated_state res;

  byte nlri1[] = {
    FLOW_TYPE_DST_PREFIX, 103, 61, 0x01, 0x12, 0x34, 0x56, 0x78, 0x98,
    FLOW_TYPE_SRC_PREFIX, 8, 0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  };

  /* Isn't included destination prefix */
  res = flow6_validate(nlri1, 0);
  bt_assert(res == FLOW_ST_VALID);

  /* Valid / Not Complete testing */
  uint valid_sizes[] = {0, 9, 13, 16, 24, 27, 0};
  uint valid_idx = 0;
  for (uint size = 0; size <= sizeof(nlri1); size++)
  {
    res = flow6_validate(nlri1, size);
    bt_debug("size %u, result: %s\n", size, flow_validated_state_str(res));
    if (size == valid_sizes[valid_idx])
    {
      valid_idx++;
      bt_assert(res == FLOW_ST_VALID);
    }
    else
    {
      bt_assert(res == FLOW_ST_NOT_COMPLETE);
    }
  }

  /* Misc err tests */

  struct tset {
    enum flow_validated_state expect;
    char *description;
    u16 size;
    byte *nlri;
  };

#define TS(type, msg, data) ((struct tset) {type, msg, sizeof(data), (data)})
  struct tset tset[] = {
    TS(
      FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
      "129-length IPv6 prefix",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 129, 64, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12
      })
    ),
    TS(
      FLOW_ST_EXCEED_MAX_PREFIX_OFFSET,
      "Prefix offset is higher than prefix length",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 48, 64, 0x40, 0x12, 0x34
      })
    ),
    TS(
      FLOW_ST_BAD_TYPE_ORDER,
      "Bad flowspec component type order",
      ((byte []) {
	FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
	FLOW_TYPE_SRC_PREFIX, 8, 0, 0xc0,
      })
    ),
    TS(
      FLOW_ST_BAD_TYPE_ORDER,
      "Doubled destination prefix component",
      ((byte []) {
	FLOW_TYPE_DST_PREFIX, 103, 61, 0x01, 0x12, 0x34, 0x56, 0x78, 0x98,
	FLOW_TYPE_DST_PREFIX, 103, 61, 0x01, 0x12, 0x34, 0x56, 0x78, 0x98,
      })
    ),
    TS(
      FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
      "The first numeric operator has set the AND bit",
      ((byte []) {
	FLOW_TYPE_PORT, 0x43, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90
      })
    ),
    TS(
      FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
      "Set zero bit in operand to one",
      ((byte []) {
	FLOW_TYPE_NEXT_HEADER, 0x89, 0x06
      })
    ),
    TS(
      FLOW_ST_VALID,
      "Component of type number 13 (Label) is well-known in IPv6",
      ((byte []) {
	FLOW_TYPE_LABEL, 0x80, 0x55
      })
    ),
    TS(
      FLOW_ST_UNKNOWN_COMPONENT,
      "Unknown component of type number 14",
      ((byte []) {
	FLOW_TYPE_LABEL, 0x80, 0x55,
	14 /*something new*/, 0x80, 0x55,
      })
    )
  };
#undef TS

  for (uint tcase = 0; tcase < ARRAY_SIZE(tset); tcase++)
  {
    res = flow6_validate(tset[tcase].nlri, tset[tcase].size);
    bt_assert_msg(res == tset[tcase].expect, "Assertion (%s == %s) %s", flow_validated_state_str(res), flow_validated_state_str(tset[tcase].expect), tset[tcase].description);
  }

  return 1;
}



/*
 * 	Builder tests
 */

static int
t_builder4(void)
{
  struct flow_builder *fb = flow_builder_init(&root_pool);

  /* Expectation */

  static byte nlri[] = {
    25,
    FLOW_TYPE_DST_PREFIX, 24, 5, 6, 7,
    FLOW_TYPE_SRC_PREFIX, 32, 10, 11, 12, 13,
    FLOW_TYPE_IP_PROTOCOL, 0x80, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_TCP_FLAGS, 0x80, 0x55
  };

  net_addr_flow4 *expect;
  NET_ADDR_FLOW4_(expect, ip4_build(5, 6, 7, 0), 24, nlri);

  /* Normal order */

  net_addr_ip4 n1;
  net_fill_ip4((net_addr *) &n1, ip4_build(5,6,7,0), 24);
  flow_builder_set_type(fb, FLOW_TYPE_DST_PREFIX);
  flow_builder4_add_pfx(fb, &n1);

  net_addr_ip4 n2;
  net_fill_ip4((net_addr *) &n2, ip4_build(10,11,12,13), 32);
  flow_builder_set_type(fb, FLOW_TYPE_SRC_PREFIX);
  flow_builder4_add_pfx(fb, &n2);

  flow_builder_set_type(fb, FLOW_TYPE_IP_PROTOCOL);
  flow_builder_add_op_val(fb, 0, 0x06);

  flow_builder_set_type(fb, FLOW_TYPE_PORT);
  flow_builder_add_op_val(fb, 0x03, 0x89);
  flow_builder_add_op_val(fb, 0x45, 0x8b);
  flow_builder_add_op_val(fb, 0x01, 0x1f90);

  /* Try put a component twice time */
  flow_builder_set_type(fb, FLOW_TYPE_IP_PROTOCOL);
  flow_builder_add_op_val(fb, 0, 0x06);

  flow_builder_set_type(fb, FLOW_TYPE_TCP_FLAGS);
  flow_builder_add_op_val(fb, 0, 0x55);

  net_addr_flow4 *res = flow_builder4_finalize(fb, tmp_linpool);

  bt_assert(memcmp(res, expect, expect->length) == 0);

  /* Reverse order */

  flow_builder_clear(fb);

  flow_builder_set_type(fb, FLOW_TYPE_TCP_FLAGS);
  flow_builder_add_op_val(fb, 0, 0x55);

  flow_builder_set_type(fb, FLOW_TYPE_PORT);
  flow_builder_add_op_val(fb, 0x03, 0x89);
  flow_builder_add_op_val(fb, 0x45, 0x8b);
  flow_builder_add_op_val(fb, 0x01, 0x1f90);

  flow_builder_set_type(fb, FLOW_TYPE_IP_PROTOCOL);
  flow_builder_add_op_val(fb, 0, 0x06);

  net_fill_ip4((net_addr *) &n2, ip4_build(10,11,12,13), 32);
  flow_builder_set_type(fb, FLOW_TYPE_SRC_PREFIX);
  flow_builder4_add_pfx(fb, &n2);

  net_fill_ip4((net_addr *) &n1, ip4_build(5,6,7,0), 24);
  flow_builder_set_type(fb, FLOW_TYPE_DST_PREFIX);
  flow_builder4_add_pfx(fb, &n1);

  bt_assert(memcmp(res, expect, expect->length) == 0);

  return 1;
}

static int
t_builder6(void)
{
  net_addr_ip6 ip;

  struct flow_builder *fb = flow_builder_init(&root_pool);
  fb->ipv6 = 1;

  /* Expectation */

  byte nlri[] = {
    27,
    FLOW_TYPE_DST_PREFIX, 103, 61, 0x01, 0x12, 0x34, 0x56, 0x78, 0x98,
    FLOW_TYPE_SRC_PREFIX, 8, 0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x80, 0x06,
    FLOW_TYPE_PORT, 0x03, 0x89, 0x45, 0x8b, 0x91, 0x1f, 0x90,
    FLOW_TYPE_LABEL, 0x80, 0x55,
  };

  net_addr_flow6 *expect;
  NET_ADDR_FLOW6_(expect, ip6_build(0, 1, 0x12345678, 0x98000000), 103, nlri);

  /* Normal order */

  net_fill_ip6((net_addr *) &ip, ip6_build(0, 1, 0x12345678, 0x98000000), 103);
  flow_builder_set_type(fb, FLOW_TYPE_DST_PREFIX);
  flow_builder6_add_pfx(fb, &ip, 61);

  /* Try put a component twice time */
  net_fill_ip6((net_addr *) &ip, ip6_build(0, 1, 0x12345678, 0x98000000), 103);
  flow_builder_set_type(fb, FLOW_TYPE_DST_PREFIX);
  bt_assert(flow_builder6_add_pfx(fb, &ip, 61) == 0);

  net_fill_ip6((net_addr *) &ip, ip6_build(0xc0000000,0,0,0), 8);
  flow_builder_set_type(fb, FLOW_TYPE_SRC_PREFIX);
  flow_builder6_add_pfx(fb, &ip, 0);

  flow_builder_set_type(fb, FLOW_TYPE_NEXT_HEADER);
  flow_builder_add_op_val(fb, 0, 0x06);

  flow_builder_set_type(fb, FLOW_TYPE_PORT);
  flow_builder_add_op_val(fb, 0x03, 0x89);
  flow_builder_add_op_val(fb, 0x45, 0x8b);
  flow_builder_add_op_val(fb, 0x01, 0x1f90);

  flow_builder_set_type(fb, FLOW_TYPE_LABEL);
  flow_builder_add_op_val(fb, 0, 0x55);

  net_addr_flow6 *res = flow_builder6_finalize(fb, tmp_linpool);
  bt_assert(memcmp(res, expect, expect->length) == 0);

  /* Reverse order */

  flow_builder_clear(fb);
  fb->ipv6 = 1;

  flow_builder_set_type(fb, FLOW_TYPE_LABEL);
  flow_builder_add_op_val(fb, 0, 0x55);

  flow_builder_set_type(fb, FLOW_TYPE_PORT);
  flow_builder_add_op_val(fb, 0x03, 0x89);
  flow_builder_add_op_val(fb, 0x45, 0x8b);
  flow_builder_add_op_val(fb, 0x01, 0x1f90);

  flow_builder_set_type(fb, FLOW_TYPE_NEXT_HEADER);
  flow_builder_add_op_val(fb, 0, 0x06);

  net_fill_ip6((net_addr *) &ip, ip6_build(0xc0000000,0,0,0), 8);
  flow_builder_set_type(fb, FLOW_TYPE_SRC_PREFIX);
  flow_builder6_add_pfx(fb, &ip, 0);

  net_fill_ip6((net_addr *) &ip, ip6_build(0, 1, 0x12345678, 0x98000000), 103);
  flow_builder_set_type(fb, FLOW_TYPE_DST_PREFIX);
  flow_builder6_add_pfx(fb, &ip, 61);

  res = flow_builder6_finalize(fb, tmp_linpool);
  bt_assert(memcmp(res, expect, expect->length) == 0);

  return 1;
}

static int
t_formatting4(void)
{
  char b[1024];

  byte nlri[] = {
    0,
    FLOW_TYPE_DST_PREFIX, 0x08, 10,
    FLOW_TYPE_IP_PROTOCOL, 0x81, 23,
    FLOW_TYPE_DST_PORT, 0x02, 24, 0x44, 30, 0x03, 40, 0x45, 50, 0x03, 60, 0x45, 70, 0x01, 80, 0xc3, 90,
    FLOW_TYPE_SRC_PORT, 0x02, 24, 0x44, 0x1e, 0x01, 0x28, 0x01, 0x32, 0x03, 0x3c, 0x45, 0x46, 0x81, 0x50,
    FLOW_TYPE_ICMP_TYPE, 0x81, 0x50,
    FLOW_TYPE_ICMP_CODE, 0x81, 0x5a,
    FLOW_TYPE_TCP_FLAGS, 0x01, 0x03, 0xc2, 0x0c,
    FLOW_TYPE_PACKET_LENGTH, 0x03, 0, 0xd5, 0xff, 0xff,
    FLOW_TYPE_DSCP, 0x81, 63,
    FLOW_TYPE_FRAGMENT, 0x01, 0x01, 0x82, 0x02
  };
  *nlri = (u8) sizeof(nlri);

  net_addr_flow4 *input;
  NET_ADDR_FLOW4_(input, ip4_build(5, 6, 7, 0), 24, nlri);

  const char *expect = "flow4 { dst 10.0.0.0/8; proto 23; dport > 24 && < 30 || 40..50,60..70,80 && >= 90; sport > 24 && < 30 || 40,50,60..70,80; icmp type 80; icmp code 90; tcp flags 0x3/0x3 && 0x0/0xc; length 0..65535; dscp 63; fragment dont_fragment || !is_fragment; }";

  bt_assert(flow4_net_format(b, sizeof(b), input) == strlen(expect));
  bt_debug(" expect: '%s',\n output: '%s'\n", expect, b);
  bt_assert(strcmp(b, expect) == 0);

  return 1;
}

static int
t_formatting6(void)
{
  char b[1024];

  byte nlri[] = {
    0,
    FLOW_TYPE_DST_PREFIX, 103, 61, 0x01, 0x12, 0x34, 0x56, 0x78, 0x98,
    FLOW_TYPE_SRC_PREFIX, 8, 0, 0xc0,
    FLOW_TYPE_NEXT_HEADER, 0x81, 0x06,
    FLOW_TYPE_PORT, 0x03, 20, 0x45, 40, 0x91, 0x01, 0x11,
    FLOW_TYPE_LABEL, 0xa4, 0x00, 0x07, 0xa1, 0x20,
  };
  *nlri = (u8) sizeof(nlri);

  net_addr_flow6 *input;
  NET_ADDR_FLOW6_(input, ip6_build(0, 1, 0x12345678, 0x98000000), 103, nlri);

  const char *expect = "flow6 { dst ::1:1234:5678:9800:0/103 offset 61; src c000::/8; next header 6; port 20..40,273; label < 500000; }";

  bt_assert(flow6_net_format(b, sizeof(b), input) == strlen(expect));
  bt_debug(" expect: '%s',\n output: '%s'\n", expect, b);
  bt_assert(strcmp(b, expect) == 0);

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_read_length,  "Testing get NLRI length");
  bt_test_suite(t_write_length, "Testing set NLRI length");
  bt_test_suite(t_first_part,   "Searching first part in net_addr_flow");
  bt_test_suite(t_iterators4,   "Testing iterators (IPv4)");
  bt_test_suite(t_iterators6,   "Testing iterators (IPv6)");
  bt_test_suite(t_accessors4,   "Testing accessors (IPv4)");
  bt_test_suite(t_accessors6,   "Testing accessors (IPv6)");
  bt_test_suite(t_validation4,  "Testing validation (IPv4)");
  bt_test_suite(t_validation6,  "Testing validation (IPv6)");
  bt_test_suite(t_builder4,     "Inserting components into existing Flow Specification (IPv4)");
  bt_test_suite(t_builder6,     "Inserting components into existing Flow Specification (IPv6)");
  bt_test_suite(t_formatting4,  "Formatting Flow Specification (IPv4) into text representation");
  bt_test_suite(t_formatting6,  "Formatting Flow Specification (IPv6) into text representation");

  return bt_exit_value();
}

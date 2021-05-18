/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Flow specification (flowspec)
 *
 * Flowspec are rules (RFC 5575) for firewalls disseminated using BGP protocol.
 * The |flowspec.c| is a library for handling flowspec binary streams and
 * flowspec data structures. You will find there functions for validation
 * incoming flowspec binary streams, iterators for jumping over components,
 * functions for handling a length and functions for formatting flowspec data
 * structure into user-friendly text representation.
 *
 * In this library, you will find also flowspec builder. In |confbase.Y|, there
 * are grammar's rules for parsing and building new flowspec data structure
 * from BIRD's configuration files and from BIRD's command line interface.
 * Finalize function will assemble final &net_addr_flow4 or &net_addr_flow6
 * data structure.
 *
 * The data structures &net_addr_flow4 and &net_addr_flow6 are defined in
 * |net.h| file. The attribute length is size of whole data structure plus
 * binary stream representation of flowspec including a compressed encoded
 * length of flowspec.
 *
 * Sometimes in code, it is used expression flowspec type, it should mean
 * flowspec component type.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/flowspec.h"
#include "conf/conf.h"


static const char* flow4_type_str[] = {
  [FLOW_TYPE_DST_PREFIX]	= "dst",
  [FLOW_TYPE_SRC_PREFIX]	= "src",
  [FLOW_TYPE_IP_PROTOCOL]	= "proto",
  [FLOW_TYPE_PORT]		= "port",
  [FLOW_TYPE_DST_PORT]		= "dport",
  [FLOW_TYPE_SRC_PORT]		= "sport",
  [FLOW_TYPE_ICMP_TYPE]		= "icmp type",
  [FLOW_TYPE_ICMP_CODE]		= "icmp code",
  [FLOW_TYPE_TCP_FLAGS]		= "tcp flags",
  [FLOW_TYPE_PACKET_LENGTH]	= "length",
  [FLOW_TYPE_DSCP]		= "dscp",
  [FLOW_TYPE_FRAGMENT]		= "fragment"
};

static const char* flow6_type_str[] = {
  [FLOW_TYPE_DST_PREFIX]	= "dst",
  [FLOW_TYPE_SRC_PREFIX]	= "src",
  [FLOW_TYPE_NEXT_HEADER]	= "next header",
  [FLOW_TYPE_PORT]		= "port",
  [FLOW_TYPE_DST_PORT]		= "dport",
  [FLOW_TYPE_SRC_PORT]		= "sport",
  [FLOW_TYPE_ICMP_TYPE]		= "icmp type",
  [FLOW_TYPE_ICMP_CODE]		= "icmp code",
  [FLOW_TYPE_TCP_FLAGS]		= "tcp flags",
  [FLOW_TYPE_PACKET_LENGTH]	= "length",
  [FLOW_TYPE_DSCP]		= "dscp",
  [FLOW_TYPE_FRAGMENT]		= "fragment",
  [FLOW_TYPE_LABEL]		= "label"
};

/**
 * flow_type_str - get stringified flowspec name of component
 * @type: flowspec component type
 * @ipv6: IPv4/IPv6 decide flag, use zero for IPv4 and one for IPv6
 *
 * This function returns flowspec name of component @type in string.
 */
const char *
flow_type_str(enum flow_type type, int ipv6)
{
  return ipv6 ? flow6_type_str[type] : flow4_type_str[type];
}

/*
 * 	Length
 */

/**
 * flow_write_length - write compressed length value
 * @data: destination buffer to write
 * @len: the value of the length (0 to 0xfff) for writing
 *
 * This function writes appropriate as (1- or 2-bytes) the value of @len into
 * buffer @data. The function returns number of written bytes, thus 1 or 2 bytes.
 */
uint
flow_write_length(byte *data, u16 len)
{
  if (len >= 0xf0)
  {
    put_u16(data, len | 0xf000);
    return 2;
  }

  *data = len;
  return 1;
}

inline static uint
get_value_length(const byte *op)
{
  return (1 << ((*op & 0x30) >> 4));
}


/*
 *	Flowspec iterators
 */

static inline u8  num_op(const byte *op)    { return  (*op & 0x07); }
static inline int isset_and(const byte *op) { return ((*op & 0x40) == 0x40); }
static inline int isset_end(const byte *op) { return ((*op & 0x80) == 0x80); }

static const byte *
flow_first_part(const byte *data)
{
  if (!data || flow_read_length(data) == 0)
    return NULL;

  /* It is allowed to encode the value of length less then 240 into 2-bytes too */
  if ((data[0] & 0xf0) == 0xf0)
    return data + 2;

  return data + 1;
}

/**
 * flow4_first_part - get position of the first flowspec component
 * @f: flowspec data structure &net_addr_flow4
 *
 * This function return a position to the beginning of the first flowspec
 * component in IPv4 flowspec @f.
 */
inline const byte *
flow4_first_part(const net_addr_flow4 *f)
{
  return f ? flow_first_part(f->data) : NULL;
}

/**
 * flow6_first_part - get position of the first flowspec component
 * @f: flowspec data structure &net_addr_flow6
 *
 * This function return a position to the beginning of the first flowspec
 * component in IPv6 flowspec @f.
 */
inline const byte *
flow6_first_part(const net_addr_flow6 *f)
{
  return f ? flow_first_part(f->data) : NULL;
}

static const byte *
flow_next_part(const byte *pos, const byte *end, int ipv6)
{
  switch (*pos++)
  {
  case FLOW_TYPE_DST_PREFIX:
  case FLOW_TYPE_SRC_PREFIX:
  {
    uint pxlen = *pos++;
    uint bytes = BYTES(pxlen);
    if (ipv6)
    {
      uint offset = *pos++ / 8;
      pos += bytes - offset;
    }
    else
    {
      pos += bytes;
    }
    break;
  }

  case FLOW_TYPE_IP_PROTOCOL: /* == FLOW_TYPE_NEXT_HEADER */
  case FLOW_TYPE_PORT:
  case FLOW_TYPE_DST_PORT:
  case FLOW_TYPE_SRC_PORT:
  case FLOW_TYPE_ICMP_TYPE:
  case FLOW_TYPE_ICMP_CODE:
  case FLOW_TYPE_TCP_FLAGS:
  case FLOW_TYPE_PACKET_LENGTH:
  case FLOW_TYPE_DSCP:
  case FLOW_TYPE_FRAGMENT:
  case FLOW_TYPE_LABEL:
  {
    /* Is this the end of list operator-value pair? */
    uint last = 0;

    while (!last)
    {
      last = isset_end(pos);

      /* Value length of operator */
      uint len = get_value_length(pos);
      pos += 1+len;
    }
    break;
  }
  default:
    return NULL;
  }

  return (pos < end) ? pos : NULL;
}

/**
 * flow4_next_part - an iterator over flowspec components in flowspec binary stream
 * @pos: the beginning of a previous or the first component in flowspec binary
 *       stream
 * @end: the last valid byte in scanned flowspec binary stream
 *
 * This function returns a position to the beginning of the next component
 * (to a component type byte) in flowspec binary stream or %NULL for the end.
 */
inline const byte *
flow4_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 0);
}

/**
 * flow6_next_part - an iterator over flowspec components in flowspec binary stream
 * @pos: the beginning of a previous or the first component in flowspec binary
 *       stream
 * @end: the last valid byte in scanned flowspec binary stream
 *
 * This function returns a position to the beginning of the next component
 * (to a component type byte) in flowspec binary stream or %NULL for the end.
 */
inline const byte *
flow6_next_part(const byte *pos, const byte *end)
{
  return flow_next_part(pos, end, 1);
}

static const byte *
flow_get_part(const byte *data, uint dlen, uint type, int ipv6)
{
  const byte *part;

  for (part = flow_first_part(data);
       part && (part[0] <= type);
       part = flow_next_part(part, data+dlen, ipv6))
    if (part[0] == type)
      return part;

  return NULL;
}

const byte *
flow4_get_part(const net_addr_flow4 *f, uint type)
{
  return flow_get_part(f->data, f->length - sizeof(net_addr_flow4), type, 0);
}

const byte *
flow6_get_part(const net_addr_flow6 *f, uint type)
{
  return flow_get_part(f->data, f->length - sizeof(net_addr_flow6), type, 1);
}


/*
 *	Flowspec accessors
 */

static inline ip4_addr
flow_read_ip4(const byte *px, uint pxlen)
{
  ip4_addr ip = IP4_NONE;
  memcpy(&ip, px, BYTES(pxlen));
  return ip4_ntoh(ip);
}

ip4_addr
flow_read_ip4_part(const byte *part)
{
  return flow_read_ip4(part + 2, part[1]);
}

static inline ip6_addr
flow_read_ip6(const byte *px, uint pxlen, uint pxoffset)
{
  uint floor_offset = BYTES(pxoffset - (pxoffset % 8));
  uint ceil_len = BYTES(pxlen);
  ip6_addr ip = IP6_NONE;

  memcpy(((byte *) &ip) + floor_offset, px, ceil_len - floor_offset);

  return ip6_ntoh(ip);
}

ip6_addr
flow_read_ip6_part(const byte *part)
{
  return flow_read_ip6(part + 3, part[1], part[2]);
}

static uint
get_value(const byte *val, u8 len)
{
  switch (len)
  {
  case 1: return *val;
  case 2: return get_u16(val);
  case 4: return get_u32(val);
  // No component may have length 8
  // case 8: return get_u64(val);
  }

  return 0;
}


/*
 * 	Flowspec validation
 */

static const char* flow_validated_state_str_[] = {
  [FLOW_ST_UNKNOWN_COMPONENT] 		= "Unknown component",
  [FLOW_ST_VALID] 			= "Valid",
  [FLOW_ST_NOT_COMPLETE] 		= "Not complete",
  [FLOW_ST_EXCEED_MAX_PREFIX_LENGTH] 	= "Exceed maximal prefix length",
  [FLOW_ST_EXCEED_MAX_PREFIX_OFFSET]	= "Exceed maximal prefix offset",
  [FLOW_ST_EXCEED_MAX_VALUE_LENGTH]	= "Exceed maximal value length",
  [FLOW_ST_BAD_TYPE_ORDER] 		= "Bad component order",
  [FLOW_ST_AND_BIT_SHOULD_BE_UNSET] 	= "The AND-bit should be unset",
  [FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED] 	= "The Zero-bit should be unset",
  [FLOW_ST_DEST_PREFIX_REQUIRED] 	= "Destination prefix is missing",
  [FLOW_ST_INVALID_TCP_FLAGS]		= "TCP flags exceeding 0xfff",
  [FLOW_ST_CANNOT_USE_DONT_FRAGMENT]    = "Cannot use Don't fragment flag in IPv6 flow"
};

/**
 * flow_validated_state_str - return a textual description of validation process
 * @code: validation result
 *
 * This function return well described validation state in string.
 */
const char *
flow_validated_state_str(enum flow_validated_state code)
{
  return flow_validated_state_str_[code];
}

static const u8 flow4_max_value_length[] = {
  [FLOW_TYPE_DST_PREFIX]	= 0,
  [FLOW_TYPE_SRC_PREFIX]	= 0,
  [FLOW_TYPE_IP_PROTOCOL]	= 1,
  [FLOW_TYPE_PORT]		= 2,
  [FLOW_TYPE_DST_PORT]		= 2,
  [FLOW_TYPE_SRC_PORT]		= 2,
  [FLOW_TYPE_ICMP_TYPE]		= 1,
  [FLOW_TYPE_ICMP_CODE]		= 1,
  [FLOW_TYPE_TCP_FLAGS]		= 2,
  [FLOW_TYPE_PACKET_LENGTH]	= 2,
  [FLOW_TYPE_DSCP]		= 1,
  [FLOW_TYPE_FRAGMENT]		= 1	/* XXX */
};

static const u8 flow6_max_value_length[] = {
  [FLOW_TYPE_DST_PREFIX]	= 0,
  [FLOW_TYPE_SRC_PREFIX]	= 0,
  [FLOW_TYPE_NEXT_HEADER]	= 1,
  [FLOW_TYPE_PORT]		= 2,
  [FLOW_TYPE_DST_PORT]		= 2,
  [FLOW_TYPE_SRC_PORT]		= 2,
  [FLOW_TYPE_ICMP_TYPE]		= 1,
  [FLOW_TYPE_ICMP_CODE]		= 1,
  [FLOW_TYPE_TCP_FLAGS]		= 2,
  [FLOW_TYPE_PACKET_LENGTH]	= 2,
  [FLOW_TYPE_DSCP]		= 1,
  [FLOW_TYPE_FRAGMENT]		= 1,	/* XXX */
  [FLOW_TYPE_LABEL]		= 4
};

static u8
flow_max_value_length(enum flow_type type, int ipv6)
{
  return ipv6 ? flow6_max_value_length[type] : flow4_max_value_length[type];
}

/**
 * flow_check_cf_bmk_values - check value/bitmask part of flowspec component
 * @fb: flow builder instance
 * @neg: negation operand
 * @val: value from value/mask pair
 * @mask: bitmap mask from value/mask pair
 *
 * This function checks value/bitmask pair. If some problem will appear, the
 * function calls cf_error() function with a textual description of reason
 * to failing of validation.
 */
void
flow_check_cf_bmk_values(struct flow_builder *fb, u8 neg, u32 val, u32 mask)
{
  flow_check_cf_value_length(fb, val);
  flow_check_cf_value_length(fb, mask);

  if (neg && !(val == 0 || val == mask))
    cf_error("For negation, value must be zero or bitmask");

  if ((fb->this_type == FLOW_TYPE_TCP_FLAGS) && (mask & 0xf000))
    cf_error("Invalid mask 0x%x, must not exceed 0xfff", mask);

  if ((fb->this_type == FLOW_TYPE_FRAGMENT) && fb->ipv6 && (mask & 0x01))
    cf_error("Invalid mask 0x%x, bit 0 must be 0", mask);

  if (val & ~mask)
    cf_error("Value 0x%x outside bitmask 0x%x", val, mask);
}

/**
 * flow_check_cf_value_length - check value by flowspec component type
 * @fb: flow builder instance
 * @val: value
 *
 * This function checks if the value is in range of component's type support.
 * If some problem will appear, the function calls cf_error() function with
 * a textual description of reason to failing of validation.
 */
void
flow_check_cf_value_length(struct flow_builder *fb, u32 val)
{
  enum flow_type t = fb->this_type;
  u8 max = flow_max_value_length(t, fb->ipv6);

  if (t == FLOW_TYPE_DSCP && val > 0x3f)
    cf_error("%s value %u out of range (0-63)", flow_type_str(t, fb->ipv6), val);

  if (max == 1 && (val > 0xff))
    cf_error("%s value %u out of range (0-255)", flow_type_str(t, fb->ipv6), val);

  if (max == 2 && (val > 0xffff))
    cf_error("%s value %u out of range (0-65535)", flow_type_str(t, fb->ipv6), val);
}

static enum flow_validated_state
flow_validate(const byte *nlri, uint len, int ipv6)
{
  enum flow_type type = 0;
  const byte *pos = nlri;
  const byte *end = nlri + len;

  while (pos < end)
  {
    /* Check increasing type ordering */
    if (*pos <= type)
      return FLOW_ST_BAD_TYPE_ORDER;
    type = *pos++;

    switch (type)
    {
    case FLOW_TYPE_DST_PREFIX:
    case FLOW_TYPE_SRC_PREFIX:
    {
      uint pxlen = *pos++;
      if (pxlen > (ipv6 ? IP6_MAX_PREFIX_LENGTH : IP4_MAX_PREFIX_LENGTH))
	return FLOW_ST_EXCEED_MAX_PREFIX_LENGTH;

      uint bytes = BYTES(pxlen);
      if (ipv6)
      {
        uint pxoffset = *pos++;
        if (pxoffset > IP6_MAX_PREFIX_LENGTH || pxoffset > pxlen)
          return FLOW_ST_EXCEED_MAX_PREFIX_OFFSET;
        bytes -= pxoffset / 8;
      }
      pos += bytes;

      break;
    }

    case FLOW_TYPE_LABEL:
      if (!ipv6)
	return FLOW_ST_UNKNOWN_COMPONENT;
      /* fall through */
    case FLOW_TYPE_IP_PROTOCOL: /* == FLOW_TYPE_NEXT_HEADER */
    case FLOW_TYPE_PORT:
    case FLOW_TYPE_DST_PORT:
    case FLOW_TYPE_SRC_PORT:
    case FLOW_TYPE_ICMP_TYPE:
    case FLOW_TYPE_ICMP_CODE:
    case FLOW_TYPE_TCP_FLAGS:
    case FLOW_TYPE_PACKET_LENGTH:
    case FLOW_TYPE_DSCP:
    case FLOW_TYPE_FRAGMENT:
    {
      uint last = 0;
      uint first = 1;

      while (!last)
      {
	/*
	 *    0   1   2   3   4   5   6   7
	 *  +---+---+---+---+---+---+---+---+
	 *  | e | a |  len  | 0 |lt |gt |eq |
	 *  +---+---+---+---+---+---+---+---+
	 *
	 *           Numeric operator
	 */

	last = isset_end(pos);

	/* The AND bit should in the first operator byte of a sequence */
	if (first && isset_and(pos))
	  return FLOW_ST_AND_BIT_SHOULD_BE_UNSET;

	/* This bit should be zero */
	if (*pos & 0x08)
	  return FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED;

	if (type == FLOW_TYPE_TCP_FLAGS || type == FLOW_TYPE_FRAGMENT)
	{
	  /*
	   *    0   1   2   3   4   5   6   7
	   *  +---+---+---+---+---+---+---+---+
	   *  | e | a |  len  | 0 | 0 |not| m |
	   *  +---+---+---+---+---+---+---+---+
	   *
	   *           Bitmask operand
	   */
	  if (*pos & 0x04)
	    return FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED;
	}

	/* Value length of operator */
	uint len = get_value_length(pos);
	if (len > flow_max_value_length(type, ipv6))
	  return FLOW_ST_EXCEED_MAX_VALUE_LENGTH;

	/* TCP Flags component must not check highest nibble (just 12 valid bits) */
	if ((type == FLOW_TYPE_TCP_FLAGS) && (len == 2) && (pos[1] & 0xf0))
	  return FLOW_ST_INVALID_TCP_FLAGS;

	/* Bit-7 must be 0 [draft-ietf-idr-flow-spec-v6] */
	if ((type == FLOW_TYPE_FRAGMENT) && ipv6 && (pos[1] & 0x01))
	  return FLOW_ST_CANNOT_USE_DONT_FRAGMENT;
	/* XXX: Could be a fragment component encoded in 2-bytes? */

	pos += 1+len;

	if (pos > end && !last)
	  return FLOW_ST_NOT_COMPLETE;

	if (pos > (end+1))
	  return FLOW_ST_NOT_COMPLETE;

	first = 0;
      }
      break;
    }
    default:
      return FLOW_ST_UNKNOWN_COMPONENT;
    }
  }

  if (pos != end)
    return FLOW_ST_NOT_COMPLETE;

  return FLOW_ST_VALID;
}

/**
 * flow4_validate - check untrustworthy IPv4 flowspec data stream
 * @nlri: flowspec data stream without compressed encoded length value
 * @len: length of @nlri
 *
 * This function checks meaningfulness of binary flowspec. It should return
 * %FLOW_ST_VALID or %FLOW_ST_UNKNOWN_COMPONENT. If some problem appears, it
 * returns some other %FLOW_ST_xxx state.
 */
inline enum flow_validated_state
flow4_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 0);
}

/**
 * flow6_validate - check untrustworthy IPv6 flowspec data stream
 * @nlri: flowspec binary stream without encoded length value
 * @len: length of @nlri
 *
 * This function checks meaningfulness of binary flowspec. It should return
 * %FLOW_ST_VALID or %FLOW_ST_UNKNOWN_COMPONENT. If some problem appears, it
 * returns some other %FLOW_ST_xxx state.
 */
inline enum flow_validated_state
flow6_validate(const byte *nlri, uint len)
{
  return flow_validate(nlri, len, 1);
}

/**
 * flow4_validate_cf - validate flowspec data structure &net_addr_flow4 in parsing time
 * @f: flowspec data structure &net_addr_flow4
 *
 * Check if @f is valid flowspec data structure. Can call cf_error() function
 * with a textual description of reason to failing of validation.
 */
void
flow4_validate_cf(net_addr_flow4 *f)
{
  enum flow_validated_state r = flow4_validate(flow4_first_part(f), flow_read_length(f->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}

/**
 * flow6_validate_cf - validate flowspec data structure &net_addr_flow6 in parsing time
 * @f: flowspec data structure &net_addr_flow6
 *
 * Check if @f is valid flowspec data structure. Can call cf_error() function
 * with a textual description of reason to failing of validation.
 */
void
flow6_validate_cf(net_addr_flow6 *f)
{
  enum flow_validated_state r = flow6_validate(flow6_first_part(f), flow_read_length(f->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}


/*
 * 	Flowspec Builder
 */

/**
 * flow_builder_init - constructor for flowspec builder instance
 * @pool: memory pool
 *
 * This function prepares flowspec builder instance using memory pool @pool.
 */
struct flow_builder *
flow_builder_init(pool *pool)
{
  struct flow_builder *fb = mb_allocz(pool, sizeof(struct flow_builder));
  BUFFER_INIT(fb->data, pool, 4);
  return fb;
}

static int
is_stackable_type(enum flow_type type)
{
  switch (type)
  {
  case FLOW_TYPE_IP_PROTOCOL:
  case FLOW_TYPE_PORT:
  case FLOW_TYPE_DST_PORT:
  case FLOW_TYPE_SRC_PORT:
  case FLOW_TYPE_ICMP_TYPE:
  case FLOW_TYPE_ICMP_CODE:
  case FLOW_TYPE_TCP_FLAGS:
  case FLOW_TYPE_PACKET_LENGTH:
  case FLOW_TYPE_DSCP:
  case FLOW_TYPE_FRAGMENT:
  case FLOW_TYPE_LABEL:
    return 1;

  default:
    /* The unknown components are not stack-able in default */
    return 0;
  }
}

static int
builder_add_prepare(struct flow_builder *fb)
{
  if (fb->parts[fb->this_type].length)
  {
    if (fb->last_type != fb->this_type)
      return 0;

    if (!is_stackable_type(fb->this_type))
      return 0;
  }
  else
  {
    fb->parts[fb->this_type].offset = fb->data.used;
  }

  return 1;
}

static void
builder_add_finish(struct flow_builder *fb)
{
  fb->parts[fb->this_type].length = fb->data.used - fb->parts[fb->this_type].offset;
  flow_builder_set_type(fb, fb->this_type);
}

static void
push_pfx_to_buffer(struct flow_builder *fb, u8 pxlen_bytes, byte *ip)
{
  for (int i = 0; i < pxlen_bytes; i++)
    BUFFER_PUSH(fb->data) = *ip++;
}

/**
 * flow_builder4_add_pfx - add IPv4 prefix
 * @fb: flowspec builder instance
 * @n4: net address of type IPv4
 *
 * This function add IPv4 prefix into flowspec builder instance.
 */
int
flow_builder4_add_pfx(struct flow_builder *fb, const net_addr_ip4 *n4)
{
  if (!builder_add_prepare(fb))
    return 0;

  ip4_addr ip4 = ip4_hton(n4->prefix);

  BUFFER_PUSH(fb->data) = fb->this_type;
  BUFFER_PUSH(fb->data) = n4->pxlen;
  push_pfx_to_buffer(fb, BYTES(n4->pxlen), (byte *) &ip4);

  builder_add_finish(fb);
  return 1;
}

/**
 * flow_builder6_add_pfx - add IPv6 prefix
 * @fb: flowspec builder instance
 * @n6: net address of type IPv4
 * @pxoffset: prefix offset for @n6
 *
 * This function add IPv4 prefix into flowspec builder instance. This function
 * should return 1 for successful adding, otherwise returns %0.
 */
int
flow_builder6_add_pfx(struct flow_builder *fb, const net_addr_ip6 *n6, u32 pxoffset)
{
  if (!builder_add_prepare(fb))
    return 0;

  ip6_addr ip6 = ip6_hton(n6->prefix);

  BUFFER_PUSH(fb->data) = fb->this_type;
  BUFFER_PUSH(fb->data) = n6->pxlen;
  BUFFER_PUSH(fb->data) = pxoffset;
  push_pfx_to_buffer(fb, BYTES(n6->pxlen) - (pxoffset / 8), ((byte *) &ip6) + (pxoffset / 8));

  builder_add_finish(fb);
  return 1;
}

/**
 * flow_builder_add_op_val - add operator/value pair
 * @fb: flowspec builder instance
 * @op: operator
 * @value: value
 *
 * This function add operator/value pair as a part of a flowspec component. It
 * is required to set appropriate flowspec component type using function
 * flow_builder_set_type(). This function should return 1 for successful
 * adding, otherwise returns 0.
 */
int
flow_builder_add_op_val(struct flow_builder *fb, byte op, u32 value)
{
  if (!builder_add_prepare(fb))
    return 0;

  if (fb->this_type == fb->last_type)
  {
    /* Remove the end-bit from last operand-value pair of the component */
    fb->data.data[fb->last_op_offset] &= 0x7f;
  }
  else
  {
    BUFFER_PUSH(fb->data) = fb->this_type;
  }

  fb->last_op_offset = fb->data.used;

  /* Set the end-bit for operand-value pair of the component */
  op |= 0x80;

  if (value & 0xff00)
  {
    BUFFER_PUSH(fb->data) = op | 0x10;
    put_u16(BUFFER_INC(fb->data, 2), value);
  }
  else
  {
    BUFFER_PUSH(fb->data) = op;
    BUFFER_PUSH(fb->data) = (u8) value;
  }

  builder_add_finish(fb);
  return 1;
}

/**
 * flow_builder_add_val_mask - add value/bitmask pair
 * @fb: flowspec builder instance
 * @op: operator
 * @value: value
 * @mask: bitmask
 *
 * It is required to set appropriate flowspec component type using function
 * flow_builder_set_type(). Note that for negation, value must be zero or equal
 * to bitmask.
 */
int
flow_builder_add_val_mask(struct flow_builder *fb, byte op, u32 value, u32 mask)
{
  u32 a =  value & mask;
  u32 b = ~value & mask;

  if (a)
  {
    flow_builder_add_op_val(fb, op ^ 0x01, a);
    op |= FLOW_OP_AND;
  }

  if (b)
    flow_builder_add_op_val(fb, op ^ 0x02, b);

  return 1;
}


/**
 * flow_builder_set_type - set type of next flowspec component
 * @fb: flowspec builder instance
 * @type: flowspec component type
 *
 * This function sets type of next flowspec component. It is necessary to call
 * this function before each changing of adding flowspec component.
 */
void
flow_builder_set_type(struct flow_builder *fb, enum flow_type type)
{
  fb->last_type = fb->this_type;
  fb->this_type = type;
}

static void
builder_write_parts(struct flow_builder *fb, byte *buf)
{
  for (int i = 1; i < FLOW_TYPE_MAX; i++)
  {
    if (fb->parts[i].length)
    {
      memcpy(buf, fb->data.data + fb->parts[i].offset, fb->parts[i].length);
      buf += fb->parts[i].length;
    }
  }
}

/**
 * flow_builder4_finalize - assemble final flowspec data structure &net_addr_flow4
 * @fb: flowspec builder instance
 * @lpool: linear memory pool
 *
 * This function returns final flowspec data structure &net_addr_flow4 allocated
 * onto @lpool linear memory pool.
 */
net_addr_flow4 *
flow_builder4_finalize(struct flow_builder *fb, linpool *lpool)
{
  uint data_len = fb->data.used + (fb->data.used < 0xf0 ? 1 : 2);
  net_addr_flow4 *f = lp_alloc(lpool, sizeof(struct net_addr_flow4) + data_len);

  ip4_addr prefix = IP4_NONE;
  uint pxlen = 0;

  if (fb->parts[FLOW_TYPE_DST_PREFIX].length)
  {
    byte *part = fb->data.data + fb->parts[FLOW_TYPE_DST_PREFIX].offset;
    prefix = flow_read_ip4_part(part);
    pxlen = flow_read_pxlen(part);
  }
  *f = NET_ADDR_FLOW4(prefix, pxlen, data_len);

  builder_write_parts(fb, f->data + flow_write_length(f->data, fb->data.used));

  return f;
}

/**
 * flow_builder6_finalize - assemble final flowspec data structure &net_addr_flow6
 * @fb: flowspec builder instance
 * @lpool: linear memory pool for allocation of
 *
 * This function returns final flowspec data structure &net_addr_flow6 allocated
 * onto @lpool linear memory pool.
 */
net_addr_flow6 *
flow_builder6_finalize(struct flow_builder *fb, linpool *lpool)
{
  uint data_len =  fb->data.used + (fb->data.used < 0xf0 ? 1 : 2);
  net_addr_flow6 *n = lp_alloc(lpool, sizeof(net_addr_flow6) + data_len);

  ip6_addr prefix = IP6_NONE;
  uint pxlen = 0;

  if (fb->parts[FLOW_TYPE_DST_PREFIX].length)
  {
    byte *part = fb->data.data + fb->parts[FLOW_TYPE_DST_PREFIX].offset;
    prefix = flow_read_ip6_part(part);
    pxlen = flow_read_pxlen(part);
  }
  *n = NET_ADDR_FLOW6(prefix, pxlen, data_len);

  builder_write_parts(fb, n->data + flow_write_length(n->data, fb->data.used));

  return n;
}

/**
 * flow_builder_clear - flush flowspec builder instance for another flowspec creation
 * @fb: flowspec builder instance
 *
 * This function flushes all data from builder but it maintains pre-allocated
 * buffer space.
 */
void
flow_builder_clear(struct flow_builder *fb)
{
  BUFFER(byte) data;
  BUFFER_FLUSH(fb->data);

  BUFFER_SHALLOW_COPY(data, fb->data);
  memset(fb, 0, sizeof(struct flow_builder));
  BUFFER_SHALLOW_COPY(fb->data, data);
}


/*
 *	Flowspec explication
 */

/**
 * flow_explicate_buffer_size - return buffer size needed for explication
 * @part: flowspec part to explicate
 *
 * This function computes and returns a required buffer size that has to be
 * preallocated and passed to flow_explicate_part(). Note that it returns number
 * of records, not number of bytes.
 */
uint
flow_explicate_buffer_size(const byte *part)
{
  const byte *pos = part + 1;
  uint first = 1;
  uint len = 0;

  while (1)
  {
    /*
     * Conjunction sequences represent (mostly) one interval, do not count
     * additional AND-ed operators. Ignore AND bit for the first operator.
     */
    if (!isset_and(pos) || first)
      len++;

    /*
     * The exception is that NEQ operator adds one more interval (by splitting
     * one of intervals defined by other operators).
     */
    if (num_op(pos) == FLOW_OP_NEQ)
      len++;

    if (isset_end(pos))
      break;

    first = 0;
    pos = pos + 1 + get_value_length(pos);
  }

  return len;
}

static int flow_uint_cmp(const void *p1, const void *p2)
{ return uint_cmp(* (const uint *) p1, * (const uint *) p2); }

/**
 * flow_explicate_part - compute explicit interval list from flowspec part
 * @part: flowspec part to explicate
 * @buf: pre-allocated buffer for result
 *
 * This function analyzes a flowspec part with numeric operators (e.g. port) and
 * computes an explicit interval list of allowed values. The result is written
 * to provided buffer @buf, which must have space for enough interval records as
 * returned by flow_explicate_buffer_size(). The intervals are represented as
 * two-sized arrays of lower and upper bound, both including. The return value
 * is the number of intervals in the buffer.
 */
uint
flow_explicate_part(const byte *part, uint (*buf)[2])
{
  /*
   * The Flowspec numeric expression is almost in DNF form (as union of
   * intersections), where each operator represents one elementary interval.
   * The exception is NEQ operator, which represents union of two intervals,
   * separated by the excluded value. Naive algorithm would be like:
   *
   * A <- empty set of intervals
   * for each sequence of operators in conjunction
   * {
   *   B <- empty set of intervals
   *   for each operator in the current sequence
   *   {
   *     C <- one or two elementary intervals from the current operator
   *     B <- intersection(B, C)
   *   }
   *   A <- union(A, B)
   * }
   *
   * We simplify this by representing B just as one interval (vars lo, hi) and a
   * list of excluded values. After the inner cycle, we expand that to a proper
   * list of intervals that is added to existing ones from previous cycles.
   * Finally, we sort and merge intersecting or touching intervals in A.
   *
   * The code handles up to 32bit values in numeric operators. Intervals are
   * represented by lower and upper bound, both including. Intermediate values
   * use s64 to simplify representation of excluding bounds for 0 and UINT32_MAX.
   */

  const byte *pos = part + 1;
  const s64 max = 0xffffffff;
  s64 lo = 0;
  s64 hi = max;
  uint num = 0;
  uint neqs = 0;

  /* Step 1 - convert conjunction sequences to lists of intervals */
  while (1)
  {
    uint op = num_op(pos);
    uint len = get_value_length(pos);
    s64  val = get_value(pos + 1, len);
    uint last = isset_end(pos);
    const byte *next_pos = pos + 1 + len;

    /* Get a new interval from this operator */
    s64 nlo = (op & FLOW_OP_LT) ? 0   : ((op & FLOW_OP_EQ) ? val : (val + 1));
    s64 nhi = (op & FLOW_OP_GT) ? max : ((op & FLOW_OP_EQ) ? val : (val - 1));

    /* Restrict current interval */
    lo = MAX(lo, nlo);
    hi = MIN(hi, nhi);

    /* Store NEQs for later */
    if (op == FLOW_OP_NEQ)
    {
      buf[num + neqs][0] = val;
      buf[num + neqs][1] = 0;
      neqs++;
    }

    /* End of conjunction sequence */
    if (last || !isset_and(next_pos))
    {
      if (neqs)
      {
	/* Sort stored NEQs */
	qsort(buf + num, neqs, 2 * sizeof(uint), flow_uint_cmp);

	/* Dump stored NEQs as intervals */
	uint base = num;
	for (uint i = 0; i < neqs; i++)
	{
	  val = buf[base + i][0];

	  if ((val < lo) || (val > hi))
	    continue;

	  if (val == lo)
	  { lo++; continue; }

	  if (val == hi)
	  { hi--; continue; }

	  buf[num][0] = lo;
	  buf[num][1] = val - 1;
	  num++;

	  lo = val + 1;
	}

	neqs = 0;
      }

      /* Save final interval */
      if (lo <= hi)
      {
	buf[num][0] = lo;
	buf[num][1] = hi;
	num++;
      }

      lo = 0;
      hi = max;
    }

    if (last)
      break;

    pos = next_pos;
  }

  if (num < 2)
    return num;

  /* Step 2 - Sort and merge list of intervals */
  qsort(buf, num, 2 * sizeof(uint), flow_uint_cmp);

  uint i = 0, j = 0;
  while (i < num)
  {
    lo = buf[i][0];
    hi = buf[i][1];
    i++;

    /* If intervals are intersecting or just touching, merge them */
    while ((i < num) && ((s64) buf[i][0] <= (hi + 1)))
    {
      hi = MAX(hi, (s64) buf[i][1]);
      i++;
    }

    buf[j][0] = lo;
    buf[j][1] = hi;
    j++;
  }

  return j;
}


/*
 * 	Net Formatting
 */

/* Flowspec operators for [op, value]+ pairs */

static const char *
num_op_str(const byte *op)
{
  switch (*op & 0x07)
  {
  case FLOW_OP_TRUE:	return "true";
  case FLOW_OP_EQ:	return "=";
  case FLOW_OP_GT:	return ">";
  case FLOW_OP_GEQ:	return ">=";
  case FLOW_OP_LT:	return "<";
  case FLOW_OP_LEQ:	return "<=";
  case FLOW_OP_NEQ:	return "!=";
  case FLOW_OP_FALSE:	return "false";
  }

  return NULL;
}

static const char *
fragment_val_str(u8 val)
{
  switch (val)
  {
  case 1: return "dont_fragment";
  case 2: return "is_fragment";
  case 4: return "first_fragment";
  case 8: return "last_fragment";
  }
  return "???";
}

static void
net_format_flow_ip(buffer *b, const byte *part, int ipv6)
{
  uint pxlen = part[1];
  if (ipv6)
  {
    uint pxoffset = part[2];
    if (pxoffset)
      buffer_print(b, "%I6/%u offset %u; ", flow_read_ip6_part(part), pxlen, pxoffset);
    else
      buffer_print(b, "%I6/%u; ", flow_read_ip6_part(part), pxlen);
  }
  else
  {
    buffer_print(b, "%I4/%u; ", flow_read_ip4_part(part), pxlen);
  }
}

static void
net_format_flow_num(buffer *b, const byte *part)
{
  const byte *last_op = NULL;
  const byte *op = part+1;
  uint val;
  uint len;
  uint first = 1;

  while (1)
  {
    if (!first)
    {
      /* XXX: I don't like this so complicated if-tree */
      if (!isset_and(op) &&
	  ((num_op(     op) == FLOW_OP_EQ) || (num_op(     op) == FLOW_OP_GEQ)) &&
	  ((num_op(last_op) == FLOW_OP_EQ) || (num_op(last_op) == FLOW_OP_LEQ)))
      {
	b->pos--; /* Remove last char (it is a space) */
	buffer_puts(b, ",");
      }
      else
      {
	buffer_puts(b, isset_and(op) ? "&& " : "|| ");
      }
    }
    first = 0;

    len = get_value_length(op);
    val = get_value(op+1, len);

    if (!isset_end(op) && !isset_and(op) && isset_and(op+1+len) &&
	(num_op(op) == FLOW_OP_GEQ) && (num_op(op+1+len) == FLOW_OP_LEQ))
    {
      /* Display interval */
      buffer_print(b, "%u..", val);
      op += 1 + len;
      len = get_value_length(op);
      val = get_value(op+1, len);
      buffer_print(b, "%u", val);
    }
    else if (num_op(op) == FLOW_OP_EQ)
    {
      buffer_print(b, "%u", val);
    }
    else
    {
      buffer_print(b, "%s %u", num_op_str(op), val);
    }

    if (isset_end(op))
    {
      buffer_puts(b, "; ");
      break;
    }
    else
    {
      buffer_puts(b, " ");
    }

    last_op = op;
    op += 1 + len;
  }
}

static void
net_format_flow_bitmask(buffer *b, const byte *part)
{
  const byte *op = part+1;
  uint val;
  uint len;
  uint first = 1;

  while (1)
  {
    if (!first)
      buffer_puts(b, isset_and(op) ? "&& " : "|| ");

    first = 0;

    len = get_value_length(op);
    val = get_value(op+1, len);

    /*
     *   Not Match  Show
     *  ------------------
     *    0    0    !0/B
     *    0    1     B/B
     *    1    0     0/B
     *    1    1    !B/B
     */

    if ((*op & 0x3) == 0x3 || (*op & 0x3) == 0)
      buffer_puts(b, "!");

    if (*part == FLOW_TYPE_FRAGMENT && (val == 1 || val == 2 || val == 4 || val == 8))
      buffer_print(b, "%s%s", ((*op & 0x1) ? "" : "!"), fragment_val_str(val));
    else
      buffer_print(b, "0x%x/0x%x", ((*op & 0x1) ? val : 0), val);

    if (isset_end(op))
    {
      buffer_puts(b, "; ");
      break;
    }
    else
    {
      buffer_puts(b, " ");
    }

    op += 1 + len;
  }
}

static uint
net_format_flow(char *buf, uint blen, const byte *data, uint dlen, int ipv6)
{
  buffer b = {
    .start = buf,
    .pos = buf,
    .end = buf + blen,
  };

  const byte *part = flow_first_part(data);
  *buf = 0;

  if (ipv6)
    buffer_puts(&b, "flow6 { ");
  else
    buffer_puts(&b, "flow4 { ");

  while (part)
  {
    buffer_print(&b, "%s ", flow_type_str(*part, ipv6));

    switch (*part)
    {
    case FLOW_TYPE_DST_PREFIX:
    case FLOW_TYPE_SRC_PREFIX:
      net_format_flow_ip(&b, part, ipv6);
      break;
    case FLOW_TYPE_IP_PROTOCOL: /* == FLOW_TYPE_NEXT_HEADER */
    case FLOW_TYPE_PORT:
    case FLOW_TYPE_DST_PORT:
    case FLOW_TYPE_SRC_PORT:
    case FLOW_TYPE_ICMP_TYPE:
    case FLOW_TYPE_ICMP_CODE:
    case FLOW_TYPE_PACKET_LENGTH:
    case FLOW_TYPE_DSCP:
    case FLOW_TYPE_LABEL:
      net_format_flow_num(&b, part);
      break;
    case FLOW_TYPE_TCP_FLAGS:
    case FLOW_TYPE_FRAGMENT:
      net_format_flow_bitmask(&b, part);
      break;
    }

    part = flow_next_part(part, data+dlen, ipv6);
  }

  buffer_puts(&b, "}");

  if (b.pos == b.end)
  {
    b.pos = b.start + MIN(blen - 6, strlen(b.start));
    buffer_puts(&b, " ...}");
  }

  return b.pos - b.start;
}

/**
 * flow4_net_format - stringify flowspec data structure &net_addr_flow4
 * @buf: pre-allocated buffer for writing a stringify net address flowspec
 * @blen: free allocated space in @buf
 * @f: flowspec data structure &net_addr_flow4 for stringify
 *
 * This function writes stringified @f into @buf. The function returns number
 * of written chars. If final string is too large, the string will ends the with
 * ' ...}' sequence and zero-terminator.
 */
uint
flow4_net_format(char *buf, uint blen, const net_addr_flow4 *f)
{
  return net_format_flow(buf, blen, f->data, f->length - sizeof(net_addr_flow4), 0);
}

/**
 * flow6_net_format - stringify flowspec data structure &net_addr_flow6
 * @buf: pre-allocated buffer for writing a stringify net address flowspec
 * @blen: free allocated space in @buf
 * @f: flowspec data structure &net_addr_flow4 for stringify
 *
 * This function writes stringified @f into @buf. The function returns number
 * of written chars. If final string is too large, the string will ends the with
 * ' ...}' sequence and zero-terminator.
 */
uint
flow6_net_format(char *buf, uint blen, const net_addr_flow6 *f)
{
  return net_format_flow(buf, blen, f->data, f->length - sizeof(net_addr_flow6), 1);
}

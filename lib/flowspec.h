/*
 *	BIRD Library -- Flow specification (RFC 5575)
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_FLOWSPEC_H_
#define _BIRD_FLOWSPEC_H_

#include "nest/bird.h"
#include "lib/buffer.h"
#include "lib/net.h"


/* Flow component operators */
#define FLOW_OP_FALSE		0x00	/* 0b000 */
#define FLOW_OP_EQ		0x01	/* 0b001 */
#define FLOW_OP_GT		0x02	/* 0b010 */
#define FLOW_OP_GEQ		0x03	/* 0b011 */
#define FLOW_OP_LT		0x04	/* 0b100 */
#define FLOW_OP_LEQ		0x05	/* 0b101 */
#define FLOW_OP_NEQ		0x06	/* 0b110 */
#define FLOW_OP_TRUE		0x07	/* 0b111 */

#define FLOW_OP_OR		0x00
#define FLOW_OP_AND		0x40


/* Types of components in flowspec */
enum flow_type {
  FLOW_TYPE_DST_PREFIX 		=  1,
  FLOW_TYPE_SRC_PREFIX 		=  2,
  FLOW_TYPE_IP_PROTOCOL 	=  3,
  FLOW_TYPE_NEXT_HEADER 	=  3,	/* IPv6 */
  FLOW_TYPE_PORT 		=  4,
  FLOW_TYPE_DST_PORT 		=  5,
  FLOW_TYPE_SRC_PORT 		=  6,
  FLOW_TYPE_ICMP_TYPE 		=  7,
  FLOW_TYPE_ICMP_CODE 		=  8,
  FLOW_TYPE_TCP_FLAGS 		=  9,
  FLOW_TYPE_PACKET_LENGTH 	= 10,
  FLOW_TYPE_DSCP 		= 11,	/* DiffServ Code Point */
  FLOW_TYPE_FRAGMENT 		= 12,
  FLOW_TYPE_LABEL 		= 13,	/* IPv6 */
  FLOW_TYPE_MAX
};

const char *flow_type_str(enum flow_type type, int ipv6);


/*
 * 	Length
 */

uint flow_write_length(byte *data, u16 len);

static inline u16 flow_hdr_length(const byte *data)
{ return ((*data & 0xf0) == 0xf0) ? 2 : 1; }

static inline u16 flow_read_length(const byte *data)
{ return ((*data & 0xf0) == 0xf0) ? get_u16(data) & 0x0fff : *data; }

static inline u16 flow4_get_length(const net_addr_flow4 *f)
{ return f->length - sizeof(net_addr_flow4); }

static inline u16 flow6_get_length(const net_addr_flow6 *f)
{ return f->length - sizeof(net_addr_flow6); }

static inline void flow4_set_length(net_addr_flow4 *f, u16 len)
{ f->length = sizeof(net_addr_flow4) + flow_write_length(f->data, len) + len; }

static inline void flow6_set_length(net_addr_flow6 *f, u16 len)
{ f->length = sizeof(net_addr_flow6) + flow_write_length(f->data, len) + len; }


/*
 * 	Iterators
 */

const byte *flow4_first_part(const net_addr_flow4 *f);
const byte *flow6_first_part(const net_addr_flow6 *f);
const byte *flow4_next_part(const byte *pos, const byte *end);
const byte *flow6_next_part(const byte *pos, const byte *end);
const byte *flow4_get_part(const net_addr_flow4 *f, uint type);
const byte *flow6_get_part(const net_addr_flow6 *f, uint type);


/*
 *	Flowspec accessors
 */

ip4_addr flow_read_ip4_part(const byte *part);
ip6_addr flow_read_ip6_part(const byte *part);
static inline int flow_read_pxlen(const byte *part) { return part[1]; }


/*
 * 	Flowspec Builder
 */

/* A data structure for keep a state of flow builder */
struct flow_builder {
  BUFFER_(byte) data;
  enum flow_type this_type;
  enum flow_type last_type;
  u16 last_op_offset;			/* Position of last operator in data.data */
  int ipv6;
  struct {
    u16 offset;				/* Beginning of a component */
    u16 length;				/* Length of a component */
  } parts[FLOW_TYPE_MAX];		/* Indexing all components */
};

struct flow_builder *flow_builder_init(pool *pool);
void flow_builder_clear(struct flow_builder *fb);
void flow_builder_set_type(struct flow_builder *fb, enum flow_type p);
int flow_builder4_add_pfx(struct flow_builder *fb, const net_addr_ip4 *n4);
int flow_builder6_add_pfx(struct flow_builder *fb, const net_addr_ip6 *n6, u32 offset);
int flow_builder_add_op_val(struct flow_builder *fb, byte op, u32 value);
int flow_builder_add_val_mask(struct flow_builder *fb, byte op, u32 value, u32 mask);
net_addr_flow4 *flow_builder4_finalize(struct flow_builder *fb, linpool *lpool);
net_addr_flow6 *flow_builder6_finalize(struct flow_builder *fb, linpool *lpool);


/*
 * 	Validation
 */

/* Results of validation Flow specification */
enum flow_validated_state {
  FLOW_ST_UNKNOWN_COMPONENT,
  FLOW_ST_VALID,
  FLOW_ST_NOT_COMPLETE,
  FLOW_ST_EXCEED_MAX_PREFIX_LENGTH,
  FLOW_ST_EXCEED_MAX_PREFIX_OFFSET,
  FLOW_ST_EXCEED_MAX_VALUE_LENGTH,
  FLOW_ST_BAD_TYPE_ORDER,
  FLOW_ST_AND_BIT_SHOULD_BE_UNSET,
  FLOW_ST_ZERO_BIT_SHOULD_BE_UNSED,
  FLOW_ST_DEST_PREFIX_REQUIRED,
  FLOW_ST_INVALID_TCP_FLAGS,
  FLOW_ST_CANNOT_USE_DONT_FRAGMENT
};

const char *flow_validated_state_str(enum flow_validated_state code);
enum flow_validated_state flow4_validate(const byte *nlri, uint len);
enum flow_validated_state flow6_validate(const byte *nlri, uint len);
void flow_check_cf_value_length(struct flow_builder *fb, u32 expr);
void flow_check_cf_bmk_values(struct flow_builder *fb, u8 neg, u32 val, u32 mask);
void flow4_validate_cf(net_addr_flow4 *f);
void flow6_validate_cf(net_addr_flow6 *f);


/*
 * 	Net Formatting
 */

uint flow4_net_format(char *buf, uint blen, const net_addr_flow4 *f);
uint flow6_net_format(char *buf, uint blen, const net_addr_flow6 *f);

#endif /* _BIRD_FLOWSPEC_H_ */

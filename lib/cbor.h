#ifndef CBOR_H
#define CBOR_H

#include "nest/bird.h"

enum cbor_basic_type {
  CBOR_POSINT = 0,
  CBOR_NEGINT = 1,
  CBOR_BYTES = 2,
  CBOR_TEXT = 3,
  CBOR_ARRAY = 4,
  CBOR_MAP = 5,
  CBOR_TAG = 6,
  CBOR_SPECIAL = 7,
};

const char *cbor_type_str(enum cbor_basic_type);

struct cbor_writer {
  int pt; // where will next byte go
  int capacity;
  int8_t *cbor;
  struct linpool *lp;
};


struct cbor_writer *cbor_init(uint8_t *buff, uint32_t capacity, struct linpool *lp);
  
void cbor_open_block(struct cbor_writer *writer);

void cbor_open_list(struct cbor_writer *writer);

void cbor_close_block_or_list(struct cbor_writer *writer);

void cbor_open_block_with_length(struct cbor_writer *writer, uint32_t length);

void cbor_open_list_with_length(struct cbor_writer *writer, uint32_t length);


void cbor_add_int(struct cbor_writer *writer, int64_t item);

void cbor_add_ipv4(struct cbor_writer *writer, ip4_addr);

void cbor_add_ipv6(struct cbor_writer *writer, ip6_addr);

void cbor_epoch_time(struct cbor_writer *writer, int64_t time, int shift);

void cbor_relativ_time(struct cbor_writer *writer, int64_t time, int shift);

void cbor_add_ipv4_prefix(struct cbor_writer *writer, net_addr_ip4 *n);


void cbor_add_ipv6_prefix(struct cbor_writer *writer, net_addr_ip6 *n);


void cbor_add_uint(struct cbor_writer *writer, uint64_t item);

void cbor_add_tag(struct cbor_writer *writer, int item);

void cbor_add_string(struct cbor_writer *writer, const char *string);

void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint32_t length);

void write_item(struct cbor_writer *writer, uint8_t major, uint64_t num);

void cbor_write_item_with_constant_val_length_4(struct cbor_writer *writer, uint8_t major, uint64_t num);

void rewrite_4bytes_int(struct cbor_writer *writer, int pt, int num);

/*
 * Parser bits
 */

struct cbor_parser_context {
  /* Public part */
  linpool *lp;			/* Linpool for in-parser allocations */

  byte type;			/* Last parsed type */
  enum {
    CPT_VARLEN = 1,
  } tflags;			/* Additional flags for the type / value pair */
  u64 value;			/* Last parsed (integer) value */

  byte *target_buf;		/* Target buf for CBOR_BYTES or CBOR_TEXT */
  uint target_len;		/* Set how many bytes to store */

  const char *error;		/* Error message */

  /* Private part */
  lp_state *flush;		/* Linpool reset pointer */

  enum {			/* Multi-byte reader */
    CPE_TYPE = 0,
    CPE_READ_INT,
    CPE_COMPLETE_INT,
    CPE_READ_BYTE,
    CPE_ITEM_DONE,
    CPE_EXIT,
  } partial_state;

  u64 partial_countdown;	/* How many items remaining in CBOR_ARRAY / CBOR_MAP */

  uint stack_pos, stack_max;	/* Nesting of CBOR_ARRAY / CBOR_MAP */
  u64 stack_countdown[0];
};

struct cbor_parser_context *cbor_parser_new(pool *, uint stack_max_depth);
static inline void cbor_parser_free(struct cbor_parser_context *ctx)
{ rfree(ctx->lp); }
void cbor_parser_reset(struct cbor_parser_context *ctx);

enum cbor_parse_result {
  CPR_ERROR	= 0,
  CPR_MORE	= 1,
  CPR_MAJOR	= 2,
  CPR_STR_END	= 3,
} cbor_parse_byte(struct cbor_parser_context *, const byte);
bool cbor_parse_block_end(struct cbor_parser_context *);

#define CBOR_PARSE_IF(_ctx, _type, _target)  if (((_ctx)->type == CBOR_##_type) && CBOR_STORE_##_type((_ctx), _target))
#define CBOR_PARSE_ONLY(_ctx, _type, _target) CBOR_PARSE_IF(_ctx, _type, _target) {} else CBOR_PARSER_ERROR("Expected %s for %s, got %s", #_type, #_target, cbor_type_str((_ctx)->type))

#define CBOR_STORE_POSINT(_ctx, _target)  ((_target = (_ctx)->value), 1)
#define CBOR_STORE_NEGINT(_ctx, _target)  ((_target = -1LL-(_ctx)->value), 1)
#define CBOR_STORE_BYTES(_ctx, _target)   ({ \
    if ((_ctx)->tflags & CPT_VARLEN) CBOR_PARSER_ERROR("Variable length string not supported yet"); \
    if ((_target)) CBOR_PARSER_ERROR("Duplicate argument %s", #_target); \
    ASSERT_DIE(!(_ctx)->target_buf); \
    _target = (_ctx)->target_buf = lp_alloc((_ctx)->lp, ((_ctx)->target_len = (_ctx)->value) + 1); \
    1; })
#define CBOR_STORE_TEXT CBOR_STORE_BYTES


#endif

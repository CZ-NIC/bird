#ifndef CBOR_H
#define CBOR_H

#include "nest/bird.h"

/**
 * CBOR Commonalities
 **/

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

/**
 * CBOR Writer
 **/

struct cbor_writer {
  buffer data;
  uint stack_pos, stack_max;	/* Nesting of CBOR_ARRAY / CBOR_MAP */
  struct cbor_writer_stack_item {
    u64 items;
    byte *head;
  } stack[0];
};

/* Initialization */
static inline struct cbor_writer *cbor_writer_init(struct cbor_writer *w, uint stack_max_depth, byte *buf, uint size)
{
  *w = (struct cbor_writer) {
    .data = {
      .start = buf,
      .pos = buf,
      .end = buf + size,
    },
    .stack_max = stack_max_depth,
  };
  return w;
}

#define cbor_writer_new(p, smax, buf, size) cbor_writer_init(mb_alloc((p), sizeof(struct cbor_writer) + (smax) * sizeof(struct cbor_writer_stack_item)), (smax), (buf), (size))


/* Return how many items have been encoded */
static inline int cbor_writer_done(struct cbor_writer *w)
{
  if (w->stack_pos > 0)
    return -1;
  else
    return w->stack[0].items;
}

/* Integer types */
bool cbor_put(struct cbor_writer *w, enum cbor_basic_type type, u64 value);
#define cbor_put_posint(w,v)  cbor_put((w), CBOR_POSINT, (v))
#define cbor_put_negint(w,v)  cbor_put((w), CBOR_NEGINT, -1-(v))
bool cbor_put_int(struct cbor_writer *w, int64_t value);

/* String types */
bool cbor_put_raw_bytes(struct cbor_writer *w, enum cbor_basic_type type, const byte *block, u64 size);
#define cbor_put_bytes(w, b, s)	cbor_put_raw_bytes((w), CBOR_BYTES, (b), (s))
#define cbor_put_text(w, b, s)	cbor_put_raw_bytes((w), CBOR_TEXT, (b), (s))
#define cbor_put_string(w, s)	cbor_put_raw_bytes((w), CBOR_TEXT, (s), strlen(s))
#define cbor_put_toks(w, s)	cbor_put_raw_bytes((w), CBOR_TEXT, #s, sizeof #s)

/* Compound types */
bool cbor_put_open(struct cbor_writer *w, enum cbor_basic_type type);
bool cbor_put_close(struct cbor_writer *w, u64 actual_size, bool strict);
#define cbor_open_array(w)	cbor_put_open((w), CBOR_ARRAY)
#define cbor_open_map(w)	cbor_put_open((w), CBOR_MAP)

#define cbor_close_array(w)	cbor_put_close((w), 0, 0)
#define cbor_close_map(w)	cbor_put_close((w), 0, 0)

#define CBOR_PUT_ARRAY(w) for (struct cbor_writer *_w = w, *_ww = cbor_open_array(_w) ? (_w) : (bug("buffer overflow on CBOR_ARRAY"), NULL); (_w = NULL), _ww; cbor_close_array(_ww), _ww = NULL)

#define CBOR_PUT_MAP(w) for (struct cbor_writer *_w = w, *_ww = cbor_open_map(_w) ? (_w) : (bug("buffer overflow on CBOR_MAP"), NULL); (_w = NULL), _ww; cbor_close_map(_ww), _ww = NULL)

/* Specials */
#define cbor_put_false(w)	cbor_put((w), CBOR_SPECIAL, 20);
#define cbor_put_true(w)	cbor_put((w), CBOR_SPECIAL, 21);
#define cbor_put_null(w)	cbor_put((w), CBOR_SPECIAL, 22);
#define cbor_put_undef(w)	cbor_put((w), CBOR_SPECIAL, 23);

#if 0
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
#endif

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

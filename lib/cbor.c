/*
 *	BIRD CBOR parser and writer
 *
 *	(c) 2023--2024 Katerina Kubecova <katerina.kubecova@nic.cz>
 *	(c) 2024--2026 Maria Matejka <mq@jmq.cz>
 *	(c) 2023--2026 CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdint.h>
#include <string.h>

#include "lib/cbor.h"

/* String versions of type constants */
static const char *cbor_type_str_a[] = {
  "POSINT",
  "NEGINT",
  "BYTES",
  "TEXT",
  "ARRAY",
  "MAP",
  "TAG",
  "SPECIAL",
};

const char *
cbor_type_str(enum cbor_basic_type t)
{
  return (t < ARRAY_SIZE(cbor_type_str_a)) ?
    cbor_type_str_a[t] :
    tmp_sprintf("(unknown: %u)", t);
}

/* Raw data writing */

bool cbor_put_check(struct cbor_writer *w, u64 amount)
{
  return w->data.pos + amount <= w->data.end;
}

#define CBOR_PUT(amount) ({					\
    byte *put = w->data.pos;					\
    if ((w->data.pos += (amount)) >= w->data.end) return false;	\
    put; })

bool cbor_put_raw_u8(struct cbor_writer *w, byte b)
{
  *(CBOR_PUT(1)) = b;
  return true;
}

bool cbor_put_raw_u16(struct cbor_writer *w, u16 val)
{
  put_u16(CBOR_PUT(2), val);
  return true;
}

bool cbor_put_raw_u32(struct cbor_writer *w, u32 val)
{
  put_u32(CBOR_PUT(4), val);
  return true;
}

bool cbor_put_raw_u64(struct cbor_writer *w, u64 val)
{
  put_u64(CBOR_PUT(8), val);
  return true;
}

bool cbor_put_raw_data(struct cbor_writer *w, const byte *block, u64 size)
{
  memcpy(CBOR_PUT(size), block, size);
  return true;
}

/* Basic value putting */
bool cbor_put(struct cbor_writer *w, enum cbor_basic_type type, u64 value)
{
  ASSERT_DIE((type >= 0) && (type <= 8));
  w->stack[w->stack_pos].items++;
  byte tt = type << 5;
  if (value < 0x18)
    return
      cbor_put_raw_u8(w, tt | value);
  else if (value < 0x100)
    return
      cbor_put_raw_u8(w, tt | 0x18) &&
      cbor_put_raw_u8(w, value);
  else if (value < 0x10000)
    return
      cbor_put_raw_u8(w, tt | 0x19) &&
      cbor_put_raw_u16(w, value);
  else if (value < 0x100000000)
    return
      cbor_put_raw_u8(w, tt | 0x1a) &&
      cbor_put_raw_u32(w, value);
  else
    return
      cbor_put_raw_u8(w, tt | 0x1b) &&
      cbor_put_raw_u64(w, value);
}

bool cbor_put_int(struct cbor_writer *w, int64_t value)
{
  if (value >= 0)
    return cbor_put(w, CBOR_POSINT, value);
  else
    return cbor_put(w, CBOR_NEGINT, -1-value);
}

/* Strings */
bool cbor_put_raw_bytes(struct cbor_writer *w, enum cbor_basic_type type, const byte *block, u64 size)
{
  return
    cbor_put(w, type, size) &&
    cbor_put_raw_data(w, block, size);
}

/* Arrays and maps */
bool cbor_put_open(struct cbor_writer *w, enum cbor_basic_type type)
{
  if (++w->stack_pos >= w->stack_max)
    return false;

  w->stack[w->stack_pos].head = w->data.pos;
  w->stack[w->stack_pos].items = 0;

  return cbor_put(w, type, ~0ULL);
}

bool cbor_put_close(struct cbor_writer *w, u64 actual_size, bool strict)
{
  ASSERT_DIE(w->stack_pos > 0);

  /* Pop the stack */
  byte *head = w->stack[w->stack_pos].head;
  u64 items = w->stack[w->stack_pos].items;

  w->stack_pos--;

  /* Check the original head position */
  ASSERT_DIE((head[0] & 0x1f) == 0x1f);
  ASSERT_DIE(w->data.pos >= w->data.start + 9);
  switch (head[0] >> 5)
  {
    case CBOR_ARRAY:
      if (strict && (items != actual_size))
	bug("Inconsistent array item count");
      break;

    case CBOR_MAP:
      if (strict && (items != actual_size * 2))
	bug("Inconsistent map item count");
      else if (items & 1)
	bug("Trailing map key");
      else
	items /= 2;
      break;

    default:
      bug("Head points to something other than array or map");
  }

  /* Move the data back */

  if (items < 0x18)
  {
    memmove(head+1, head+9, w->data.pos - (head+9));
    head[0] &= (0xe0 | items);
    w->data.pos -= 8;
  }
  else if (items < 0x100)
  {
    memmove(head+2, head+9, w->data.pos - (head+9));
    head[0] &= 0xf8;
    head[1] = items;
    w->data.pos -= 7;
  }
  else if (items < 0x10000)
  {
    memmove(head+3, head+9, w->data.pos - (head+9));
    head[0] &= 0xf9;
    put_u16(head+1, items);
    w->data.pos -= 6;
  }
  else if (items < 0x100000000)
  {
    memmove(head+5, head+9, w->data.pos - (head+9));
    head[0] &= 0xfa;
    put_u32(head+1, items);
    w->data.pos -= 4;
  }
  else
  {
    head[0] &= 0xfb;
    put_u64(head+1, items);
  }

  return true;
}

/* Tags: TODO! */


struct cbor_parser_context *
cbor_parser_new(pool *p, uint stack_max_depth)
{
  linpool *lp = lp_new(p);
  struct cbor_parser_context *ctx = lp_allocz(
      lp, sizeof *ctx + (stack_max_depth + 1) * sizeof ctx->stack_countdown[0]);

  ctx->lp = lp;
  ctx->flush = lp_save(lp);

  ctx->type = 0xff;
  ctx->stack_countdown[0] = 1;
  ctx->stack_max = stack_max_depth;

  return ctx;
}

void cbor_parser_reset(struct cbor_parser_context *ctx)
{
  lp_restore(ctx->lp, ctx->flush);
  ctx->flush = lp_save(ctx->lp);

  ctx->type = 0xff;
  ctx->target_buf = NULL;
  ctx->target_len = 0;
  ctx->error = NULL;
  ctx->partial_state = CPE_TYPE;
  ctx->partial_countdown = 0;
  ctx->stack_pos = 0;
  ctx->stack_countdown[0] = 1;
}

#define CBOR_PARSER_ERROR(...) do {		\
  ctx->error = lp_sprintf(ctx->lp, __VA_ARGS__);\
  return CPR_ERROR;				\
} while (0)

enum cbor_parse_result
cbor_parse_byte(struct cbor_parser_context *ctx, const byte bp)
{
  ctx->tflags = 0;

  switch (ctx->partial_state)
  {
    case CPE_EXIT:
      CBOR_PARSER_ERROR("Trailing byte %02x", bp);

    case CPE_ITEM_DONE:
      bug("You have to check cbor_parse_block_end() before running cbor_parse_byte()");

    case CPE_TYPE:
      /* Split the byte to type and value */
      ctx->type = bp >> 5;
      ctx->value = bp & 0x1f;

      if (ctx->type == 7)
      {
	if (ctx->value < 20)
	  CBOR_PARSER_ERROR("Unknown simple value %u", ctx->value);
	else if (ctx->value < 24)
	  ; /* false, true, null, undefined */
	else if (ctx->value < 28)
	{
	  /* Need more data */
	  ctx->partial_state = CPE_READ_INT;
	  ctx->partial_countdown = (1 << (ctx->value - 24));
	  ctx->value = 0;
	  break;
	}
	else if (ctx->value == 31)
	  ; /* break-stop */
	else
	  CBOR_PARSER_ERROR("Unknown simple value %u", ctx->value);
      }
      else
      {
	if (ctx->value < 24)
	  ; /* Immediate value, fall through */
	else if (ctx->value < 28)
	{
	  /* Need more data */
	  ctx->partial_state = CPE_READ_INT;
	  ctx->partial_countdown = (1 << (ctx->value - 24));
	  ctx->value = 0;
	  break;
	}
	else if ((ctx->value == 31) && (ctx->type >= 2) && (ctx->type <= 5))
	  /* Indefinite length, fall through */
	  ctx->tflags |= CPT_VARLEN;
	else
	  CBOR_PARSER_ERROR("Garbled additional value %u for type %u", ctx->value, ctx->type);
      }
      /* fall through */

    case CPE_READ_INT:
      if (ctx->partial_state == CPE_READ_INT)
      {
	/* Reading a network order integer */
	ctx->value <<= 8;
	ctx->value |= bp;
	if (--ctx->partial_countdown)
	  break;
      }
      /* fall through */

    case CPE_COMPLETE_INT:
      /* Some types are completely parsed, some not yet */
      switch (ctx->type)
      {
	case 0:
	case 1:
	case 7:
	  ctx->partial_state = CPE_ITEM_DONE;
	  break;

	case 2:
	case 3:
	  ctx->partial_state = CPE_READ_BYTE;
	  ctx->partial_countdown = ctx->value;
	  break;

	case 4:
	case 5:
	  if (++ctx->stack_pos >= ctx->stack_max)
	    CBOR_PARSER_ERROR("Stack too deep");

	  /* set array/map size;
	   * once for arrays, twice for maps;
	   * ~0 for indefinite, plus one for the array/map head itself */
	  ctx->stack_countdown[ctx->stack_pos] = (ctx->tflags & CPT_VARLEN) ? ~0ULL :
	    (ctx->value * (ctx->type - 3)) ;
	  ctx->partial_state = CPE_TYPE;
	  break;
      }

      /* Process the value */
      return CPR_MAJOR;

    case CPE_READ_BYTE:
      *ctx->target_buf = bp;
      ctx->target_buf++;
      if (--ctx->target_len)
	break;

      ctx->target_buf = NULL;
      ctx->partial_state = CPE_ITEM_DONE;
      return CPR_STR_END;
  }

  return CPR_MORE;
}

bool
cbor_parse_block_end(struct cbor_parser_context *ctx)
{
  if (ctx->partial_state != CPE_ITEM_DONE)
    return false;

  if (--ctx->stack_countdown[ctx->stack_pos])
  {
    ctx->partial_state = CPE_TYPE;
    return false;
  }

  if (!ctx->stack_pos--)
    ctx->partial_state = CPE_EXIT;

  return true;
}


#if 0

void cbor_epoch_time(struct cbor_writer *writer, int64_t time, int shift)
{
  write_item(writer, 6, 1); // 6 is TAG, 1 is tag number for epoch time
  cbor_relativ_time(writer, time, shift);
}

void cbor_relativ_time(struct cbor_writer *writer, int64_t time, int shift)
{
  write_item(writer, 6, 4); // 6 is TAG, 4 is tag number for decimal fraction
  cbor_open_list_with_length(writer, 2);
  cbor_add_int(writer, shift);
  cbor_add_int(writer, time);
}

void cbor_add_ipv4(struct cbor_writer *writer, ip4_addr addr)
{
  write_item(writer, 6, 52); // 6 is TAG, 52 is tag number for ipv4
  write_item(writer, 2, 4); // bytestring of length 4
  put_ip4(&writer->cbor[writer->pt], addr);
  writer->pt += 4;
}

void cbor_add_ipv6(struct cbor_writer *writer, ip6_addr addr)
{
  write_item(writer, 6, 54); // 6 is TAG, 54 is tag number for ipv6
  write_item(writer, 2, 16); // bytestring of length 16
  put_ip6(&writer->cbor[writer->pt], addr);
  writer->pt += 16;
}


void cbor_add_ipv4_prefix(struct cbor_writer *writer, net_addr_ip4 *n)
{
  write_item(writer, 6, 52); // 6 is TAG, 52 is tag number for ipv4
  cbor_open_block_with_length(writer, 2);
  cbor_add_int(writer, n->pxlen);
  write_item(writer, 2, 4); // bytestring of length 4
  put_ip4(&writer->cbor[writer->pt], n->prefix);
  writer->pt += 4;
}


void cbor_add_ipv6_prefix(struct cbor_writer *writer, net_addr_ip6 *n)
{
  write_item(writer, 6, 54); // 6 is TAG, 54 is tag number for ipv6
  cbor_open_block_with_length(writer, 2);
  cbor_add_int(writer, n->pxlen);

  write_item(writer, 2, 16);
  put_ip6(&writer->cbor[writer->pt], n->prefix);
  writer->pt += 16;
}


void cbor_add_uint(struct cbor_writer *writer, uint64_t item)
{
  write_item(writer, 0, item);
}

void cbor_add_tag(struct cbor_writer *writer, int item)
{
  write_item(writer, 6, item);
}

void cbor_add_string(struct cbor_writer *writer, const char *string)
{
  int length = strlen(string);
  write_item(writer, 3, length);  // 3 is major, then goes length of string and string
  check_memory(writer, length);
  memcpy(writer->cbor+writer->pt, string, length);
  writer->pt+=length;
}

void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint32_t length)
{
  write_item(writer, 3, length);  // 3 is major, then goes length of string and string
  check_memory(writer, length);
  memcpy(writer->cbor+writer->pt, string, length);
  writer->pt+=length;
}

void write_item(struct cbor_writer *writer, uint8_t major, uint64_t num)
{
  //log("write major %i %li", major, num);
  major = major<<5;
  check_memory(writer, 10);
  if (num > ((uint64_t)1<<(4*8))-1)
  { // We need 8 bytes to encode the num
    major += 0x1b; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 7; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > (1<<(2*8))-1)
  { // We need 4 bytes to encode the num
    major += 0x1a; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 3; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > (1<<(8))-1)
  { // We need 2 bytes to encode the num
    major += 0x19; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 1; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > 23)
  { // byte is enough, but aditional value would be too big
    major += 0x18; // reserving that byte
    writer->cbor[writer->pt] = major;
    writer->pt++;
    uint8_t to_write = num & 0xff;
    writer->cbor[writer->pt] = to_write;
    writer->pt++;
    return;
  }
  //log("write item major %i num %i writer->pt %i writer->capacity %i writer %i", major, num, writer->pt, writer->capacity, writer);
  major += num;  // we can store the num as additional value 
  writer->cbor[writer->pt] = major;
  writer->pt++;
}

void cbor_write_item_with_constant_val_length_4(struct cbor_writer *writer, uint8_t major, uint64_t num)
{
// this is only for headers which should be constantly long. 
  major = major<<5;
  check_memory(writer, 10);
  major += 0x1a; // reserving those bytes
  writer->cbor[writer->pt] = major;
  writer->pt++;
  for (int i = 3; i>=0; i--)
  { // write n-th byte of num
    uint8_t to_write = (num>>(i*8)) & 0xff;
    writer->cbor[writer->pt] = to_write;
    writer->pt++;
  }
}


void rewrite_4bytes_int(struct cbor_writer *writer, int pt, int num)
{
  for (int i = 3; i>=0; i--)
  {
    uint8_t to_write = (num>>(i*8)) & 0xff;
    writer->cbor[pt] = to_write;
    pt++;
  }
}

void check_memory(struct cbor_writer *writer, int add_size)
{
  if (writer->capacity - writer->pt-add_size < 0)
  {
    bug("There is not enough space for cbor response in given buffer");
  }
}
#endif

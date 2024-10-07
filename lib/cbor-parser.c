/*
 *	BIRD CBOR parser
 *
 *	(c) 2024 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/hash.h"

/*
 * Basic parser bits
 */

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

/*
 * CBOR channel multiplexer
 */

#define CCH_EQ(a,b)	(a)->id == (b)->id
#define CCH_FN(x)	(x)->idhash
#define CCH_KEY(x)	(x)
#define CCH_NEXT(x)	(x)->next_hash

struct cbor_channel cbor_channel_parse_error;

#define CSTR_PARSER_ERROR(...) do {		\
  log(L_ERR __VA_ARGS__);			\
  sk_close(s);					\
  return 0;					\
} while (0)

#define CCH_PARSE(kind)  do {				\
  ASSERT_DIE(cch);					\
  switch (cch->parse(cch, kind)) {			\
    case CPR_MORE:	continue;			\
    case CPR_ERROR:	sk_close(s);			\
			return 0;			\
    case CPR_BLOCK_END: stream->state = CSTR_FINISH;	\
			break;				\
    default: bug("Invalid return value from channel parser");	\
  }} while(0)

static int
cbor_stream_rx(sock *s, uint sz)
{
  struct cbor_stream *stream = s->data;
  struct cbor_parser_context *ctx = &stream->parser;
  struct cbor_channel *cch = stream->cur_rx_channel;
  struct cbor_channel cchloc = {};

  for (uint pos = 0; pos < sz; pos++)
  {
    switch (cbor_parse_byte(ctx, s->rbuf[pos]))
    {
      case CPR_MORE:
	continue;

      case CPR_ERROR:
	log(L_ERR "CBOR parser failure: %s", ctx->error);
	sk_close(s);
	return 0;

      case CPR_MAJOR:
	switch (stream->state)
	{
	  case CSTR_INIT:
	    if (ctx->type != 4)
	      CSTR_PARSER_ERROR("Expected array, got %u", ctx->type);

	    if (ctx->value != 3)
	      CSTR_PARSER_ERROR("Expected array of length exactly 3");

	    stream->state = CSTR_EXPECT_ID;
	    break;

	  case CSTR_EXPECT_ID:
	    CBOR_PARSE_ONLY(ctx, POSINT, cchloc.id);
	    stream->state = CSTR_MSG;

	    cchloc.idhash = cchloc.id * stream->hmul;
	    stream->cur_rx_channel = cch = HASH_FIND(stream->channels, CCH, &cchloc);
	    if (cch)
	      break;

	    stream->cur_rx_channel = cch = sl_alloc(stream->slab);
	    *cch = cchloc;
	    cch->p = rp_newf(stream->p, stream->p->domain, "Channel 0x%lx", cchloc.id);
	    HASH_INSERT(stream->channels, CCH, cch);
	    break;

	  case CSTR_MSG:
	    CCH_PARSE(CPR_MAJOR);
	    break;

	  case CSTR_FINISH:
	  case CSTR_CLEANUP:
	    bug("Invalid stream pre-parser state");
	}
	break;

      case CPR_STR_END:
	ASSERT_DIE(stream->state == CSTR_MSG);
	CCH_PARSE(CPR_STR_END);
	break;

      case CPR_BLOCK_END:
	bug("Impossible value returned from cbor_parse_byte()");
    }

    while (cbor_parse_block_end(ctx))
    {
      switch (stream->state)
      {
	case CSTR_INIT:
	case CSTR_EXPECT_ID:
	case CSTR_CLEANUP:
	  CSTR_PARSER_ERROR("Invalid stream pre-parser state");

	case CSTR_MSG:
	  CCH_PARSE(CPR_BLOCK_END);
	  break;

	case CSTR_FINISH:
	  stream->state = CSTR_CLEANUP;
	  break;
      }
    }

    if (stream->state == CSTR_CLEANUP)
    {
      if (ctx->partial_state != CPE_EXIT)
	CSTR_PARSER_ERROR("Garbled end of message");

      ctx->partial_state = CPE_TYPE;
      stream->state = CSTR_INIT;

      if (pos + 1 < sz)
      {
	memmove(s->rbuf, s->rbuf + pos + 1, sz - pos - 1);
	s->rpos = s->rbuf + sz - pos - 1;
      }

      return 0;
    }
  }

  return 1;
}

void
cbor_stream_attach(struct cbor_stream *stream, sock *sk)
{
  sk->data = stream;
  sk->rx_hook = cbor_stream_rx;
}

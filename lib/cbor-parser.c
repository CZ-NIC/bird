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

static void
cbor_parser_init(struct cbor_parser_context *ctx, linpool *lp, uint max_depth)
{
  ctx->lp = lp;
  ctx->flush = lp_save(lp);

  ctx->stack_countdown[0] = 1;
  ctx->stack_pos = 0;
  ctx->stack_max = max_depth;

  ctx->target_buf = NULL;
  ctx->target_len = 0;

  ctx->type = 0xff;

  ctx->partial_state = CPE_TYPE;
  ctx->partial_countdown = 0;
}

struct cbor_parser_context *
cbor_parser_new(pool *p, uint stack_max_depth)
{
  linpool *lp = lp_new(p);
  struct cbor_parser_context *ctx = lp_allocz(
      lp, sizeof *ctx + (stack_max_depth + 1) * sizeof ctx->stack_countdown[0]);

  cbor_parser_init(ctx, lp, stack_max_depth);
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

#define CCH_CALL_PARSER(cch, kind)  (			\
    cch->parse ? cch->parse(cch, kind) :		\
    (ctx->stack_pos > 1) ? CPR_MORE : CPR_BLOCK_END	\
    )

#define CCH_PARSE(kind)  do {				\
  ASSERT_DIE(cch);					\
  switch (CCH_CALL_PARSER(cch, kind)) {			\
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
  u64 id;

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

	    if (ctx->value < 2)
	      CSTR_PARSER_ERROR("Expected array of length at least 2");

	    stream->state = CSTR_EXPECT_ID;
	    break;

	  case CSTR_EXPECT_ID:
	    CBOR_PARSE_ONLY(ctx, POSINT, id);
	    stream->state = CSTR_MSG;
	    stream->cur_rx_channel = cch = (
		cbor_channel_find(stream, id) ?:
		cbor_channel_create(stream, id)
		);
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
//	  CSTR_PARSER_ERROR("Invalid stream pre-parser state");
	  bug("Invalid stream pre-parser state");

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

      stream->cur_rx_channel = NULL;

      if (!cch->parse)
	cbor_channel_done(cch);

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

static void
cbor_stream_err(sock *sk, int err)
{
  struct cbor_stream *stream = sk->data;
  if (err)
    log(L_INFO "CBOR stream %p error: %d (%M)", sk, err, err);
  else
    log(L_INFO "CBOR stream %p hangup", sk);

  stream->cur_rx_channel = NULL;

  HASH_WALK_DELSAFE(stream->channels, next_hash, cch)
  {
    cbor_channel_done(cch);
  }
  HASH_WALK_DELSAFE_END;

  stream->cancel(stream);

  sk_close(sk);
}

void
cbor_stream_init(struct cbor_stream *stream, pool *p, uint parser_depth, uint writer_depth, uint channel_size)
{
  stream->p = rp_newf(p, p->domain, "Stream pool");
  HASH_INIT(stream->channels, stream->p, 4);
  stream->slab = sl_new(stream->p, channel_size);

  random_bytes(&stream->hmul, sizeof stream->hmul);
  stream->writer_depth = writer_depth;
  stream->state = CSTR_INIT;

  cbor_parser_init(&stream->parser, lp_new(p), parser_depth);
}

void
cbor_stream_attach(struct cbor_stream *stream, sock *sk)
{
  sk->data = stream;
  sk->rx_hook = cbor_stream_rx;
  sk->err_hook = cbor_stream_err;

  stream->s = sk;
  stream->loop = sk->loop;
}

struct cbor_channel *
cbor_channel_create(struct cbor_stream *stream, u64 id)
{
  struct cbor_channel *cch = sl_allocz(stream->slab);
  *cch = (struct cbor_channel) {
    .id = id,
    .idhash = id * stream->hmul,
    .p = rp_newf(stream->p, stream->p->domain, "Channel 0x%lx", id),
    .stream = stream,
    .parse = stream->parse,
  };

  log(L_TRACE "CBOR channel create in stream %p, id %lx", stream, id);
  HASH_INSERT(stream->channels, CCH, cch);
  return cch;
}

struct cbor_channel *
cbor_channel_find(struct cbor_stream *stream, u64 id)
{
  struct cbor_channel cchloc;
  cchloc.id = id;
  cchloc.idhash = cchloc.id * stream->hmul;

  return HASH_FIND(stream->channels, CCH, &cchloc);
}

struct cbor_channel *
cbor_channel_new(struct cbor_stream *stream)
{
  u64 id;
  while (cbor_channel_find(stream, id = random_type(u64)))
    ;

  return cbor_channel_create(stream, id);
}

void
cbor_channel_done(struct cbor_channel *channel)
{
  struct cbor_stream *stream = channel->stream;
  bool active = (stream->cur_rx_channel == channel);

  log(L_TRACE "CBOR channel%s done in stream %p, id %lx",
      active ? " (active)" : "", stream, channel->id);

  if (active)
  {
    channel->parse = NULL;
  }
  else
  {
    HASH_REMOVE(stream->channels, CCH, channel);
    rp_free(channel->p);
    sl_free(channel);
  }
}

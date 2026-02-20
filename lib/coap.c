/*
 *	CoAP -- Constrained Application Protocol
 *
 *	(c) 2026 CZ.NIC
 *	(c) 2026 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Constrained Application Protocol
 *
 * Constrained Application Protocol is a minimalist protocol described
 * by RFC 7252 and several more. It's designed for constrained environments
 * but we are using it for high-performance API.
 *
 * CoAP is somehow convertible from/to HTTP, as there are many equivalent
 * constructions and principles.
 *
 * This implementation aims for step-by-step parsing. We wanna avoid allocating
 * data while parsing, and instead of creating generic structures, we generate
 * events and let the caller process parts of the message on-the-fly;
 * most specifically, allocate and copy only these parts which really need to
 * be parsed.
 *
 * Implemented standards:
 * RFC 7252 -- The Constrained Application Protocol (CoAP) (rudimentary support for UDP)
 * RFC 8323 -- CoAP over TCP, TLS and Websockets (only TCP for now)
 */

#include "lib/birdlib.h"
#include "lib/coap.h"
#include "lib/string.h"

#include "lib/ip.h"
#include "lib/socket.h"

#include <limits.h>

/* Just to be sure that bytes do what they are expected to do */
STATIC_ASSERT_MSG(CHAR_BIT == 8, "Weird char length");

/* Check frame and option packing for convenience macros */
static struct {
  struct coap_tx_frame f;
  struct coap_tx_option *optr[1];
} coap_tx_frame_check;
STATIC_ASSERT(&coap_tx_frame_check.f.opt[0] == &coap_tx_frame_check.optr[0]);

/* Get onwire length of one option */
static uint
coap_tx_option_raw_len(const struct coap_tx_option *o, uint prev_type)
{
  return 1				/* DL-byte */
	+ (o->type >= prev_type + 13)	/* One-byte delta */
	+ (o->type >= prev_type + 269)	/* Two-byte delta */
	+ (o->len >= 13)		/* One-byte length */
	+ (o->len >= 269)		/* Two-byte length */
	+ o->len;			/* Actual option length */
}

/**
 * coap_tx_extend - Allocate one TX block
 * @s: CoAP session
 * @queue: Queue to put the block in
 *
 * Allocates and returns one more TX block for the supplied queue.
 * */
struct coap_tx *
coap_tx_extend(struct coap_session *s UNUSED, TLIST_LIST(coap_tx) *queue)
{
  /* Allocate new block if there is not enough space for the header.
   * Also use separate blocks for non-TCP */
  struct coap_tx *tx = alloc_page();
  void *data = &tx[1];
  *tx = (struct coap_tx) {
    .buf.start = data,
    .buf.pos = data,
    .buf.end = ((void *) tx) + page_size,
  };

  coap_tx_add_tail(queue, tx);
  return tx;
}

static void
coap_tx_put_header(struct coap_session *s, struct coap_tx *tx, TLIST_LIST(coap_tx) *q, const struct coap_tx_frame *f, u64 elen)
{
  /* Put version/len/TKL byte, and possibly extended length */
  switch (s->transport)
  {
    case COAP_TRANSPORT_UDP:
      *tx->buf.pos++ = (f->version & 3) << 6 | (f->type & 3) << 4 | (f->toklen & 7);
      break;

    case COAP_TRANSPORT_TCP:
      if (elen < 13)
	*tx->buf.pos++ = elen << 4 | (f->toklen & 7);
      else if (elen < 269)
      {
	*tx->buf.pos++ = 13 << 4 | (f->toklen & 7);
	*tx->buf.pos++ = elen - 13;
      }
      else if (elen < 65805)
      {
	*tx->buf.pos++ = 14 << 4 | (f->toklen & 7);
	put_u16(tx->buf.pos, elen - 269);
	tx->buf.pos += 2;
      }
      else if (elen < 4295033101)
      {
	*tx->buf.pos++ = 15 << 4 | (f->toklen & 7);
	put_u32(tx->buf.pos, elen - 65805);
	tx->buf.pos += 4;
      }
      else
	bug("Frame of this size (%lu) may collapse into a black hole.", elen);

      break;

    case COAP_TRANSPORT_WEBSOCKET:
      *tx->buf.pos++ = f->toklen & 7;
      break;
  }

  /* Put code */
  *tx->buf.pos++ = f->code;

  /* Put msgid for UDP */
  if (s->transport == COAP_TRANSPORT_UDP)
  {
    memcpy(tx->buf.pos, &f->msg_id, 2);
    tx->buf.pos += 2;
  }

  /* Put token */
  ASSERT_DIE(f->toklen <= 8);
  if (f->toklen)
    memcpy(tx->buf.pos, f->token, f->toklen);
  tx->buf.pos += f->toklen;

  ASSERT_DIE(tx->buf.pos <= tx->buf.end);

  /* Put options */
  uint prev_type = 0;
  bool payload_marker = false;
  for (uint i = 0; i < f->optcnt; i++)
  {
    struct coap_tx_option *opt = f->opt[i];

    /* This option has been omitted */
    if (!opt)
      continue;

    if (!opt->type)
    {
      /* This is a payload block */
      if (!payload_marker)
      {
	/* Write a payload marker */
	payload_marker = true;
	if (tx->buf.pos == tx->buf.end)
	  tx = coap_tx_extend(s, q);

	*tx->buf.pos++ = 0xff;
      }

      /* Copy payload data */
      for (uint d = 0; d < opt->len; )
      {
	if (tx->buf.pos == tx->buf.end)
	  tx = coap_tx_extend(s, q);

	uint cp = MIN(tx->buf.end - tx->buf.pos, opt->len);
	memcpy(tx->buf.pos, &opt->data[d], cp);

	tx->buf.pos += cp;
	d += cp;
      }

      continue;
    }

    if (opt->type < prev_type || payload_marker)
      bug("Sending frames with unsorted options is not supported.");

    /* Ensure the whole option is written into one single block */
    uint rlen = coap_tx_option_raw_len(opt, prev_type);

    if (tx->buf.pos + rlen > tx->buf.end)
      tx = coap_tx_extend(s, q);

    if (tx->buf.pos + rlen > tx->buf.end)
      bug("This option (size %u) fits only Antonov An-225. Buy one before continuing.", rlen);

    uint delta = opt->type - prev_type;
    ASSERT_DIE(delta < 65536);

    uint dlen = (delta >= 13) + (delta >= 269);
    uint llen = (opt->len >= 13) + (opt->len >= 269);

    /* Write DL-byte */
    *tx->buf.pos++ = (dlen ? dlen + 13 : delta) << 4 | (llen ? llen + 13 : opt->len);

    /* Write delta */
    if (dlen == 1)
      *tx->buf.pos++ = delta - 13;
    else if (dlen == 2)
    {
      put_u16(tx->buf.pos, delta - 269);
      tx->buf.pos += 2;
    }

    /* Write length */
    if (llen == 1)
      *tx->buf.pos++ = opt->len - 13;
    else if (llen == 2)
    {
      put_u16(tx->buf.pos, opt->len - 269);
      tx->buf.pos += 2;
    }

    /* Write option value */
    memcpy(tx->buf.pos, opt->data, opt->len);
    tx->buf.pos += opt->len;

    ASSERT_DIE(tx->buf.pos <= tx->buf.end);
  }
}

/**
 * coap_tx_send - send a completely prepared frame
 * @s: CoAP session
 * @f: Frame to send
 */
void
coap_tx_send(struct coap_session *s, const struct coap_tx_frame *f)
{
  struct coap_tx *tx = s->tx_queue.last;

  if (!tx || (tx->buf.end - tx->buf.pos < 24) || s->transport != COAP_TRANSPORT_TCP)
    tx = coap_tx_extend(s, &s->tx_queue);

  /* Compute option+payload length */
  u64 elen = 0;
  uint prev_type = 0;
  bool payload_marker = false;

  for (uint i = 0; i < f->optcnt; i++)
  {
    struct coap_tx_option *opt = f->opt[i];

    /* This option has been omitted */
    if (!opt)
      continue;

    if (opt->type)
    {
      if (opt->type < prev_type || payload_marker)
	bug("Sending frames with unsorted options is not supported.");

      elen += 1					/* DL-byte */
	+ (opt->type >= prev_type + 13)		/* One-byte delta */
	+ (opt->type >= prev_type + 269)	/* Two-byte delta */
	+ (opt->len >= 13)			/* One-byte length */
	+ (opt->len >= 269)			/* Two-byte length */
	+ opt->len;				/* Actual option length */
      prev_type = opt->type;
    }
    else
    {
      payload_marker = true;
      elen += opt->len;
    }
  }

  elen += payload_marker;
  coap_tx_put_header(s, tx, &s->tx_queue, f, elen);
}

/**
 * coap_tx_written - indicate that TX buffer has been flushed
 * @s: CoAP session
 */
void
coap_tx_written(struct coap_session *s, struct birdsock *sk)
{
  ASSERT_DIE(s->tx_pending->buf.start == sk->tbuf);
  sk_set_tbuf(sk, NULL);
  free_page(s->tx_pending);
  s->tx_pending = NULL;
}

/**
 * coap_tx_flush - flush TX buffers
 * @s: CoAP session
 * @sk: BIRD socket
 */
void
coap_tx_flush(struct coap_session *s, struct birdsock *sk)
{
  while (!s->tx_pending && !EMPTY_TLIST(coap_tx, &s->tx_queue))
  {
    /* Supply the buffer */
    s->tx_pending = s->tx_queue.first;
    coap_tx_rem_node(&s->tx_queue, s->tx_pending);
    sk_set_tbuf(sk, s->tx_pending->buf.start);

    /* Request the write */
    if (sk_send(sk, s->tx_pending->buf.pos - s->tx_pending->buf.start) > 0)
      coap_tx_written(s, sk);
  }
}

/* Generic errors */
void
coap_bad_request(struct coap_session *s, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  struct coap_tx_option *payload = COAP_TX_OPTION_VPRINTF(0, fmt, args);
  coap_tx_send(s, COAP_TX_FRAME(COAP_CERR_BAD_REQUEST, payload));
  coap_tx_send(s, COAP_TX_FRAME(COAP_SCO_ABORT));
  s->flush_and_close = true;
}

/* Process Empty Message */
static bool
coap_process_req_empty(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;
  ASSERT_DIE(ctx->code == COAP_REQ_EMPTY);
}

/* Capabilities and Settings Message Error */
static void
coap_bad_csm(struct coap_session *s, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  struct coap_parse_context *ctx = &s->parser;

  struct coap_tx_option *opt_bad_csm = (ctx->option_type < 256)
    ? COAP_TX_OPTION_INT(COAP_OPT_BAD_CSM, (u8) ctx->option_type)
    : COAP_TX_OPTION_INT(COAP_OPT_BAD_CSM, (u16) ctx->option_type);

  struct coap_tx_option *payload = COAP_TX_OPTION_VPRINTF(0, fmt, args);

  coap_tx_send(s, COAP_TX_FRAME(COAP_SCO_ABORT, opt_bad_csm, payload));
  s->flush_and_close = true;

  va_end(args);
}

/* Capabilities and Settings Message Processing */
static bool
coap_process_sco_csm(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;
  ASSERT_DIE(ctx->code == COAP_SCO_CSM);

  switch (ctx->state) {
    case COAP_PS_HEADER:
      /* Header parsed. Initialize receiving data storage. */
      s->max_msg_size_rx = 0;
      s->blockwise_rx = true;
      return true;

    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      /* Load message options. */
      switch (ctx->option_type) {
	case COAP_OPT_MAX_MSG_SIZE:
	  /* Load maximum message size */
	  if (ctx->option_len > 4)
	  {
	    coap_bad_csm(s, "Too long: %u", ctx->option_len);
	    return true;
	  }

	  for (uint i = 0; i < ctx->option_chunk_len; i++)
	  {
	    s->max_msg_size_rx <<= 8;
	    s->max_msg_size_rx += ctx->option_value[i];
	  }

	  return true;

	case COAP_OPT_BLOCKWISE:
	  /* Stream Blockwise Transfer supported */
	  if (ctx->option_len == 0)
	    s->blockwise_rx = true;
	  else
	    coap_bad_csm(s, "Too long: %u", ctx->option_len);

	  return true;

	default:
	  /* Ignore an unknown option unless critical */
	  if (ctx->option_type & COAP_OPT_F_CRITICAL)
	    coap_bad_csm(s, "Unknown option");

	  return true;
      }

    case COAP_PS_PAYLOAD_PARTIAL:
      /* Ignore payload */
      return true;

    case COAP_PS_PAYLOAD_COMPLETE:
      /* Done, reset the code */
      ctx->code = 0;
      return true;

    case COAP_PS_MORE:
      return true;

    case COAP_PS_ERROR:
    case COAP_PS_EMPTY:
      coap_bad_csm(s, "Parse error");
      return true;
  }

  return false;
}

static bool
coap_process_sco_ping(struct coap_session *s)
{ return false; }

static bool
coap_process_sco_pong(struct coap_session *s)
{ return false; }

static bool
coap_process_sco_release(struct coap_session *s)
{ return false; }

static bool
coap_process_sco_abort(struct coap_session *s)
{ return false; }

/**
 * coap_process - dispatch default CoAP processes
 * @s: CoAP session
 *
 * There are technical and stream control messages and other stuff inside
 * CoAP which don't have any semantics outside. This call processes all that
 * stuff so that the YANG subsystem doesn't need to care.
 *
 * Returns true if everything was processed here, otherwise yields to YANG by
 * returning false.
 */
bool
coap_process(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;

  switch (ctx->code) {
    case COAP_REQ_EMPTY:
      return coap_process_req_empty(s);
    case COAP_SCO_CSM:
      return coap_process_sco_csm(s);
    case COAP_SCO_PING:
      return coap_process_sco_ping(s);
    case COAP_SCO_PONG:
      return coap_process_sco_pong(s);
    case COAP_SCO_RELEASE:
      return coap_process_sco_release(s);
    case COAP_SCO_ABORT:
      return coap_process_sco_abort(s);

    default:
      return false;
  }

}

#define END			(ctx->data_ptr >= ctx->data_len)
#define CUR			(&ctx->data[ctx->data_ptr])
#define ONEBYTE()		(ctx->data[ctx->data_ptr++])
#define REMAINS			(ctx->data_len - ctx->data_ptr)

#define FAIL(_e) return (ctx->state = _e), false

#define EAT(_n)	do { \
  ctx->data_ptr += (_n); \
  if (ctx->data_len <= ctx->data_ptr) \
    FAIL(COAP_PSE_TRUNCATED); \
} while (0)

#define COPY(_tgt, _n) do { \
  const void *_cur = CUR; \
  uint _nn = (_n); \
  EAT(_nn); \
  memcpy(_tgt, _cur, _nn); \
} while (0)

#define GET(_v) COPY(&_v, sizeof (_v))

#define LOADINT(which, next_state)  do { \
  ctx->which <<= 8; \
  ctx->which += ONEBYTE(); \
  if (!--ctx->load_len_missing) \
  { \
    switch (ctx->load_len) \
    { \
      case 4: ctx->which += 65536;	/* fall through */ \
      case 2: ctx->which += 256;	/* fall through */ \
      case 1: ctx->which += 13;		/* fall through */ \
	      break; \
      default: bug("Weird load len"); \
    } \
    ctx->state = next_state; \
  } \
} while (0)

static enum coap_parse_state
coap_parse_option(struct coap_session *s, bool allow_partial)
{
#define MORE(_s) do { \
  if (!allow_partial) \
    FAIL(COAP_PSE_TRUNCATED); \
  else { \
    ctx->state = (_s); \
    return (ctx->state < COAP_PSM_NONE) || (ctx->state >= COAP_PSE_NONE); \
  } \
} while (0)

#define CHECK_EOF() do { \
  if (end_of_frame <= ctx->data_ptr) { \
    FAIL(COAP_PSE_TRUNCATED); \
  } \
} while (0)

  struct coap_parse_context *ctx = &s->parser;

  s64 end_of_frame = ctx->data_option_offset + ctx->common_len;

  while (!END)
  {
    switch (ctx->state)
    {
      case COAP_PS_EMPTY:
      case COAP_PSM_NONE ... COAP_PSM_OPTION_NONE:
      case COAP_PS__MORE_MAX:
      case COAP_PS_PAYLOAD_PARTIAL:
      case COAP_PS_PAYLOAD_COMPLETE:
      case COAP_PS_ERROR:
	bug("Unexpected state when parsing CoAP option");

      case COAP_PS_HEADER:
	/* Initialize the payload total length */
	ctx->payload_total_len = ctx->common_len;
	ctx->data_option_offset = ctx->data_ptr;
	end_of_frame = ctx->data_option_offset + ctx->common_len;

	/* fall through */

      case COAP_PS_OPTION_COMPLETE:
	/* At the end of frame, no more options and no payload */
	if (end_of_frame == ctx->data_ptr)
	{
	  ctx->payload_chunk_offset = 0;
	  ctx->payload_chunk_len = 0;
	  ctx->payload_total_len = 0;

	  return (ctx->state = COAP_PS_PAYLOAD_COMPLETE), true;
	}

	/* fall through */

      case COAP_PSM_OPTION_DL:
	ctx->option_dlbyte = ONEBYTE();

	switch (ctx->option_dlbyte >> 4)
	{
	  case 0xf:
	    if (ctx->option_dlbyte != 0xff)
	      FAIL(COAP_PSE_FAKE_PAYLOAD_MARKER);
	    else
	    {
	      ctx->state = COAP_PS_PAYLOAD_PARTIAL;
	      ctx->payload_chunk_offset = ctx->payload_chunk_len = 0;
	      ctx->payload_total_len = end_of_frame - ctx->data_ptr;
	      continue;
	    }

	  case 0xe:
	  case 0xd:
	    ctx->load_len = ctx->load_len_missing = 1 << ((ctx->option_dlbyte >> 4) - 13);
	    ctx->state = COAP_PSM_OPTION_DELTA;

	    if (END)
	      MORE(ctx->state);

	    break;

	  default:
	    ctx->option_delta = ctx->option_dlbyte >> 4;
	    break;
	}

	/* We have parsed just one half of the dlbyte but now we may need to parse
	 * the option delta before parsing the length */

	/* fall through */

      case COAP_PSM_OPTION_DELTA:
	if (ctx->state == COAP_PSM_OPTION_DELTA)
	{
	  LOADINT(option_delta, COAP_PSM_OPTION_PRE_LEN);

	  /* We have parsed a byte but we need more, continue */
	  if (ctx->state == COAP_PSM_OPTION_DELTA)
	    continue;
	}

	/* Now the option delta is parsed, continue to the length */

	/* fall through */

      case COAP_PSM_OPTION_PRE_LEN:
	/* Apply the Option Delta */
	ctx->option_type += ctx->option_delta;
	ctx->option_delta = 0;

	/* Load the option length */
	switch (ctx->option_dlbyte & 0xf)
	{
	  case 0xf:
	    FAIL(COAP_PSE_RESERVED_OPTION_LEN);

	  case 0xe:
	  case 0xd:
	    ctx->load_len = ctx->load_len_missing = 1 << ((ctx->option_dlbyte & 0xf) - 13);
	    ctx->state = COAP_PSM_OPTION_LEN;
	    break;

	  default:
	    ctx->option_len = ctx->option_dlbyte & 0xf;
	    ctx->state = COAP_PS_OPTION_PARTIAL;
	    break;
	}

	if (ctx->option_len && END)
	  MORE(ctx->state);

	/* Now finally parsing the option len bytes */

	/* fall through */

      case COAP_PSM_OPTION_LEN:
	if (ctx->state == COAP_PSM_OPTION_LEN)
	{
	  LOADINT(option_len, COAP_PS_OPTION_PARTIAL);

	  /* We have parsed a byte but we need more, continue */
	  if (ctx->state == COAP_PSM_OPTION_LEN)
	    continue;
	}

	/* Zero-length option is already done */
	if (ctx->option_len == 0)
	  return (ctx->state = COAP_PS_OPTION_COMPLETE), true;

	/* Now loading the option data */
	ctx->option_chunk_offset = 0;
	ctx->option_chunk_len = 0;

	/* fall through */

      case COAP_PS_OPTION_PARTIAL:
	if (END)
	  MORE(ctx->state);

	ctx->option_value = CUR;
	ctx->option_chunk_offset += ctx->option_chunk_len;
	ctx->option_chunk_len = ctx->data_len - ctx->data_ptr;
	if (ctx->option_chunk_len + ctx->option_chunk_offset >= ctx->option_len)
	{
	  ctx->option_chunk_len = ctx->option_len - ctx->option_chunk_offset;
	  ctx->data_ptr += ctx->option_chunk_len;
	  ASSERT_DIE(ctx->data_ptr <= ctx->data_len);
	  if (end_of_frame < ctx->data_ptr)
	    FAIL(COAP_PSE_TRUNCATED);

	  return (ctx->state = COAP_PS_OPTION_COMPLETE), true;
	}
	else
	{
	  ctx->data_ptr = ctx->data_len;
	  CHECK_EOF();
	  MORE(COAP_PS_OPTION_PARTIAL);
	}
    }
  }

  CHECK_EOF();

  return ctx->state;

#undef MORE
}

/**
 * coap_udp_parse - do one step in incoming CoAP message parsing
 * @s: The CoAP session.
 *
 * The caller is expected to repeatedly call this function (e.g. in a
 * |while|-loop) until it returns COAP_PS_PAYLOAD_COMPLETE.
 *
 * Needs to be fed by coap_udp_rx() before every packet.
 */
enum coap_parse_state
coap_udp_parse(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;

  switch (ctx->state)
  {
    /* Refuse to continue if error happened, or called again
     * with payload already complete; reset needed */
    case COAP_PS_PAYLOAD_COMPLETE:
    case COAP_PS_ERROR:
      FAIL(COAP_PSE_NEED_RESET);

    /* Nothing parsed yet, let's start with the message header
     * as defined in RFC 7252 Sec. 3 */
    case COAP_PS_EMPTY:
      {
	/* 2 bits version, 2 bits type, 4 bits token length. */
	u8 vtk;
	GET(vtk);

	/* Version must be 1 */
	if ((ctx->version = vtk >> 6) != 1)
	  FAIL(COAP_PSE_INVALID_VERSION);

	/* Message type; all values defined, no error */
	ctx->type = (vtk >> 4) & 0x3;

	/* Token lengths 9 to 15 reserved by RFC 7252 */
	if ((ctx->token_len = vtk & 0xf) > 8)
	  FAIL(COAP_PSE_INVALID_TOKLEN);

	/* 3 bytes class, 5 bytes details */
	GET(ctx->code);
	ctx->class = ctx->code >> 5;

	/* Load message id, that's just a blob */
	GET(ctx->msg_id);

	/* Consume the token size */
	if (ctx->token_len)
	  COPY(&ctx->token, ctx->token_len);

	/* Header processed */
	ctx->common_len = ctx->data_len - (4 + ctx->token_len);
	if (ctx->common_len < 1)
	  FAIL(COAP_PSE_TRUNCATED);

	return (ctx->state = COAP_PS_HEADER);
      }

    /* Call common option parser */
    case COAP_PS_HEADER:
    case COAP_PS_OPTION_PARTIAL:
    case COAP_PS_OPTION_COMPLETE:
      return coap_parse_option(s, false);

      /* fall through */
    case COAP_PS_MORE:
    case COAP_PS_PAYLOAD_PARTIAL:
      /* If more data would be needed, the UDP packet has been truncated */
      FAIL(COAP_PSE_TRUNCATED);
  }

  bug("Unimplemented");
}

/**
 * coap_udp_rx - more data received
 * @s: The CoAP session
 * @ptr: Packet data
 * @len: Packet length
 *
 * The UDP parser expects the whole packet to be received at once by the
 * underlying layer. Resets the parser so that one may run coap_udp_parse()
 * afterwards.
 */
void
coap_udp_rx(struct coap_session *s, const char *data, uint len)
{
  struct coap_parse_context *ctx = &s->parser;
  *ctx = (struct coap_parse_context) {
    .state = COAP_PS_EMPTY,
    .data = data,
    .data_len = len,
    .data_ptr = 0,
  };
}

/**
 * coap_tcp_parse - do one step in incoming CoAP message parsing
 * @ctx: Context structure previously initialized by coap_parse_init()
 *
 * The caller is expected to repeatedly call this function (e.g. in a
 * |while|-loop) until it returns COAP_PMS_PAYLOAD_COMPLETE.
 *
 * Returns true if there is still something remaining to parse. Check
 * |ctx->state| to find out what has happened.
 */
bool
coap_tcp_parse(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;

  if (
      /* Special case: No options nor payload */
      (ctx->state == COAP_PS_HEADER) && (ctx->common_len == 0) ||

      /* Special case: No payload after options */
      (ctx->state == COAP_PS_OPTION_COMPLETE) && (ctx->data_ptr == ctx->data_option_offset + ctx->common_len)
     )
  {
    ctx->payload_chunk_offset = ctx->payload_chunk_len = ctx->payload_total_len = 0;
    ctx->state = COAP_PS_PAYLOAD_COMPLETE;
    return true;
  }

  while (!END)
  {
    switch (ctx->state)
    {
      case COAP_PS_PAYLOAD_COMPLETE:
      case COAP_PS_EMPTY:
	{
	  u8 lentkl = ONEBYTE();

	  /* Token lengths 9 to 15 reserved by RFC 7252 */
	  if ((ctx->token_len_missing = ctx->token_len = lentkl & 0xf) > 8)
	    FAIL(COAP_PSE_INVALID_TOKLEN);

	  u8 elen = lentkl >> 4;
	  if (elen <= 12)
	  {
	    ctx->common_len = elen;
	    ctx->state = COAP_PSM_CODE;
	  }
	  else
	  {
	    ctx->common_len = 0;
	    ctx->load_len_missing = ctx->load_len = (1 << (elen - 13));
	    ctx->state = COAP_PSM_ELEN;
	  }

	  continue;
	}

      case COAP_PSM_ELEN:
	LOADINT(common_len, COAP_PSM_CODE);
	continue;

      case COAP_PSM_CODE:
	ctx->code = ONEBYTE();
	ctx->class = ctx->code >> 5;

	if (!ctx->token_len)
	  return (ctx->state = COAP_PS_HEADER), true;

	ctx->state = COAP_PSM_TOKEN;
	continue;

      case COAP_PSM_TOKEN:
	ctx->token[ctx->token_len - ctx->token_len_missing] = ONEBYTE();
	if (!--ctx->token_len_missing)
	  return (ctx->state = COAP_PS_HEADER), true;

	continue;

      case COAP_PS_HEADER:
	ctx->option_type = 0;

	/* fall through */

      case COAP_PS_OPTION_PARTIAL:
      case COAP_PS_OPTION_COMPLETE:
      case COAP_PSM_OPTION_NONE ... COAP_PS__MORE_MAX:
	return coap_parse_option(s, true);

      case COAP_PS_PAYLOAD_PARTIAL:
	ctx->payload = CUR;
	ctx->payload_chunk_offset += ctx->payload_chunk_len;
	ctx->payload_chunk_len = ctx->data_len - ctx->data_ptr;
	if (ctx->payload_chunk_len + ctx->payload_chunk_offset >= ctx->payload_total_len)
	{
	  ctx->payload_chunk_len = ctx->payload_total_len - ctx->payload_chunk_offset;
	  ctx->data_ptr += ctx->payload_chunk_len;
	  ASSERT_DIE(ctx->data_ptr <= ctx->data_len);
	  return (ctx->state = COAP_PS_PAYLOAD_COMPLETE), true;
	}
	else
	{
	  ctx->data_ptr = ctx->data_len;
	  return (ctx->state = COAP_PS_PAYLOAD_PARTIAL), true;
	}

      case COAP_PSM_NONE:
      case COAP_PS_ERROR:
	FAIL(COAP_PSE_NEED_RESET);
    }
  }

  return false;
}

/**
 * coap_tcp_rx - more data received
 * @s: The CoAP session
 * @ptr: Packet data
 * @len: Packet length
 *
 * The TCP parser may receive frames weirdly sliced, and therefore this
 * simply supplies more data. All the data must be consumed by
 * coap_tcp_parse() before its lifetime is up.
 */
void
coap_tcp_rx(struct coap_session *s, const char *data, uint len)
{
  struct coap_parse_context *ctx = &s->parser;

  /* Move the data option offset backwards */
  ctx->data_option_offset -= ctx->data_len;

  ctx->data = data;
  ctx->data_len = len;
  ctx->data_ptr = 0;
}

#if 0
static const char *
coap_parse_strerror(const struct coap_parsed_message *ctx)
{
  switch (ctx->state) {
    case COAP_PMSE_TRUNCATED:
      return tmp_sprintf(
	  "Truncated message (length %u, needed at least %u)",
	  ctx->data_len, ctx->data_ptr);

    case COAP_PMSE_INVALID_VERSION:
      return tmp_sprintf("Invalid version: %u", ctx->version);

    case COAP_PMSE_INVALID_TOKLEN:
      return tmp_sprintf("Invalid token length: %u", ctx->token_len);

    case COAP_PMS_EMPTY:
      return "OK, initialized";

    case COAP_PMS_HEADER:
      return tmp_sprintf("OK, header parsed: version %u, type %u, token length %u",
	  ctx->version,
	  ctx->type, /* TODO: stringify */
	  ctx->token_len);
	  
    default:
      return tmp_sprintf("Unknown %s: %u",
	  (ctx->state <= COAP_PMS_ERROR) ? "state" : "error", ctx->state);
  }
}
#endif

void
coap_session_init(struct coap_session *s)
{
  s->transport = COAP_TRANSPORT_TCP;
  s->max_msg_size = 0xefefefefU;
  struct coap_tx_option *opt_max_msg_size = COAP_TX_OPTION_INT(COAP_OPT_MAX_MSG_SIZE, s->max_msg_size);
  coap_tx_send(s, COAP_TX_FRAME(COAP_SCO_CSM, opt_max_msg_size));
}

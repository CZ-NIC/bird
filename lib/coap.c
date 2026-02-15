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

#include <limits.h>

STATIC_ASSERT_MSG(CHAR_BIT == 8, "Weird char length");

#define END			(ctx->data_ptr >= ctx->data_len)
#define CUR			(&ctx->data[ctx->data_ptr])
#define ONEBYTE()		(ctx->data[ctx->data_ptr++])
#define REMAINS			(ctx->data_len - ctx->data_ptr)

#define FAIL(_e) return (ctx->state = _e)

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
      case 1: ctx->which += 13;		/* fall through */ \
      case 2: ctx->which += 256;	/* fall through */ \
      case 4: ctx->which += 65536;	/* fall through */ \
	      break; \
      default: bug("Weird load len"); \
    } \
    ctx->state = next_state; \
  } \
} while (0)

static enum coap_parse_state
coap_parse_option(struct coap_session *s, bool allow_partial)
{
#define MORE(_s) \
  if (allow_partial && ( \
	((_s) >= COAP_PSM_NONE) && \
	((_s) < COAP_PSE_NONE) || \
	((_s) == COAP_PS_OPTION_PARTIAL))) \
    return ctx->state = (_s); \
  else \
    FAIL(COAP_PSE_TRUNCATED)

  struct coap_parse_context *ctx = &s->parser;

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

      case COAP_PS_OPTION_COMPLETE:
      case COAP_PS_HEADER:
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
	  return ctx->state = COAP_PS_OPTION_COMPLETE;

	/* Now loading the option */
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
	  return ctx->state = COAP_PS_OPTION_COMPLETE;
	}
	else
	{
	  ctx->data_ptr = ctx->data_len;
	  MORE(COAP_PS_OPTION_PARTIAL);
	}
    }
  }

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

  ctx->state = COAP_PS_EMPTY;
  ctx->data = data;
  ctx->data_len = len;
  ctx->data_ptr = 0;
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
enum coap_parse_state
coap_tcp_parse(struct coap_session *s)
{
  struct coap_parse_context *ctx = &s->parser;

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
	  return ctx->state = COAP_PS_HEADER;

	ctx->state = COAP_PSM_TOKEN;
	continue;

      case COAP_PSM_TOKEN:
	ctx->token[ctx->token_len - ctx->token_len_missing] = ONEBYTE();
	if (!--ctx->token_len_missing)
	  return ctx->state = COAP_PS_HEADER;

	continue;

      case COAP_PS_HEADER:
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
	  return ctx->state = COAP_PS_PAYLOAD_COMPLETE;
	}
	else
	{
	  ctx->data_ptr = ctx->data_len;
	  return ctx->state = COAP_PS_PAYLOAD_PARTIAL;
	}

      case COAP_PSM_NONE:
      case COAP_PS_ERROR:
	FAIL(COAP_PSE_NEED_RESET);
    }
  }

  return ctx->state;
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

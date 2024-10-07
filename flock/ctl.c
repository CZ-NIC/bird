#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/string.h"
#include "lib/io-loop.h"

#include "flock/flock.h"

#include <stdlib.h>

/*
 * Hand-written parser for a very simple CBOR protocol:
 *
 * - on toplevel always array of three elements:
 *   - the ID (u64)
 *   - the command saying what to expect in the third element
 *     - 0 with NULL (7-22) = shutdown the hypervisor
 *     - 1 with NULL = open a telnet listener
 *     - 2 with one string = create a machine of this name
 *     - 3 with array of strings = run the given command inside the hypervisor
 */

struct hcs_parser_context {
  struct cbor_parser_context *ctx;
  struct cbor_stream *stream;
  sock *sock;

  u64 bytes_consumed;
  u64 major_state;
};

struct hcs_parser_channel {
  struct cbor_channel cch;
  struct hcs_parser_context *htx;

  enum {
    HCS_CMD_SHUTDOWN = 1,
    HCS_CMD_TELNET,
    HCS_CMD_MACHINE_START,
    HCS_CMD_MACHINE_STOP,
    HCS_CMD__MAX,
  } cmd;

  union flock_machine_config cfg;
};

static void
hcs_request_poweroff(struct hcs_parser_channel *hpc)
{
  log(L_INFO "Requested shutdown via CLI");
  ev_send_loop(&main_birdloop, &poweroff_event);

  struct cbor_writer *cw = cbor_init(htx->sock->tbuf, htx->sock->tbsize, ctx->lp);
  cbor_open_block_with_length(cw, 1);
  cbor_add_int(cw, -1);
  cbor_add_string(cw, "OK");
  sk_send(htx->sock, cw->pt);
}

static void
hcs_get_telnet(struct hcs_parser_context *htx)
{
}

struct hcs_parser_context *
hcs_parser_init(sock *s)
{
  struct cbor_parser_context *ctx = cbor_parser_new(s->pool, 4);
  struct hcs_parser_context *htx = mb_allocz(s->pool, sizeof *htx);

  htx->ctx = ctx;
  htx->sock = s;
  htx->stream = cbor_stream_new(s->pool, 4);

  return htx;
}

#define CBOR_PARSER_ERROR(...)	do {		\
  ctx->error = lp_sprintf(ctx->lp, __VA_ARGS__);\
  return -(htx->bytes_consumed + pos + 1);	\
} while (0)

s64
hcs_parse(struct hcs_parser_context *htx, const byte *buf, s64 size)
{
  ASSERT_DIE(size > 0);
  struct cbor_parser_context *ctx = htx->ctx;

  for (int pos = 0; pos < size; pos++)
  {
    if (!htx->channel)
    {
      htx->channel = cbor_parse_channel(ctx, htx->stream, buf[pos]);
      if (htx->channel == &cbor_channel_parse_error)
	return -(htx->bytes_consumed + pos + 1);
      continue;
    }

    switch (cbor_parse_byte(ctx, buf[pos]))
    {
      case CPR_ERROR:
	/* Parser failure */
	return -(htx->bytes_consumed + pos + 1);

      case CPR_MORE:
	/* Need more bytes */
	continue;

      case CPR_MAJOR:
	/* Check type acceptance */
	switch (htx->major_state)
	{
	  case 0: /* toplevel */
	    if (ctx->type != 4)
	      CBOR_PARSER_ERROR("Expected array, got %u", ctx->type);

	    if (ctx->value != 3)
	      CBOR_PARSER_ERROR("Expected array of length 1, got %u", ctx->value);

	    htx->major_state = 1;
	    break;

	  case 1: /* ID */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->id);
	    htx->major_state = 2;
	    break;

	  case 2: /* Command */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->cmd);
	    if (htx->cmd > HCS_CMD__MAX)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", htx->cmd);

	    htx->major_state = htx->cmd + 10;
	    break;

	  case HCS_CMD_SHUTDOWN + 10: /* shutdown command: expected null */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    hcs_request_poweroff(htx);

	    htx->major_state = 3;
	    break;

	  case HCS_CMD_TELNET + 10: /* telnet listener open */
	    if ((ctx->type == 7) && (ctx->value == 22))
	    {
	      hcs_get_telnet(htx);
	      htx->major_state = 3;
	      break;
	    }

	    else CBOR_PARSE_IF(ctx, TEXT, htx->cfg.cf.name)
	      ;
	    else
	      CBOR_PARSER_ERROR("Expected null or string, got %s", cbor_type_str(ctx->type));
	    break;

	  case HCS_CMD_MACHINE_START + 10: /* machine creation request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    htx->major_state = 501;
	    break;

	  case HCS_CMD_MACHINE_STOP + 1: /* machine shutdown request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expecting mapping, got %u", ctx->type);

	    htx->major_state = 601;
	    break;

	  case 7: /* process spawner */
	    bug("process spawner not implemented");
	    break;

	  case 501: /* machine creation argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 502;
	    break;

	  case 502: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, htx->cfg.cf.name);
	    break;

	  case 503: /* machine creation argument 1: type */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->cfg.cf.type);

	    if ((ctx->value < 1) && (ctx->value > 1) )
	      CBOR_PARSER_ERROR("Unexpected type, got %lu", ctx->value);

	    htx->major_state = 501;
	    break;

	  case 504: /* machine creation argument 2: basedir */
	    CBOR_PARSE_ONLY(ctx, BYTES, htx->cfg.container.basedir);
	    break;

	  case 505: /* machine creation argument 3: workdir */
	    CBOR_PARSE_ONLY(ctx, BYTES, htx->cfg.container.workdir);
	    break;

	  case 601: /* machine shutdown argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 602;
	    break;

	  case 602: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, htx->cfg.cf.name);
	    break;

	  default:
	    bug("invalid parser state");
	}
	break;

      case CPR_STR_END:
	/* Bytes read completely! */
	switch (htx->major_state)
	{
	  case 3:
	    hexp_get_telnet(htx->sock, htx->cfg.cf.name);
	    htx->major_state = 1;
	    break;

	  case 502:
	  case 504:
	  case 505:
	    htx->major_state = 501;
	    break;

	  case 602:
	    htx->major_state = 601;
	    break;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}
	break;
    }

    /* End of array or map */
    while (cbor_parse_block_end(ctx))
    {
      switch (htx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  htx->major_state = ~0ULL;
	  return pos + 1;

	case 1:
	  htx->major_state = 0;
	  break;

	case 5:
	  /* Finalize the command to exec in hypervisor */
	  CBOR_PARSER_ERROR("NOT IMPLEMENTED YET");
	  htx->major_state = 1;
	  break;

	case 501:
	  if (!htx->cfg.cf.type)
	    CBOR_PARSER_ERROR("Machine type not specified");

	  if (!htx->cfg.cf.name)
	    CBOR_PARSER_ERROR("Machine name not specified");

	  if (!htx->cfg.container.workdir)
	    CBOR_PARSER_ERROR("Machine workdir not specified");

	  if (!htx->cfg.container.basedir)
	    CBOR_PARSER_ERROR("Machine basedir not specified");

	  hypervisor_container_request(
	      htx->sock,
	      htx->cfg.cf.name,
	      htx->cfg.container.basedir,
	      htx->cfg.container.workdir);

	  htx->major_state = 1;
	  break;

	case 601:
	  if (!htx->cfg.cf.name)
	    CBOR_PARSER_ERROR("Machine name not specified");

	  hypervisor_container_shutdown(htx->sock, htx->cfg.cf.name);

	  htx->major_state = 1;
	  break;

	default:
	  bug("Unexpected state to end a mapping in");
      }
    }
  }

  htx->bytes_consumed += size;
  return size;
}

bool
hcs_complete(struct hcs_parser_context *htx)
{
  return htx->major_state == ~0ULL;
}

const char *
hcs_error(struct hcs_parser_context *htx)
{
  return htx->ctx->error;
}

void
hcs_parser_cleanup(struct hcs_parser_context *htx)
{
  cbor_parser_free(htx->ctx);
}

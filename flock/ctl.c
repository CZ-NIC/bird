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

struct hcs_parser_stream {
  struct cbor_parser_context *ctx;
  struct hcs_parser_channel *channel;
  sock *sock;

  u64 bytes_consumed;
  u64 major_state;

  struct cbor_stream stream;
};

struct hcs_parser_channel {
  struct cbor_channel cch;
  struct hcs_parser_stream *htx;

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

  CBOR_REPLY(&hpc->cch, cw)
    CBOR_PUT_MAP(cw)
    {
      cbor_put_int(cw, -1);
      cbor_put_string(cw, "OK");
    }

  cbor_done_channel(&hpc->cch);
}

struct hcs_parser_stream *
hcs_parser_init(sock *s)
{
  struct cbor_parser_context *ctx = cbor_parser_new(s->pool, 4);
  struct hcs_parser_stream *htx = mb_allocz(s->pool, sizeof *htx);

  htx->ctx = ctx;
  htx->sock = s;
  cbor_stream_init(&htx->stream, 3);

  return htx;
}

#define CBOR_PARSER_ERROR(...)	do {			\
  log(L_ERR "Hypervisor ctl parse: " __VA_ARGS__);	\
  return CPR_ERROR;					\
} while (0)

enum cbor_parse_result
hcs_parse(struct cbor_channel *cch, enum cbor_parse_result res)
{
  SKIP_BACK_DECLARE(struct hcs_parser_channel, hpc, cch, cch);
  SKIP_BACK_DECLARE(struct hcs_parser_stream, htx, stream, cch->stream);
  struct cbor_parser_context *ctx = &htx->stream.parser;

  switch (res)
  {
      case CPR_MAJOR:
	/* Check type acceptance */
	switch (htx->major_state)
	{
	  case 0: /* Command */
	    CBOR_PARSE_ONLY(ctx, POSINT, hpc->cmd);
	    if (hpc->cmd > HCS_CMD__MAX)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", hpc->cmd);

	    htx->major_state = hpc->cmd + 10;
	    return CPR_MORE;

	  case HCS_CMD_SHUTDOWN + 10: /* shutdown command: expected null */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    hcs_request_poweroff(hpc);
	    htx->major_state = 3;
	    return CPR_MORE;

	  case HCS_CMD_TELNET + 10: /* telnet listener open */
	    if ((ctx->type == 7) && (ctx->value == 22))
	    {
	      hexp_get_telnet(hpc);
	      htx->major_state = 3;
	      return CPR_MORE;
	    }

	    else CBOR_PARSE_IF(ctx, TEXT, hpc->cfg.cf.name)
	      ;
	    else
	      CBOR_PARSER_ERROR("Expected null or string, got %s", cbor_type_str(ctx->type));
	    return CPR_MORE;

	  case HCS_CMD_MACHINE_START + 10: /* machine creation request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    htx->major_state = 501;
	    return CPR_MORE;

	  case HCS_CMD_MACHINE_STOP + 1: /* machine shutdown request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expecting mapping, got %u", ctx->type);

	    htx->major_state = 601;
	    return CPR_MORE;

	  case 7: /* process spawner */
	    bug("process spawner not implemented");

	  case 501: /* machine creation argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 502;
	    return CPR_MORE;

	  case 502: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, hpc->cfg.cf.name);
	    return CPR_MORE;

	  case 503: /* machine creation argument 1: type */
	    CBOR_PARSE_ONLY(ctx, POSINT, hpc->cfg.cf.type);

	    if ((ctx->value < 1) && (ctx->value > 1) )
	      CBOR_PARSER_ERROR("Unexpected type, got %lu", ctx->value);

	    htx->major_state = 501;
	    return CPR_MORE;

	  case 504: /* machine creation argument 2: basedir */
	    CBOR_PARSE_ONLY(ctx, BYTES, hpc->cfg.container.basedir);
	    return CPR_MORE;

	  case 505: /* machine creation argument 3: workdir */
	    CBOR_PARSE_ONLY(ctx, BYTES, hpc->cfg.container.workdir);
	    return CPR_MORE;

	  case 601: /* machine shutdown argument */
	    CBOR_PARSE_ONLY(ctx, POSINT, htx->major_state);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state += 602;
	    return CPR_MORE;

	  case 602: /* machine creation argument 0: name */
	    CBOR_PARSE_ONLY(ctx, TEXT, hpc->cfg.cf.name);
	    return CPR_MORE;

	  default:
	    bug("invalid parser state");
	}
	break;

      case CPR_STR_END:
	/* Bytes read completely! */
	switch (htx->major_state)
	{
	  case HCS_CMD_TELNET + 10:
	    hexp_get_telnet(hpc);
	    break;

	  case 502:
	  case 504:
	  case 505:
	    htx->major_state = 501;
	    return CPR_MORE;

	  case 602:
	    htx->major_state = 601;
	    return CPR_MORE;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}
	break;

    case CPR_BLOCK_END:
      switch (htx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  htx->major_state = ~0ULL;
	  return CPR_BLOCK_END;

	case 1:
	  htx->major_state = 0;
	  return CPR_MORE;

	case 5:
	  /* Finalize the command to exec in hypervisor */
	  CBOR_PARSER_ERROR("NOT IMPLEMENTED YET");
	  htx->major_state = 1;
	  return CPR_MORE;

	case 501:
	  switch (hpc->cfg.cf.type)
	  {
	    case 1:
	      hypervisor_container_start(&hpc->cch, &hpc->cfg.container);
	      break;
	    default:
	      CBOR_PARSER_ERROR("Unknown machine type: %d", hpc->cfg.cf.type);
	  }
	  htx->major_state = 1;
	  return CPR_MORE;

	case 601:
	  /*
	  if (!htx->cfg.cf.name)
	    CBOR_PARSER_ERROR("Machine name not specified");

	  hypervisor_container_shutdown(htx->sock, htx->cfg.cf.name);
	    */

	  hypervisor_container_shutdown(&hpc->cch, &hpc->cfg.container);
	  htx->major_state = 1;
	  return CPR_MORE;

	default:
	  bug("Unexpected state to end a mapping in");
      }
      break;

    case CPR_ERROR:
    case CPR_MORE:
      CBOR_PARSER_ERROR("Invalid input");

  }

  return CPR_MORE;
}

bool
hcs_complete(struct hcs_parser_stream *htx)
{
  return htx->major_state == ~0ULL;
}

const char *
hcs_error(struct hcs_parser_stream *htx)
{
  return htx->ctx->error;
}

void
hcs_parser_cleanup(struct hcs_parser_stream *htx)
{
  cbor_parser_free(htx->ctx);
}

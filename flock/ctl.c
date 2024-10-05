#include "lib/birdlib.h"
#include "lib/cbor.h"
#include "lib/string.h"
#include "lib/io-loop.h"

#include "flock/flock.h"

#include <stdlib.h>

/*
 * Hand-written parser for a very simple CBOR protocol:
 *
 * - on toplevel always mapping of one element
 * - key of the element may be:
 *   - 0 with NULL (7-22) = shutdown the hypervisor
 *   - 1 with NULL = open a telnet listener
 *   - 2 with NULL = close the telnet listener (if not used)
 *   - 3 with one string = create a machine of this name
 *   - 4 with array of strings = run the given command inside the hypervisor
 */

struct hcs_parser_context {
  struct cbor_parser_context *ctx;
  sock *sock;

  u64 bytes_consumed;
  u64 major_state;

  /* Specific */
  union flock_machine_config cfg;
};

struct hcs_parser_context *
hcs_parser_init(sock *s)
{
  struct cbor_parser_context *ctx = cbor_parser_new(s->pool, 4);
  struct hcs_parser_context *htx = lp_allocz(ctx->lp, sizeof *htx);

  htx->ctx = ctx;
  htx->sock = s;

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
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    if (ctx->value != 1)
	      CBOR_PARSER_ERROR("Expected mapping of length 1, got %u", ctx->value);

	    htx->major_state = 1;
	    break;

	  case 1: /* inside toplevel mapping */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state = ctx->value + 2;
	    break;

	  case 2: /* shutdown command: expected null */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    log(L_INFO "Requested shutdown via CLI");
	    ev_send_loop(&main_birdloop, &poweroff_event);
	    {
	      struct cbor_writer *cw = cbor_init(htx->sock->tbuf, htx->sock->tbsize, ctx->lp);
	      cbor_open_block_with_length(cw, 1);
	      cbor_add_int(cw, -1);
	      cbor_add_string(cw, "OK");
	      sk_send(htx->sock, cw->pt);
	    }

	    htx->major_state = 1;
	    break;

	  case 3: /* telnet listener open */
	    if ((ctx->type == 7) && (ctx->value == 22))
	    {
	      hexp_get_telnet(htx->sock, NULL);
	      htx->major_state = 1;
	      break;
	    }

	    else if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected null or string, got %u-%u", ctx->type, ctx->value);

	    ASSERT_DIE(!ctx->target_buf);
	    htx->cfg.cf.name = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;

	    break;

	  case 4: /* telnet listener close */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    log(L_INFO "Requested telnet close");
	    htx->major_state = 1;
	    break;

	  case 5: /* machine creation request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    htx->major_state = 501;
	    break;

	  case 6: /* machine shutdown request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expecting mapping, got %u", ctx->type);

	    htx->major_state = 601;
	    break;

	  case 7: /* process spawner */
	    bug("process spawner not implemented");
	    break;

	  case 501: /* machine creation argument */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state = ctx->value + 502;
	    break;

	  case 502: /* machine creation argument 0: name */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (htx->cfg.cf.name)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / name");

	    ASSERT_DIE(!ctx->target_buf);
	    htx->cfg.cf.name = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 503: /* machine creation argument 1: type */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (htx->cfg.cf.type)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / type, already have %d", htx->cfg.cf.type);

	    if ((ctx->value < 1) && (ctx->value > 1) )
	      CBOR_PARSER_ERROR("Unexpected type, got %lu", ctx->value);

	    htx->cfg.cf.type = ctx->value;
	    htx->major_state = 501;
	    break;

	  case 504: /* machine creation argument 2: basedir */
	    if (ctx->type != 2)
	      CBOR_PARSER_ERROR("Expected bytestring, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (htx->cfg.container.basedir)
	      CBOR_PARSER_ERROR("Duplicate argument 2 / basedir");

	    ASSERT_DIE(!ctx->target_buf);
	    htx->cfg.container.basedir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 505: /* machine creation argument 3: workdir */
	    if (ctx->type != 2)
	      CBOR_PARSER_ERROR("Expected bytestring, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (htx->cfg.container.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 3 / workdir");

	    ASSERT_DIE(!ctx->target_buf);
	    htx->cfg.container.workdir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 601: /* machine shutdown argument */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 1)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    htx->major_state = ctx->value + 602;
	    break;

	  case 602: /* machine creation argument 0: name */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (ctx->tflags & CPT_VARLEN)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (htx->cfg.cf.name)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / name");

	    ASSERT_DIE(!ctx->target_buf);
	    htx->cfg.cf.name = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
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

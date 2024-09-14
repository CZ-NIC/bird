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

struct cbor_parser_context {
  linpool *lp;
  sock *sock;

  PACKED enum {
    CPE_TYPE = 0,
    CPE_READ_INT,
    CPE_COMPLETE_INT,
    CPE_READ_BYTE,
  } partial_state, partial_next;

  byte type;
  u64 value;
  u64 partial_countdown;

  u64 bytes_consumed;

  byte *target_buf;
  uint target_len;

  u64 major_state;

  const char *error;

#define LOCAL_STACK_MAX_DEPTH 3
  u64 stack_countdown[LOCAL_STACK_MAX_DEPTH];
  uint stack_pos;

  /* Specific */
  union flock_machine_config cfg;
};

#define CBOR_PARSER_ERROR(...)	do {		\
  ctx->error = lp_sprintf(ctx->lp, __VA_ARGS__);\
  return -(ctx->bytes_consumed + pos + 1);	\
} while (0)

#define CBOR_PARSER_READ_INT(next)  do {		\
  ctx->partial_state = CPE_READ_INT;			\
  ctx->partial_countdown = (1 << (ctx->value - 24));	\
  ctx->value = 0;					\
  ctx->partial_next = next;				\
} while (0)

struct cbor_parser_context *
hcs_parser_init(sock *s)
{
  linpool *lp = lp_new(s->pool);
  struct cbor_parser_context *ctx = lp_allocz(lp, sizeof *ctx);

  ctx->lp = lp;
  ctx->sock = s;

  ctx->type = 0xff;
  ctx->stack_countdown[0] = 1;

  return ctx;
}

s64
hcs_parse(struct cbor_parser_context *ctx, const byte *buf, s64 size)
{
  ASSERT_DIE(size > 0);

  for (int pos = 0; pos < size; pos++)
  {
    const byte bp = buf[pos];
    bool value_is_special = 0;
    bool exit_stack = false;

    switch (ctx->partial_state)
    {
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
	    CBOR_PARSER_READ_INT(CPE_COMPLETE_INT);
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
	    CBOR_PARSER_READ_INT(CPE_COMPLETE_INT);
	    break;
	  }
	  else if ((ctx->value == 31) && (ctx->type >= 2) && (ctx->type <= 5))
	    /* Indefinite length, fall through */
	    value_is_special = 1;
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
	/* TODO: exception for 7-31 end of long thing */

	/* Check type acceptance */
	switch (ctx->major_state)
	{
	  case 0: /* toplevel */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    if (ctx->value != 1)
	      CBOR_PARSER_ERROR("Expected mapping of length 1, got %u", ctx->value);

	    ctx->major_state = 1;
	    break;

	  case 1: /* inside toplevel mapping */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    ctx->major_state = ctx->value + 2;
	    break;

	  case 2: /* shutdown command: expected null */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    log(L_INFO "Requested shutdown via CLI");
	    ev_send_loop(&main_birdloop, &poweroff_event);
	    {
	      struct cbor_writer *cw = cbor_init(ctx->sock->tbuf, ctx->sock->tbsize, ctx->lp);
	      cbor_open_block_with_length(cw, 1);
	      cbor_add_int(cw, -1);
	      cbor_add_string(cw, "OK");
	      sk_send(ctx->sock, cw->pt);
	    }

	    ctx->major_state = 1;
	    break;

	  case 3: /* telnet listener open */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);
	    /* TODO: allow this also for machines */

	    log(L_INFO "Requested telnet open");

	    hexp_get_telnet(ctx->sock, NULL);

	    ctx->major_state = 1;
	    break;

	  case 4: /* telnet listener close */
	    if ((ctx->type != 7) || (ctx->value != 22))
	      CBOR_PARSER_ERROR("Expected null, got %u-%u", ctx->type, ctx->value);

	    log(L_INFO "Requested telnet close");
	    ctx->major_state = 1;
	    break;

	  case 5: /* machine creation request */
	    if (ctx->type != 5)
	      CBOR_PARSER_ERROR("Expected mapping, got %u", ctx->type);

	    ctx->major_state = 501;
	    break;

	  case 6: /* process spawner */
	    CBOR_PARSER_ERROR("NOT IMPLEMENTED YET");
	    break;

	  case 501: /* machine creation argument */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->value >= 5)
	      CBOR_PARSER_ERROR("Command key too high, got %lu", ctx->value);

	    ctx->major_state = ctx->value + 502;
	    break;

	  case 502: /* machine creation argument 0: name */
	    if (ctx->type != 3)
	      CBOR_PARSER_ERROR("Expected string, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ctx->cfg.cf.name)
	      CBOR_PARSER_ERROR("Duplicate argument 0 / name");

	    ASSERT_DIE(!ctx->target_buf);
	    ctx->cfg.cf.name = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 503: /* machine creation argument 1: type */
	    if (ctx->type != 0)
	      CBOR_PARSER_ERROR("Expected integer, got %u", ctx->type);

	    if (ctx->cfg.cf.type)
	      CBOR_PARSER_ERROR("Duplicate argument 1 / type, already have %d", ctx->cfg.cf.type);

	    if ((ctx->value < 1) && (ctx->value > 1) )
	      CBOR_PARSER_ERROR("Unexpected type, got %lu", ctx->value);

	    ctx->cfg.cf.type = ctx->value;
	    ctx->major_state = 501;
	    break;

	  case 504: /* machine creation argument 2: workdir */
	    if (ctx->type != 2)
	      CBOR_PARSER_ERROR("Expected bytestring, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ctx->cfg.container.workdir)
	      CBOR_PARSER_ERROR("Duplicate argument 2 / workdir");

	    ASSERT_DIE(!ctx->target_buf);
	    ctx->cfg.container.workdir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  case 505: /* machine creation argument 3: basedir */
	    if (ctx->type != 2)
	      CBOR_PARSER_ERROR("Expected bytestring, got %u", ctx->type);

	    if (value_is_special)
	      CBOR_PARSER_ERROR("Variable length string not supported yet");

	    if (ctx->cfg.container.basedir)
	      CBOR_PARSER_ERROR("Duplicate argument 3 / basedir");

	    ASSERT_DIE(!ctx->target_buf);
	    ctx->cfg.container.basedir = ctx->target_buf = lp_alloc(ctx->lp, ctx->value + 1);
	    ctx->target_len = ctx->value;
	    break;

	  default:
	    bug("invalid parser state");
	}

	/* Some types are completely parsed, some not yet */
	switch (ctx->type)
	{
	  case 0:
	  case 1:
	  case 7:
	    exit_stack = !--ctx->stack_countdown[ctx->stack_pos];
	    ctx->partial_state = CPE_TYPE;
	    break;

	  case 2:
	  case 3:
	    ctx->partial_state = CPE_READ_BYTE;
	    ctx->partial_countdown = ctx->value;
	    ctx->target_buf = ctx->target_buf ?: lp_allocu(
		ctx->lp, ctx->target_len = (ctx->target_len ?: ctx->value));
	    break;

	  case 4:
	  case 5:
	    if (++ctx->stack_pos >= LOCAL_STACK_MAX_DEPTH)
	      CBOR_PARSER_ERROR("Stack too deep");

	    /* set array/map size;
	     * once for arrays, twice for maps;
	     * ~0 for indefinite */
	    ctx->stack_countdown[ctx->stack_pos] = value_is_special ? ~0ULL :
	      (ctx->value * (ctx->type - 3));
	    ctx->partial_state = CPE_TYPE;
	    break;
	}

	break;

      case CPE_READ_BYTE:
	*ctx->target_buf = bp;
	ctx->target_buf++;
	if (--ctx->target_len)
	  break;

	/* Read completely! */
	switch (ctx->major_state)
	{
	  case 5:
	    /* Actually not this one */
	    CBOR_PARSER_ERROR("NOT IMPLEMENTED YET");

	  case 502:
	  case 504:
	  case 505:
	    ctx->major_state = 501;
	    break;

	  default:
	    bug("Unexpected state to end a (byte)string in");
	  /* Code to run at the end of a (byte)string */
	}

	ctx->target_buf = NULL;
	ctx->partial_state = CPE_TYPE;

	exit_stack = !--ctx->stack_countdown[ctx->stack_pos];
    }

    /* End of array or map */
    while (exit_stack)
    {
      switch (ctx->major_state)
      {
	/* Code to run at the end of the mapping */
	case 0: /* toplevel item ended */
	  ctx->major_state = ~0ULL;
	  return pos + 1;

	case 1:
	  ctx->major_state = 0;
	  break;

	case 5:
	  /* Finalize the command to exec in hypervisor */
	  CBOR_PARSER_ERROR("NOT IMPLEMENTED YET");
	  ctx->major_state = 1;
	  break;

	case 501:
	  if (!ctx->cfg.cf.type)
	    CBOR_PARSER_ERROR("Machine type not specified");

	  if (!ctx->cfg.cf.name)
	    CBOR_PARSER_ERROR("Machine name not specified");

	  if (!ctx->cfg.container.workdir)
	    CBOR_PARSER_ERROR("Machine workdir not specified");

	  if (!ctx->cfg.container.basedir)
	    CBOR_PARSER_ERROR("Machine basedir not specified");

	  container_start(ctx->sock, &ctx->cfg.container);
	  ctx->major_state = 1;
	  break;

	default:
	  bug("Unexpected state to end a mapping in");
      }

      /* Check exit from the next item */
      ASSERT_DIE(ctx->stack_pos);
      exit_stack = !--ctx->stack_countdown[--ctx->stack_pos];
    }
  }

  ctx->bytes_consumed += size;
  return size;
}

bool
hcs_complete(struct cbor_parser_context *ctx)
{
  return ctx->major_state == ~0ULL;
}

const char *
hcs_error(struct cbor_parser_context *ctx)
{
  return ctx->error;
}

void
hcs_parser_cleanup(struct cbor_parser_context *ctx)
{
  rfree(ctx->lp);
}

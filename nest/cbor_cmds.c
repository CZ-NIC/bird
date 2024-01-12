
#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/cli.h"
#include "conf/conf.h"
#include "lib/string.h"
#include "filter/filter.h"
#include "nest/cbor_cmds.h"
#include "proto/ospf/ospf_for_cbor.h"

int64_t preprocess_time(btime t) {
  return tm_get_real_time(t) TO_S ;
}

uint compare_byte_str(byte *str1, uint length, const char *str2) {
  if (length != strlen(str2)) {
    return 0;
  }
  for (size_t i = 0; i < length; i++) {
    if (str1[i]!=str2[i]) {
      return 0;
    }
  }
  return 1;
}


static char *
proto_state_name_stolen_for_cbor(struct proto *p)
{
  switch (p->proto_state)
  {
  case PS_DOWN:		return p->active ? "flush" : "down";
  case PS_START:	return "start";
  case PS_UP:		return "up";
  case PS_STOP:		return "stop";
  default:		return "???";
  }
}

// TODO include resource header to use typedefed linpool
uint
cmd_show_protocols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp)
{
  log("in cmd_show_protocols_cbor");
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);

  cbor_add_string(w, "show_protocols:message");
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "table");
  cbor_open_list(w);
  int all = 0;
  int protocol = -1;
  if (args->pt > 0 && compare_byte_str(args->args[0].arg, args->args[0].len, "all"))
  {
    all = 1;
  }

  if (args->pt - all > 0)
  {
    protocol = all;
  }

  struct proto *p;

  WALK_LIST(p, proto_list)
  {
    if (protocol == -1 || compare_byte_str(args->args[protocol].arg, args->args[protocol].len, p->name))
    {
      cbor_open_block(w);
      cbor_string_string(w, "name", p->name);
      cbor_string_string(w, "proto", p->proto->name);
      cbor_string_string(w, "table", p->main_channel ? p->main_channel->table->name : "---");
      cbor_string_string(w, "state", proto_state_name_stolen_for_cbor(p));
      cbor_string_epoch_time(w, "since", tm_get_real_time(p->last_state_change), -6);
      byte buf[256];
      buf[0] = 0;
      if (p->proto->get_status)
        p->proto->get_status(p, buf);
      cbor_string_string(w, "info", buf);

      if (all)
      {
        if (p->cf->dsc)
          cbor_string_string(w, "description", p->cf->dsc);
        if (p->message)
          cbor_string_string(w, "message", p->message);
        if (p->cf->router_id)
          cbor_string_ipv4(w, "router_id", p->cf->router_id);
        if (p->vrf_set)
          cbor_string_string(w, "vrf", p->vrf ? p->vrf->name : "default");

        if (p->proto->show_proto_info_cbor)
          p->proto->show_proto_info_cbor(w, p);
        else
        {
          struct channel *c;
          WALK_LIST(c, p->channels)
	    channel_show_info_cbor(w, c);
        }
      }
      cbor_close_block_or_list(w);
    }
  }
  cbor_close_block_or_list(w);
  return w->pt;
}

extern pool *rt_table_pool;
extern pool *rta_pool;
extern uint *pages_kept;

uint
cmd_show_memory_cbor(byte *tbuf, uint capacity, struct linpool *lp)
{
  log("in cmd_show_memory_cbor");
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  log("w->pt %i w->cbor %i", w->pt, w->cbor);
  cbor_open_block_with_length(w, 1);

  cbor_add_string(w, "show_memory:message");
  cbor_open_block_with_length(w, 2);

  cbor_string_string(w, "header", "BIRD memory usage");

  cbor_add_string(w, "body");
  cbor_open_block(w);

  struct resmem memory = rmemsize(rt_table_pool);
  cbor_named_block_two_ints(w, "routing_tables", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(rta_pool);
  cbor_named_block_two_ints(w, "route_attributes", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(proto_pool);
  cbor_named_block_two_ints(w, "protocols", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(config_pool);
  cbor_named_block_two_ints(w, "current_config", "effective", memory.effective, "overhead", memory.overhead);

  memory = rmemsize(&root_pool);
#ifdef HAVE_MMAP
  cbor_named_block_two_ints(w, "standby_memory", "effective", 0, "overhead", page_size * *pages_kept);
#endif
  memory.overhead += page_size * *pages_kept;
  cbor_named_block_two_ints(w, "total", "effective", memory.effective, "overhead", memory.overhead);

  cbor_close_block_or_list(w); // we do not know for sure, that standby memory will be printed, so we do not know number of block items. If we know that, we open the block for 6 (or 5) items and we do not close anything

  cbor_write_to_file(w, "show_memory.cbor");
  log("show memory written");
  return w->pt;
}

extern int shutting_down;
extern int configuring;

uint
cmd_show_status_cbor(byte *tbuf, uint capacity, struct linpool *lp)
{
  log("show status");
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_status:message");

  cbor_open_block_with_length(w, 3);
  cbor_string_string(w, "version", BIRD_VERSION);
  cbor_add_string(w, "body");
  cbor_open_block(w);
  cbor_string_ipv4(w, "router_id", config->router_id);
  cbor_string_string(w, "hostname", config->hostname);
  cbor_string_epoch_time(w, "server_time", tm_get_real_time(current_time()), -6);
  cbor_string_epoch_time(w, "last_reboot", tm_get_real_time(boot_time), -6);
  cbor_string_epoch_time(w, "last_reconfiguration", tm_get_real_time(config->load_time), -6);
  if (is_gr_active())
  {
    cbor_add_string(w, "gr_restart");
    cbor_open_block_with_length(w, 2);
    cbor_string_int(w, "waiting_for_n_channels_to_recover", get_graceful_restart_locks_num());
    cbor_add_string(w, "wait_timer");
    cbor_open_block_with_length(w, 2);
    cbor_string_relativ_time(w, "remains", get_tm_remains_gr_wait_timer(), -6);
    cbor_string_relativ_time(w, "count_time", get_config_gr_wait(), -6);
  }
  cbor_close_block_or_list(w);
  cbor_add_string(w, "state");
  if (shutting_down)
    cbor_add_string(w, "Shutdown in progress");
  else if (configuring)
    cbor_add_string(w, "Reconfiguration in progress");
  else
    cbor_add_string(w, "Daemon is up and running");
  cbor_write_to_file(w, "test.cbor");
  return w->pt;
}

int parse_show_symbols_arg(struct argument *argument)
{
  char *params[] = {"table", "filter", "function", "protocol", "template", "constant", "variable"};
  int param_vals[] = {SYM_TABLE, SYM_FILTER, SYM_FUNCTION, SYM_PROTO, SYM_TEMPLATE, SYM_CONSTANT, SYM_VARIABLE};  // defined in conf.h
  for (size_t j = 0; j < sizeof(params)/sizeof(char*); j++)
  {
    if (compare_byte_str(argument->arg, argument->len, params[j]))
    {
      return param_vals[j];
    }
  }
  return -1;
}

uint
cmd_show_symbols_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp)
{
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_symbols:message");
  cbor_open_block_with_length(w, 1);

  int show_type = SYM_VOID;
  if (args->pt > 0)
  {
    show_type = parse_show_symbols_arg(&args->args[args->pt - 1]); // Takes just the last one argument. Current bird cli answers only last argument too, but can fail on previous.
  }

  if (show_type == -1)
  {
    cbor_add_string(w, "table");
    cbor_open_list_with_length(w, 1);
    cbor_open_block_with_length(w, 2);

    for (const struct sym_scope *scope = config->root_scope; scope; scope = scope->next)
    {
      HASH_WALK(scope->hash, next, sym)
      {
	if (compare_byte_str(args->args[args->pt - 1].arg, args->args[args->pt - 1].len, sym->name))
	{
	  cbor_add_string(w, "name");
	  cbor_nonterminated_string(w, args->args[args->pt - 1].arg, args->args[args->pt - 1].len);
	  cbor_string_string(w, "type", cf_symbol_class_name(sym));
	  return w->pt;
        }
      }
      HASH_WALK_END;
    }
    cbor_add_string(w, "name");
    cbor_nonterminated_string(w,  args->args[args->pt - 1].arg, args->args[args->pt - 1].len);
    cbor_string_string(w, "type", "symbol not known");
    return w->pt;
  }
  else
  {
    cbor_add_string(w, "table");
    cbor_open_list(w);
    for (const struct sym_scope *scope = config->root_scope; scope; scope = scope->next)
      HASH_WALK(scope->hash, next, sym)
      {
        if (!sym->scope->active)
          continue;
        if (show_type == SYM_VARIABLE || show_type == SYM_CONSTANT)
        {
          if (!(show_type  == (int)(sym->class & 0xffffff00)))
            continue;
        }
        else if (show_type != SYM_VOID && (sym->class != show_type))
          continue;

        cbor_open_block_with_length(w, 2);
	cbor_string_string(w, "name", sym->name);
        cbor_string_string(w, "type", cf_symbol_class_name(sym));
      }
      HASH_WALK_END;

    cbor_close_block_or_list(w);
    return w->pt;
  }
}


struct proto *
cbor_get_proto_type(enum protocol_class proto_type, struct cbor_writer *w)
{
  log("in type");
  struct proto *p, *q;
  p = NULL;
  WALK_LIST(q, proto_list)
    if ((q->proto->class == proto_type) && (q->proto_state != PS_DOWN))
    {
      if (p)
      {
        cbor_string_string(w, "error", "multiple protocols running");
        return NULL;
      }
      p = q;
    }
  if (!p)
  {
    cbor_string_string(w, "error", "no such protocols running");
    return NULL;
  }
  return p;
}

struct proto *
cbor_get_proto_name(struct argument *arg, enum protocol_class proto_type, struct cbor_writer *w)
{
  log("in name");
  struct proto *q;
  WALK_LIST(q, proto_list)
  {
    log("%s %s %i %i %i", arg->arg, q->name, compare_byte_str(arg->arg, arg->len, q->name) , (q->proto_state != PS_DOWN) , (q->proto->class == proto_type));
    if (compare_byte_str(arg->arg, arg->len, q->name) && (q->proto_state != PS_DOWN) && (q->proto->class == proto_type))
    {
      return q;
    }
  }
  cbor_add_string(w, "not found");
  cbor_nonterminated_string(w, arg->arg, arg->len);
  return NULL;
}


uint
cmd_show_ospf_cbor(byte *tbuf, uint capacity, struct arg_list *args, struct linpool *lp)
{
  log("in ospf args %i, pt %i", args, args->pt);
  struct cbor_writer *w = cbor_init(tbuf, capacity, lp);
  cbor_open_block_with_length(w, 1);
  cbor_add_string(w, "show_ospf:message");

  if (args->pt == 0)
  {
    cbor_open_block_with_length(w, 1);
    cbor_string_string(w, "not_implemented", "show everything about ospf");
    return w->pt;
  }

  if (compare_byte_str(args->args[0].arg, args->args[0].len, "topology"))
  {
    cbor_open_block(w);
    struct proto *proto;
    int all_ospf = (args->pt > 1) && compare_byte_str(args->args[1].arg, args->args[1].len, "all");
    if (args->pt - all_ospf > 1) // if there is protocol name
    {
      proto = cbor_get_proto_name(&args->args[args->pt -1], PROTOCOL_OSPF, w);
    }
    else {
      proto = cbor_get_proto_type(PROTOCOL_OSPF, w);
    }

    if (proto == NULL)
    {
      cbor_close_block_or_list(w);
      return w->pt;
    }

    ospf_sh_state_cbor(w, proto, 0, all_ospf);
    cbor_close_block_or_list(w);
    return w->pt;
  } else {
    cbor_open_block_with_length(w, 1);
    cbor_add_string(w, "not_implemented");
    cbor_nonterminated_string(w, args->args[0].arg, args->args[0].len);
    return w->pt;
  }
}


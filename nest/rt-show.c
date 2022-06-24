/*
 *	BIRD -- Route Display Routines
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2017       Jan Moskyto Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/rt.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "sysdep/unix/krt.h"

static void
rt_show_table(struct rt_show_data *d)
{
  struct cli *c = d->cli;

  /* No table blocks in 'show route count' */
  if (d->stats == 2)
    return;

  if (d->last_table) cli_printf(c, -1007, "");
  cli_printf(c, -1007, "Table %s:",
      d->tab->prefilter ? "import" : d->tab->table->name);
  d->last_table = d->tab;
}

static inline struct krt_proto *
rt_show_get_kernel(struct rt_show_data *d)
{
  struct proto_config *krt = d->tab->table->config->krt_attached;
  return krt ? (struct krt_proto *) krt->proto : NULL;
}

static void
rt_show_rte(struct cli *c, byte *ia, rte *e, struct rt_show_data *d, int primary)
{
  byte from[IPA_MAX_TEXT_LENGTH+8];
  byte tm[TM_DATETIME_BUFFER_SIZE], info[256];
  ea_list *a = e->attrs;
  int sync_error = d->kernel ? krt_get_sync_error(d->kernel, e) : 0;
  void (*get_route_info)(struct rte *, byte *buf);
  eattr *nhea = net_type_match(e->net, NB_DEST) ?
    ea_find(a, &ea_gen_nexthop) : NULL;
  struct nexthop_adata *nhad = nhea ? (struct nexthop_adata *) nhea->u.ptr : NULL;
  int dest = nhad ? (NEXTHOP_IS_REACHABLE(nhad) ? RTD_UNICAST : nhad->dest) : RTD_NONE;
  int flowspec_valid = net_is_flow(e->net) ? rt_get_flowspec_valid(e) : FLOWSPEC_UNKNOWN;

  tm_format_time(tm, &config->tf_route, e->lastmod);
  ip_addr a_from = ea_get_ip(a, &ea_gen_from, IPA_NONE);
  if (ipa_nonzero(a_from) && (!nhad || !ipa_equal(a_from, nhad->nh.gw)))
    bsprintf(from, " from %I", a_from);
  else
    from[0] = 0;

  /* Need to normalize the extended attributes */
  if (d->verbose && !rta_is_cached(a) && a)
    a = ea_normalize(a, 0);

  get_route_info = e->src->proto->proto->get_route_info;
  if (get_route_info)
    get_route_info(e, info);
  else
    bsprintf(info, " (%d)", rt_get_preference(e));

  if (d->last_table != d->tab)
    rt_show_table(d);

  eattr *heea;
  struct hostentry_adata *had = NULL;
  if (!net_is_flow(e->net) && (dest == RTD_NONE) && (heea = ea_find(a, &ea_gen_hostentry)))
    had = (struct hostentry_adata *) heea->u.ptr;

  cli_printf(c, -1007, "%-20s %s [%s %s%s]%s%s", ia,
      net_is_flow(e->net) ? flowspec_valid_name(flowspec_valid) : had ? "recursive" : rta_dest_name(dest),
      e->src->proto->name, tm, from, primary ? (sync_error ? " !" : " *") : "", info);

  if (dest == RTD_UNICAST)
    NEXTHOP_WALK(nh, nhad)
    {
      char mpls[MPLS_MAX_LABEL_STACK*12 + 5], *lsp = mpls;
      char *onlink = (nh->flags & RNF_ONLINK) ? " onlink" : "";
      char weight[16] = "";

      if (nh->labels)
	{
	  lsp += bsprintf(lsp, " mpls %d", nh->label[0]);
	  for (int i=1;i<nh->labels; i++)
	    lsp += bsprintf(lsp, "/%d", nh->label[i]);
	}
      *lsp = '\0';

      if (!NEXTHOP_ONE(nhad))
	bsprintf(weight, " weight %d", nh->weight + 1);

      if (ipa_nonzero(nh->gw))
	cli_printf(c, -1007, "\tvia %I on %s%s%s%s",
		   nh->gw, nh->iface->name, mpls, onlink, weight);
      else
	cli_printf(c, -1007, "\tdev %s%s%s",
		   nh->iface->name, mpls,  onlink, weight);
    }
  else if (had)
    {
      if (ipa_nonzero(had->he->link) && !ipa_equal(had->he->link, had->he->addr))
	cli_printf(c, -1007, "\tvia %I %I table %s", had->he->addr, had->he->link, had->he->tab->name);
      else
	cli_printf(c, -1007, "\tvia %I table %s", had->he->addr, had->he->tab->name);
    }

  if (d->verbose)
    ea_show_list(c, a);
}

static void
rt_show_net(struct rt_show_data *d, const net_addr *n, rte **feed, uint count)
{
  struct cli *c = d->cli;
  byte ia[NET_MAX_TEXT_LENGTH+1];
  struct channel *ec = d->tab->export_channel;

  /* The Clang static analyzer complains that ec may be NULL.
   * It should be ensured to be not NULL by rt_show_prepare_tables() */
  ASSUME(!d->export_mode || ec);

  int first = 1;
  int first_show = 1;
  int pass = 0;

  for (uint i = 0; i < count; i++)
    {
      if (!d->tab->prefilter && (rte_is_filtered(feed[i]) != d->filtered))
	continue;

      d->rt_counter++;
      d->net_counter += first;
      first = 0;

      if (pass)
	continue;

      struct rte e = *feed[i];
      if (d->tab->prefilter)
	if (e.sender != d->tab->prefilter->in_req.hook)
	  continue;
	else while (e.attrs->next)
	  e.attrs = e.attrs->next;

      /* Export channel is down, do not try to export routes to it */
      if (ec && !ec->out_req.hook)
	goto skip;

      if (d->export_mode == RSEM_EXPORTED)
        {
	  if (!bmap_test(&ec->export_map, e.id))
	    goto skip;

	  // if (ec->ra_mode != RA_ANY)
	  //   pass = 1;
        }
      else if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_MERGED))
	{
	  /* Special case for merged export */
	  pass = 1;
	  rte *em = rt_export_merged(ec, feed, count, tmp_linpool, 1);

	  if (em)
	    e = *em;
	  else
	    goto skip;
	}
      else if (d->export_mode)
	{
	  struct proto *ep = ec->proto;
	  int ic = ep->preexport ? ep->preexport(ec, &e) : 0;

	  if (ec->ra_mode == RA_OPTIMAL || ec->ra_mode == RA_MERGED)
	    pass = 1;

	  if (ic < 0)
	    goto skip;

	  if (d->export_mode > RSEM_PREEXPORT)
	    {
	      /*
	       * FIXME - This shows what should be exported according to current
	       * filters, but not what was really exported. 'configure soft'
	       * command may change the export filter and do not update routes.
	       */
	      int do_export = (ic > 0) ||
		(f_run(ec->out_filter, &e, FF_SILENT) <= F_ACCEPT);

	      if (do_export != (d->export_mode == RSEM_EXPORT))
		goto skip;

	      if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_ACCEPTED))
		pass = 1;
	    }
	}

      if (d->show_protocol && (d->show_protocol != e.src->proto))
	goto skip;

      if (f_run(d->filter, &e, 0) > F_ACCEPT)
	goto skip;

      if (d->stats < 2)
      {
	if (first_show)
	  net_format(n, ia, sizeof(ia));
	else
	  ia[0] = 0;

	rt_show_rte(c, ia, &e, d, !d->tab->prefilter && !i);
	first_show = 0;
      }

      d->show_counter++;

    skip:
      if (d->primary_only)
	break;
    }

  if ((d->show_counter - d->show_counter_last_flush) > 64)
  {
    d->show_counter_last_flush = d->show_counter;
    cli_write_trigger(d->cli);
  }
}

static void
rt_show_net_export_bulk(struct rt_export_request *req, const net_addr *n,
    struct rt_pending_export *rpe UNUSED, rte **feed, uint count)
{
  struct rt_show_data *d = SKIP_BACK(struct rt_show_data, req, req);
  return rt_show_net(d, n, feed, count);
}

static void
rt_show_export_stopped_cleanup(struct rt_export_request *req)
{
  struct rt_show_data *d = SKIP_BACK(struct rt_show_data, req, req);

  /* The hook is now invalid */
  req->hook = NULL;

  /* Unlock referenced tables */
  struct rt_show_data_rtable *tab;
  WALK_LIST(tab, d->tables)
    rt_unlock_table(tab->table);

  /* And free the CLI (deferred) */
  rfree(d->cli->pool);
}

static int
rt_show_cleanup(struct cli *c)
{
  struct rt_show_data *d = c->rover;

  /* Cancel the feed */
  if (d->req.hook)
  {
    rt_stop_export(&d->req, rt_show_export_stopped_cleanup);
    return 1;
  }
  else
    return 0;
}

static void rt_show_export_stopped(struct rt_export_request *req);

static void
rt_show_log_state_change(struct rt_export_request *req, u8 state)
{
  if (state == TES_READY)
    rt_stop_export(req, rt_show_export_stopped);
}

static void
rt_show_dump_req(struct rt_export_request *req)
{
  debug("  CLI Show Route Feed %p\n", req);
}

static void
rt_show_cont(struct rt_show_data *d)
{
  struct cli *c = d->cli;

  if (d->running_on_config && (d->running_on_config != config))
  {
    cli_printf(c, 8004, "Stopped due to reconfiguration");

    /* Unlock referenced tables */
    struct rt_show_data_rtable *tab;
    WALK_LIST(tab, d->tables)
      rt_unlock_table(tab->table);

    /* No more action */
    c->cleanup = NULL;
    c->cont = NULL;
    c->rover = NULL;
    cli_write_trigger(c);
    return;
  }

  d->req = (struct rt_export_request) {
    .addr_in = (d->addr_mode == RSD_ADDR_IN) ? d->addr : NULL,
    .name = "CLI Show Route",
    .export_bulk = rt_show_net_export_bulk,
    .dump_req = rt_show_dump_req,
    .log_state_change = rt_show_log_state_change,
  };

  d->table_counter++;
  d->kernel = rt_show_get_kernel(d);

  d->show_counter_last = d->show_counter;
  d->rt_counter_last   = d->rt_counter;
  d->net_counter_last  = d->net_counter;

  if (d->tables_defined_by & RSD_TDB_SET)
    rt_show_table(d);

  rt_request_export(&d->tab->table->exporter, &d->req);
}

static void
rt_show_export_stopped(struct rt_export_request *req)
{
  struct rt_show_data *d = SKIP_BACK(struct rt_show_data, req, req);

  /* The hook is now invalid */
  req->hook = NULL;

  if (d->stats)
  {
    if (d->last_table != d->tab)
      rt_show_table(d);

    cli_printf(d->cli, -1007, "%d of %d routes for %d networks in table %s",
	       d->show_counter - d->show_counter_last, d->rt_counter - d->rt_counter_last,
	       d->net_counter - d->net_counter_last, d->tab->table->name);
  }

  d->kernel = NULL;
  d->tab = NODE_NEXT(d->tab);

  if (NODE_VALID(d->tab))
    return rt_show_cont(d);

  /* Unlock referenced tables */
  struct rt_show_data_rtable *tab;
  WALK_LIST(tab, d->tables)
    rt_unlock_table(tab->table);

  /* Printout total stats */
  if (d->stats && (d->table_counter > 1))
  {
    if (d->last_table) cli_printf(d->cli, -1007, "");
    cli_printf(d->cli, 14, "Total: %d of %d routes for %d networks in %d tables",
	       d->show_counter, d->rt_counter, d->net_counter, d->table_counter);
  }
  else
    cli_printf(d->cli, 0, "");

  cli_write_trigger(d->cli);
}

struct rt_show_data_rtable *
rt_show_add_table(struct rt_show_data *d, rtable *t)
{
  struct rt_show_data_rtable *tab = cfg_allocz(sizeof(struct rt_show_data_rtable));
  tab->table = t;
  add_tail(&(d->tables), &(tab->n));
  return tab;
}

static inline void
rt_show_get_default_tables(struct rt_show_data *d)
{
  struct channel *c;
  struct rt_show_data_rtable *tab;

  if (d->export_channel)
  {
    c = d->export_channel;
    tab = rt_show_add_table(d, c->table);
    tab->export_channel = c;
    return;
  }

  if (d->export_protocol)
  {
    WALK_LIST(c, d->export_protocol->channels)
    {
      if (!c->out_req.hook)
	continue;

      tab = rt_show_add_table(d, c->table);
      tab->export_channel = c;
    }
    return;
  }

  if (d->show_protocol)
  {
    WALK_LIST(c, d->show_protocol->channels)
      rt_show_add_table(d, c->table);
    return;
  }

  for (int i=1; i<NET_MAX; i++)
    if (config->def_tables[i] && config->def_tables[i]->table)
      rt_show_add_table(d, config->def_tables[i]->table);
}

static inline void
rt_show_prepare_tables(struct rt_show_data *d)
{
  struct rt_show_data_rtable *tab, *tabx;

  /* Add implicit tables if no table is specified */
  if (EMPTY_LIST(d->tables))
    rt_show_get_default_tables(d);

  WALK_LIST_DELSAFE(tab, tabx, d->tables)
  {
    /* Ensure there is defined export_channel for each table */
    if (d->export_mode)
    {
      if (!tab->export_channel && d->export_channel &&
	  (tab->table == d->export_channel->table))
	tab->export_channel = d->export_channel;

      if (!tab->export_channel && d->export_protocol)
	tab->export_channel = proto_find_channel_by_table(d->export_protocol, tab->table);

      if (!tab->export_channel)
      {
	if (d->tables_defined_by & RSD_TDB_NMN)
	  cf_error("No export channel for table %s", tab->table->name);

	rem_node(&(tab->n));
	continue;
      }
    }

    /* Ensure specified network is compatible with each table */
    if (d->addr && (tab->table->addr_type != d->addr->type))
    {
      if (d->tables_defined_by & RSD_TDB_NMN)
	cf_error("Incompatible type of prefix/ip for table %s", tab->table->name);

      rem_node(&(tab->n));
      continue;
    }
  }

  /* Ensure there is at least one table */
  if (EMPTY_LIST(d->tables))
    cf_error("No valid tables");
}

static void
rt_show_dummy_cont(struct cli *c UNUSED)
{
  /* Explicitly do nothing to prevent CLI from trying to parse another command. */
}

void
rt_show(struct rt_show_data *d)
{
  struct rt_show_data_rtable *tab;
  net *n;

  /* Filtered routes are neither exported nor have sensible ordering */
  if (d->filtered && (d->export_mode || d->primary_only))
    cf_error("Incompatible show route options");

  rt_show_prepare_tables(d);

  if (!d->addr || (d->addr_mode == RSD_ADDR_IN))
  {
    WALK_LIST(tab, d->tables)
      rt_lock_table(tab->table);

    /* There is at least one table */
    d->tab = HEAD(d->tables);
    this_cli->cleanup = rt_show_cleanup;
    this_cli->rover = d;
    this_cli->cont = rt_show_dummy_cont;
    rt_show_cont(d);
  }
  else
  {
    uint max = 64;
    rte **feed = mb_alloc(d->cli->pool, sizeof(rte *) * max);

    WALK_LIST(tab, d->tables)
    {
      d->tab = tab;
      d->kernel = rt_show_get_kernel(d);

      if (d->addr_mode == RSD_ADDR_FOR)
	n = net_route(tab->table, d->addr);
      else
	n = net_find(tab->table, d->addr);

      uint count = 0;
      for (struct rte_storage *e = n->routes; e; e = e->next)
	count++;

      if (!count)
	continue;

      if (count > max)
      {
	do max *= 2; while (count > max);
	feed = mb_realloc(feed, sizeof(rte *) * max);
      }

      uint i = 0;
      for (struct rte_storage *e = n->routes; e; e = e->next)
	feed[i++] = &e->rte;

      rt_show_net(d, n->n.addr, feed, count);
    }

    if (d->rt_counter)
      cli_msg(0, "");
    else
      cli_msg(8001, "Network not found");
  }
}

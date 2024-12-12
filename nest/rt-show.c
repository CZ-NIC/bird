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
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/cli.h"
#include "nest/iface.h"
#include "filter/filter.h"
#include "filter/data.h"
#include "sysdep/unix/krt.h"

static void rt_show_cont(struct cli *c);
static void rt_show_done(struct rt_show_data *d);

static void
rt_show_table(struct rt_show_data *d)
{
  struct cli *c = d->cli;

  /* No table blocks in 'show route count' */
  if (d->stats == 2)
    return;

  if (d->last_table) cli_printf(c, -1007, "");
  cli_printf(c, -1007, "Table %s:",
      d->tab->name);
  d->last_table = d->tab;
}

static void
rt_show_rte(struct cli *c, byte *ia, rte *e, struct rt_show_data *d, int primary)
{
  byte from[IPA_MAX_TEXT_LENGTH+8];
  byte tm[TM_DATETIME_BUFFER_SIZE], info[256];
  ea_list *a = e->attrs;
  int sync_error = d->tab->kernel ? krt_get_sync_error(d->tab->kernel, e) : 0;
  void (*get_route_info)(const rte *, byte *buf);
  const eattr *nhea = net_type_match(e->net, NB_DEST) ?
    ea_find(a, &ea_gen_nexthop) : NULL;
  struct nexthop_adata *nhad = nhea ? (struct nexthop_adata *) nhea->u.ptr : NULL;
  int dest = nhad ? (NEXTHOP_IS_REACHABLE(nhad) ? RTD_UNICAST : nhad->dest) : RTD_NONE;
  int flowspec_valid = net_is_flow(e->net) ? rt_get_flowspec_valid(e) : FLOWSPEC_UNKNOWN;

  tm_format_time(tm, c->tf ?: &d->tf_route, e->lastmod);
  ip_addr a_from = ea_get_ip(a, &ea_gen_from, IPA_NONE);
  if (ipa_nonzero(a_from) && (!nhad || !ipa_equal(a_from, nhad->nh.gw)))
    bsprintf(from, " from %I", a_from);
  else
    from[0] = 0;

  /* Need to normalize the attributes for dumping */
  if (d->verbose && !a->stored)
    a = ea_normalize(a, EALS_NONE);

  get_route_info = e->src->owner->class ? e->src->owner->class->get_route_info : NULL;
  if (get_route_info)
    get_route_info(e, info);
  else
    bsprintf(info, " (%d)", rt_get_preference(e));

  if (d->last_table != d->tab)
    rt_show_table(d);

  const eattr *heea;
  struct hostentry_adata *had = NULL;
  if (!net_is_flow(e->net) && (dest == RTD_NONE) && (heea = ea_find(a, &ea_gen_hostentry)))
    had = (struct hostentry_adata *) heea->u.ptr;

  cli_printf(c, -1007, "%-20s %s [%s %s%s]%s%s", ia,
      net_is_flow(e->net) ? flowspec_valid_name(flowspec_valid) : had ? "recursive" : rta_dest_name(dest),
      e->src->owner->name, tm, from, primary ? (sync_error ? " !" : " *") : "", info);

  if (d->verbose)
  {
    ea_show_list(c, a);
    cli_printf(c, -1008, "\tInternal route handling values: %luL %uG %uS id %u",
	e->src->private_id, e->src->global_id, e->stale_cycle, e->id);
  }
  else if (dest == RTD_UNICAST)
    ea_show_nexthop_list(c, nhad);
  else if (had)
  {
    char hetext[256];
    ea_show_hostentry(&had->ad, hetext, sizeof hetext);
    cli_printf(c, -1007, "\t%s", hetext);
  }
}

static void
rt_show_net(struct rt_show_data *d, const struct rt_export_feed *feed)
{
  struct cli *c = d->cli;
  byte ia[NET_MAX_TEXT_LENGTH+16+1];
  struct channel *ec = d->tab->export_channel;

  /* The Clang static analyzer complains that ec may be NULL.
   * It should be ensured to be not NULL by rt_show_prepare_tables() */
  ASSUME(!d->export_mode || ec);

  int first = 1;
  int first_show = 1;
  uint last_label = 0;
  int pass = 0;

  for (uint i = 0; i < feed->count_routes; i++)
    {
      rte *e = &feed->block[i];
      if (e->flags & REF_OBSOLETE)
	break;

      if (!d->tab->prefilter && (rte_is_filtered(e) != d->filtered))
	continue;

      d->rt_counter++;
      d->net_counter += first;
      first = 0;

      if (pass)
	continue;

      if (d->tab->prefilter)
	if (e->sender != d->tab->prefilter->in_req.hook)
	  continue;
	else
	  e->attrs = ea_strip_to(e->attrs, BIT32_ALL(EALS_PREIMPORT));

      /* Export channel is down, do not try to export routes to it */
      if (ec && (rt_export_get_state(&ec->out_req) == TES_DOWN))
	goto skip;

      if (d->export_mode == RSEM_EXPORTED)
        {
	  if (!bmap_test(&ec->export_accepted_map, e->id))
	    goto skip;

	  // if (ec->ra_mode != RA_ANY)
	  //   pass = 1;
        }
      else if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_MERGED))
	{
	  /* Special case for merged export */
	  pass = 1;
	  rte *em = rt_export_merged(ec, feed, tmp_linpool, 1);

	  if (em)
	    e = em;
	  else
	    goto skip;
	}
      else if (d->export_mode)
	{
	  struct proto *ep = ec->proto;
	  int ic = ep->preexport ? ep->preexport(ec, e) : 0;

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
		(f_run(ec->out_filter, e, FF_SILENT) <= F_ACCEPT);

	      if (do_export != (d->export_mode == RSEM_EXPORT))
		goto skip;

	      if ((d->export_mode == RSEM_EXPORT) && (ec->ra_mode == RA_ACCEPTED))
		pass = 1;
	    }
	}

      if (d->show_protocol && (&d->show_protocol->sources != e->src->owner))
	goto skip;

      if (f_run(d->filter, e, 0) > F_ACCEPT)
	goto skip;

      if (d->stats < 2)
      {
	uint label = ea_get_int(e->attrs, &ea_gen_mpls_label, ~0U);

	if (first_show || (last_label != label))
	{
	  if (!~label)
	    net_format(feed->ni->addr, ia, sizeof(ia));
	  else
	    bsnprintf(ia, sizeof(ia), "%N mpls %d", feed->ni->addr, label);
	}
	else
	  ia[0] = 0;

	rt_show_rte(c, ia, e, d, !d->tab->prefilter && !i);
	first_show = 0;
	last_label = label;
      }

      d->show_counter++;

    skip:
      if (d->primary_only)
	break;
#undef e
    }

  if ((d->show_counter - d->show_counter_last_flush) > 64)
  {
    d->show_counter_last_flush = d->show_counter;
    cli_write_trigger(d->cli);
  }
}

static bool
rt_show_cleanup(struct cli *c)
{
  struct rt_show_data *d = c->rover;
  struct rt_show_data_rtable *tab, *tabx;
  c->cleanup = NULL;

  /* Cancel the feeds */
  WALK_LIST_DELSAFE(tab, tabx, d->tables)
  {
    if (rt_export_feed_active(&tab->req))
      rt_feeder_unsubscribe(&tab->req);
  }

  /* Unreference the config */
  OBSREF_CLEAR(d->running_on_config);

  /* Everything cleaned up */
  return true;
}

static void
rt_show_done(struct rt_show_data *d)
{
  /* Force the cleanup */
  rt_show_cleanup(d->cli);

  /* Write pending messages */
  cli_write_trigger(d->cli);

  /* No more action */
  d->cli->cleanup = NULL;
  d->cli->cont = NULL;
  d->cli->rover = NULL;
}

static void
rt_show_cont(struct cli *c)
{
  struct rt_show_data *d = c->rover;

  if (OBSREF_GET(d->running_on_config) != OBSREF_GET(config))
  {
    cli_printf(c, 8004, "Stopped due to reconfiguration");
    return rt_show_done(d);
  }

  d->table_counter++;

  d->show_counter_last = d->show_counter;
  d->rt_counter_last   = d->rt_counter;
  d->net_counter_last  = d->net_counter;

  if (d->tables_defined_by & RSD_TDB_SET)
    rt_show_table(d);

  RT_FEED_WALK(&d->tab->req, f)
    if (f->count_routes)
      rt_show_net(d, f);

  if (rt_export_feed_active(&d->tab->req))
    rt_feeder_unsubscribe(&d->tab->req);
  else
  {
    cli_printf(c, 8004, "Table is shutting down");
    return rt_show_done(d);
  }

  if (d->stats)
  {
    if (d->last_table != d->tab)
      rt_show_table(d);

    cli_printf(d->cli, -1007, "%d of %d routes for %d networks in table %s",
	d->show_counter - d->show_counter_last, d->rt_counter - d->rt_counter_last,
	d->net_counter - d->net_counter_last, d->tab->name);
  }

  d->tab = NODE_NEXT(d->tab);

  if (NODE_VALID(d->tab))
    /* Gonna be called later by this_cli->cont() */
    return;

  /* Printout total stats */
  if (d->stats && (d->table_counter > 1))
  {
    if (d->last_table) cli_printf(d->cli, -1007, "");
    cli_printf(d->cli, 14, "Total: %d of %d routes for %d networks in %d tables",
	d->show_counter, d->rt_counter, d->net_counter, d->table_counter);
  }
  else if (!d->rt_counter && ((d->addr_mode == TE_ADDR_EQUAL) || (d->addr_mode == TE_ADDR_FOR)))
    cli_printf(d->cli, 8001, "Network not found");
  else
    cli_printf(d->cli, 0, "");

  /* No more route showing */
  rt_show_done(d);
}

struct rt_show_data_rtable *
rt_show_add_exporter(struct rt_show_data *d, struct rt_exporter *e)
{
  struct rt_show_data_rtable *tab = cfg_allocz(sizeof(struct rt_show_data_rtable));
  tab->name = e->name;
  tab->exporter = e;
  add_tail(&(d->tables), &(tab->n));
  return tab;
}

struct rt_show_data_rtable *
rt_show_add_table(struct rt_show_data *d, rtable *t)
{
  struct rt_show_data_rtable *tab = rt_show_add_exporter(d, &t->export_all);
  tab->name = t->name;

  struct proto_config *krt = t->config->krt_attached;
  if (krt)
    tab->kernel = (struct krt_proto *) krt->proto;

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
    int seen_only_export_down = 1;
    int tab_found = 0;
    WALK_LIST(c, d->export_protocol->channels)
    {
      tab_found = 1;
      if (rt_export_get_state(&c->out_req) == TES_DOWN)
        continue;

      seen_only_export_down = 0;
      tab = rt_show_add_table(d, c->table);
      tab->export_channel = c;
    }

    if (tab_found && seen_only_export_down)
      cf_error("Requested 'show route export' to protocols which aren't accepting exports at all.");

    return;
  }

  if (d->show_protocol)
  {
    WALK_LIST(c, d->show_protocol->channels)
      rt_show_add_table(d, c->table);
    return;
  }

  struct symbol **def_tables = d->cli->main_config->def_tables;
  for (int i=1; i<NET_MAX; i++)
    if (def_tables[i] && def_tables[i]->table && def_tables[i]->table->table)
      rt_show_add_table(d, def_tables[i]->table->table);
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
    struct rt_exporter *ex = tab->exporter;

    /* Ensure there is defined export_channel for each table */
    if (d->export_mode)
    {
      if (!tab->export_channel && d->export_channel &&
	  (ex == &d->export_channel->table->export_all))
	tab->export_channel = d->export_channel;

      if (!tab->export_channel && d->export_protocol)
	tab->export_channel = proto_find_channel_by_table(d->export_protocol, SKIP_BACK(rtable, export_all, ex));

      if (!tab->export_channel)
      {
	if (d->tables_defined_by & RSD_TDB_NMN)
	  cf_error("No export channel for table %s", tab->name);

	rem_node(&(tab->n));
	continue;
      }
    }

    /* Ensure specified network is compatible with each table */
    if (d->addr && (ex->net_type != d->addr->type))
    {
      if (d->tables_defined_by & RSD_TDB_NMN)
	cf_error("Incompatible type of prefix/ip for table %s", tab->name);

      rem_node(&(tab->n));
      continue;
    }

    /* Open the export request */
    tab->req = (struct rt_export_feeder) {
      .name = "cli.feeder",
      .prefilter = {
	.addr = d->addr,
	.mode = d->addr_mode,
      },
      .trace_routes = d->cli->main_config->show_route_debug,
    };

    rt_feeder_subscribe(ex, &tab->req);
  }

  /* Ensure there is at least one table */
  if (EMPTY_LIST(d->tables))
    cf_error("No valid tables");
}

void
rt_show(struct rt_show_data *d)
{
  /* Filtered routes are neither exported nor have sensible ordering */
  if (d->filtered && (d->export_mode || d->primary_only))
    cf_error("Incompatible show route options");

  rt_show_prepare_tables(d);

  if (EMPTY_LIST(d->tables))
    cf_error("No suitable tables found");

  d->tab = HEAD(d->tables);

  /* OBSREF_SET should not be called sooner than the last cf_error() may occur.
     If cf_error() called after OBSREF_SET, the crreated obstacle may not be removed at all.
     (cf_error() contains long jump.) */
  OBSREF_SET(d->running_on_config, this_cli->main_config);

  this_cli->cleanup = rt_show_cleanup;
  this_cli->rover = d;
  this_cli->cont = rt_show_cont;

  cli_write_trigger(this_cli);
}

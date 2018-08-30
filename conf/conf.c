/*
 *	BIRD Internet Routing Daemon -- Configuration File Handling
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Configuration manager
 *
 * Configuration of BIRD is complex, yet straightforward. There are three
 * modules taking care of the configuration: config manager (which takes care
 * of storage of the config information and controls switching between configs),
 * lexical analyzer and parser.
 *
 * The configuration manager stores each config as a &config structure
 * accompanied by a linear pool from which all information associated
 * with the config and pointed to by the &config structure is allocated.
 *
 * There can exist up to four different configurations at one time: an active
 * one (pointed to by @config), configuration we are just switching from
 * (@old_config), one queued for the next reconfiguration (@future_config; if
 * there is one and the user wants to reconfigure once again, we just free the
 * previous queued config and replace it with the new one) and finally a config
 * being parsed (@new_config). The stored @old_config is also used for undo
 * reconfiguration, which works in a similar way. Reconfiguration could also
 * have timeout (using @config_timer) and undo is automatically called if the
 * new configuration is not confirmed later. The new config (@new_config) and
 * associated linear pool (@cfg_mem) is non-NULL only during parsing.
 *
 * Loading of new configuration is very simple: just call config_alloc() to get
 * a new &config structure, then use config_parse() to parse a configuration
 * file and fill all fields of the structure and finally ask the config manager
 * to switch to the new config by calling config_commit().
 *
 * CLI commands are parsed in a very similar way -- there is also a stripped-down
 * &config structure associated with them and they are lex-ed and parsed by the
 * same functions, only a special fake token is prepended before the command
 * text to make the parser recognize only the rules corresponding to CLI commands.
 */

#include <setjmp.h>
#include <stdarg.h>

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "nest/iface.h"
#include "lib/resource.h"
#include "lib/string.h"
#include "lib/event.h"
#include "lib/timer.h"
#include "conf/conf.h"
#include "conf/parser.h"
#include "filter/filter.h"


struct config *config, *new_config;

static struct config *old_config;	/* Old configuration */
static struct config *future_config;	/* New config held here if recon requested during recon */
static int old_cftype;			/* Type of transition old_config -> config (RECONFIG_SOFT/HARD) */
static int future_cftype;		/* Type of scheduled transition, may also be RECONFIG_UNDO */
/* Note that when future_cftype is RECONFIG_UNDO, then future_config is NULL,
   therefore proper check for future scheduled config checks future_cftype */

static event *config_event;		/* Event for finalizing reconfiguration */
static timer *config_timer;		/* Timer for scheduled configuration rollback */

/* These are public just for cmd_show_status(), should not be accessed elsewhere */
int shutting_down;			/* Shutdown requested, do not accept new config changes */
int configuring;			/* Reconfiguration is running */
int undo_available;			/* Undo was not requested from last reconfiguration */
/* Note that both shutting_down and undo_available are related to requests, not processing */

/**
 * config_alloc - allocate a new configuration
 * @name: name of the config
 *
 * This function creates new &config structure, attaches a resource
 * pool and a linear memory pool to it and makes it available for
 * further use. Returns a pointer to the structure.
 */
static struct config *
config_alloc(struct pool *pp, struct linpool *lp)
{
  pool *p = rp_new(pp ?: &root_pool, "Config");
  linpool *l = lp ?: lp_new_default(p);
  struct config *c = lp_allocz(l, sizeof(struct config));

  init_list(&c->tests);
  c->mrtdump_file = -1; /* Hack, this should be sysdep-specific */
  c->pool = p;
  c->mem = l;
  c->load_time = current_time();
  c->tf_route = c->tf_proto = TM_ISO_SHORT_MS;
  c->tf_base = c->tf_log = TM_ISO_LONG_MS;
  c->gr_wait = DEFAULT_GR_WAIT;

  return c;
}

static void config_event_resume(void *arg)
{
  struct cf_context *ctx = arg;
  coro_resume(ctx->coro);
}

static void config_event_cleanup(void *arg)
{
  struct cf_context *ctx = arg;
  struct conf_order *order = ctx->order;

  rfree(ctx->coro);

  cf_free_context(ctx);
  order->ctx = NULL;

  if (order->flags & CO_CLI)
    {
      config_free(order->new_config);
      order->new_config = NULL;
    }

  return order->cf_done(order);
}

static void
config_parse_coro(void *arg)
{
  struct cf_context *ctx = arg;
  struct conf_order *order = ctx->order;
  DBG("Config parse coroutine started\n");

  if (setjmp(ctx->jmpbuf))
    {
      if (order->cf_outclude)
	while (! order->cf_outclude(order))
	  ;

      config_free(ctx->new_config);
      order->new_config = NULL;

      goto cleanup;
    }

  cfx_parse(ctx, ctx->yyscanner);

  if (EMPTY_LIST((ctx->new_config)->protos))
    cf_error(ctx, "No protocol is specified in the config file");

cleanup:
  ev_schedule(ctx->ev_cleanup);
  coro_suspend();
  bug("Resumed config when done.");
  return;
}

void
config_parse(struct conf_order *order)
{
  DBG("Parsing configuration named `%s'\n", order->state->name);

  if (!order->new_config)
    order->new_config = config_alloc(order->pool, order->lp);

  pool *p = order->new_config->pool;

  struct cf_context *ctx = cf_new_context(order);

  /* CLI does no preconfig */
  if (!(order->flags & CO_CLI))
    {
      sysdep_preconfig(ctx);
      protos_preconfig(ctx->new_config);
      rt_preconfig(ctx);
    }

  if (!(order->flags & CO_SYNC))
    {
      ctx->ev_resume = ev_new(p);
      ctx->ev_resume->hook = config_event_resume;
      ctx->ev_resume->data = ctx;
    }

  ctx->ev_cleanup = ev_new(p);
  ctx->ev_cleanup->hook = config_event_cleanup;
  ctx->ev_cleanup->data = ctx;

  if (order->flags & CO_FILENAME)
    if (order->cf_include)
      order->cf_include(order, order->buf, order->len);
    else
      bug("Include handler must be set to config from file");
  else
    cf_scan_bytes(ctx, order->buf, order->len);

  ctx->coro = coro_new(p, config_parse_coro, ctx);
  coro_resume(ctx->coro);
}

void config_yield(struct cf_context *ctx)
{
  DBG("Conf: Yield\n");
  ev_schedule(ctx->ev_resume);
  DBG("Conf: Yield resumed\n");
}

/**
 * config_free - free a configuration
 * @c: configuration to be freed
 *
 * This function takes a &config structure and frees all resources
 * associated with it.
 */
void
config_free(struct config *c)
{
  if (c)
    rfree(c->pool);
}

void
config_add_obstacle(struct config *c)
{
  DBG("+++ adding obstacle %d\n", c->obstacle_count);
  c->obstacle_count++;
}

void
config_del_obstacle(struct config *c)
{
  DBG("+++ deleting obstacle %d\n", c->obstacle_count);
  c->obstacle_count--;
  if (!c->obstacle_count)
    ev_schedule(config_event);
}

static int
global_commit(struct config *new, struct config *old)
{
  if (!old)
    return 0;

  if (!new->router_id)
    {
      new->router_id = old->router_id;

      if (new->router_id_from)
	{
	  u32 id = if_choose_router_id(new->router_id_from, old->router_id);
	  if (!id)
	    log(L_WARN "Cannot determine router ID, using old one");
	  else
	    new->router_id = id;
	}
    }

  return 0;
}

static int
config_do_commit(struct config *c, int type)
{
  if (type == RECONFIG_UNDO)
    {
      c = old_config;
      type = old_cftype;
    }
  else
    config_free(old_config);

  old_config = config;
  old_cftype = type;
  config = c;

  configuring = 1;
  if (old_config && !config->shutdown)
    log(L_INFO "Reconfiguring");

  if (old_config)
    old_config->obstacle_count++;

  DBG("sysdep_commit\n");
  int force_restart = sysdep_commit(c, old_config);
  DBG("global_commit\n");
  force_restart |= global_commit(c, old_config);
  DBG("rt_commit\n");
  rt_commit(c, old_config);
  DBG("protos_commit\n");
  protos_commit(c, old_config, force_restart, type);

  int obs = 0;
  if (old_config)
    obs = --old_config->obstacle_count;

  DBG("do_commit finished with %d obstacles remaining\n", obs);
  return !obs;
}

static void
config_done(void *unused UNUSED)
{
  if (config->shutdown)
    sysdep_shutdown_done();

  configuring = 0;
  if (old_config)
    log(L_INFO "Reconfigured");

  if (future_cftype)
    {
      int type = future_cftype;
      struct config *conf = future_config;
      future_cftype = RECONFIG_NONE;
      future_config = NULL;

      log(L_INFO "Reconfiguring to queued configuration");
      if (config_do_commit(conf, type))
	config_done(NULL);
    }
}

/**
 * config_commit - commit a configuration
 * @c: new configuration
 * @type: type of reconfiguration (RECONFIG_SOFT or RECONFIG_HARD)
 * @timeout: timeout for undo (in seconds; or 0 for no timeout)
 *
 * When a configuration is parsed and prepared for use, the
 * config_commit() function starts the process of reconfiguration.
 * It checks whether there is already a reconfiguration in progress
 * in which case it just queues the new config for later processing.
 * Else it notifies all modules about the new configuration by calling
 * their commit() functions which can either accept it immediately
 * or call config_add_obstacle() to report that they need some time
 * to complete the reconfiguration. After all such obstacles are removed
 * using config_del_obstacle(), the old configuration is freed and
 * everything runs according to the new one.
 *
 * When @timeout is nonzero, the undo timer is activated with given
 * timeout. The timer is deactivated when config_commit(),
 * config_confirm() or config_undo() is called.
 *
 * Result: %CONF_DONE if the configuration has been accepted immediately,
 * %CONF_PROGRESS if it will take some time to switch to it, %CONF_QUEUED
 * if it's been queued due to another reconfiguration being in progress now
 * or %CONF_SHUTDOWN if BIRD is in shutdown mode and no new configurations
 * are accepted.
 */
int
config_commit(struct config *c, int type, uint timeout)
{
  ASSERT(type != RECONFIG_CHECK);
  if (shutting_down)
    {
      config_free(c);
      return CONF_SHUTDOWN;
    }

  undo_available = 1;
  if (timeout)
    tm_start(config_timer, timeout S);
  else
    tm_stop(config_timer);

  if (configuring)
    {
      if (future_cftype)
	{
	  log(L_INFO "Queueing new configuration, ignoring the one already queued");
	  config_free(future_config);
	}
      else
	log(L_INFO "Queueing new configuration");

      future_cftype = type;
      future_config = c;
      return CONF_QUEUED;
    }

  if (config_do_commit(c, type))
    {
      config_done(NULL);
      return CONF_DONE;
    }
  return CONF_PROGRESS;
}

/**
 * config_confirm - confirm a commited configuration
 *
 * When the undo timer is activated by config_commit() with nonzero timeout,
 * this function can be used to deactivate it and therefore confirm
 * the current configuration.
 *
 * Result: %CONF_CONFIRM when the current configuration is confirmed,
 * %CONF_NONE when there is nothing to confirm (i.e. undo timer is not active).
 */
int
config_confirm(void)
{
  if (config_timer->expires == 0)
    return CONF_NOTHING;

  tm_stop(config_timer);

  return CONF_CONFIRM;
}

/**
 * config_undo - undo a configuration
 *
 * Function config_undo() can be used to change the current
 * configuration back to stored %old_config. If no reconfiguration is
 * running, this stored configuration is commited in the same way as a
 * new configuration in config_commit(). If there is already a
 * reconfiguration in progress and no next reconfiguration is
 * scheduled, then the undo is scheduled for later processing as
 * usual, but if another reconfiguration is already scheduled, then
 * such reconfiguration is removed instead (i.e. undo is applied on
 * the last commit that scheduled it).
 *
 * Result: %CONF_DONE if the configuration has been accepted immediately,
 * %CONF_PROGRESS if it will take some time to switch to it, %CONF_QUEUED
 * if it's been queued due to another reconfiguration being in progress now,
 * %CONF_UNQUEUED if a scheduled reconfiguration is removed, %CONF_NOTHING
 * if there is no relevant configuration to undo (the previous config request
 * was config_undo() too)  or %CONF_SHUTDOWN if BIRD is in shutdown mode and
 * no new configuration changes  are accepted.
 */
int
config_undo(void)
{
  if (shutting_down)
    return CONF_SHUTDOWN;

  if (!undo_available || !old_config)
    return CONF_NOTHING;

  undo_available = 0;
  tm_stop(config_timer);

  if (configuring)
    {
      if (future_cftype)
	{
	  config_free(future_config);
	  future_config = NULL;

	  log(L_INFO "Removing queued configuration");
	  future_cftype = RECONFIG_NONE;
	  return CONF_UNQUEUED;
	}
      else
	{
	  log(L_INFO "Queueing undo configuration");
	  future_cftype = RECONFIG_UNDO;
	  return CONF_QUEUED;
	}
    }

  if (config_do_commit(NULL, RECONFIG_UNDO))
    {
      config_done(NULL);
      return CONF_DONE;
    }
  return CONF_PROGRESS;
}

extern void cmd_reconfig_undo_notify(void);

static void
config_timeout(timer *t UNUSED)
{
  log(L_INFO "Config timeout expired, starting undo");
  cmd_reconfig_undo_notify();

  int r = config_undo();
  if (r < 0)
    log(L_ERR "Undo request failed");
}

void
config_init(void)
{
  config_event = ev_new(&root_pool);
  config_event->hook = config_done;

  config_timer = tm_new(&root_pool);
  config_timer->hook = config_timeout;

  cf_init_kh();
}

/**
 * order_shutdown - order BIRD shutdown
 *
 * This function initiates shutdown of BIRD. It's accomplished by asking
 * for switching to an empty configuration.
 */
void
order_shutdown(void)
{
  struct config *c;

  if (shutting_down)
    return;

  log(L_INFO "Shutting down");
  c = lp_alloc(config->mem, sizeof(struct config));
  memcpy(c, config, sizeof(struct config));
  init_list(&c->protos);
  init_list(&c->tables);
  c->shutdown = 1;

  config_commit(c, RECONFIG_HARD, 0);
  shutting_down = 1;
}

/**
 * cf_error - report a configuration error
 * @msg: printf-like format string
 *
 * cf_error() can be called during execution of config_parse(), that is
 * from the parser, a preconfig hook or a postconfig hook, to report an
 * error in the configuration.
 */
void
cf_error(struct cf_context *ctx, const char *msg, ...)
{
  va_list args;

  va_start(args, msg);
  ctx->order->cf_error(ctx->order, msg, args);
  va_end(args);

  longjmp(ctx->jmpbuf, 1);
}

#if 0
  if (bvsnprintf(ctx->order->err.msg, CONF_ERROR_MSG_LEN, msg, args) < 0)
    strcpy(ctx->order->err.msg, "<bug: error message too long>");

  ctx->order->err.lino = ctx->order->state->lino;

  uint fnlen = strlen(ctx->order->state->name);
  if (fnlen >= CONF_FILENAME_LEN)
    {
      uint l = (CONF_FILENAME_LEN - 6) / 2;
      uint r = CONF_FILENAME_LEN - 6 - l;

      memcpy(ctx->order->err.file_name, ctx->order->state->name, l);
      memcpy(ctx->order->err.file_name + l, " ... ", 5);
      strncpy(ctx->order->err.file_name + l + 5, ctx->order->state->name + fnlen - r, r);
    }
  else
    memcpy(ctx->order->err.file_name, ctx->order->state->name, fnlen + 1);

}
#endif

void *cf_alloc(struct cf_context *ctx, unsigned size) { return cfg_alloc(size); }
void *cf_allocu(struct cf_context *ctx, unsigned size) { return cfg_allocu(size); }
void *cf_allocz(struct cf_context *ctx, unsigned size) { return cfg_allocz(size); }

/**
 * cfg_strdup - copy a string to config memory
 * @c: string to copy
 *
 * cfg_strdup() creates a new copy of the string in the memory
 * pool associated with the configuration being currently parsed.
 * It's often used when a string literal occurs in the configuration
 * and we want to preserve it for further use.
 */
char *
cf_strdup(struct cf_context *ctx, const char *c)
{
  int l = strlen(c) + 1;
  char *z = cfg_allocu(l);
  memcpy(z, c, l);
  return z;
}


void
cf_copy_list(struct cf_context *ctx, list *dest, list *src, unsigned node_size)
{
  node *dn, *sn;

  init_list(dest);
  WALK_LIST(sn, *src)
  {
    dn = cfg_alloc(node_size);
    memcpy(dn, sn, node_size);
    add_tail(dest, dn);
  }
}

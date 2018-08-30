/*
 *	BIRD Internet Routing Daemon -- Configuration File Handling
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_CONF_H_
#define _BIRD_CONF_H_

#include "sysdep/config.h"
#include "nest/cli.h"
#include "lib/ip.h"
#include "lib/hash.h"
#include "lib/resource.h"
#include "lib/timer.h"


/* Configuration structure */

struct config {
  pool *pool;				/* Pool the configuration is stored in */
  linpool *mem;				/* Linear pool containing configuration data */
  list protos;				/* Configured protocol instances (struct proto_config) */
  list tables;				/* Configured routing tables (struct rtable_config) */
  list logfiles;			/* Configured log files (sysdep) */
  list tests;				/* Configured unit tests (f_bt_test_suite) */

  int mrtdump_file;			/* Configured MRTDump file (sysdep, fd in unix) */
  char *syslog_name;			/* Name used for syslog (NULL -> no syslog) */
  struct rtable_config *def_tables[NET_MAX]; /* Default routing tables for each network */
  struct iface_patt *router_id_from;	/* Configured list of router ID iface patterns */

  u32 router_id;			/* Our Router ID */
  unsigned proto_default_debug;		/* Default protocol debug mask */
  unsigned proto_default_mrtdump;	/* Default protocol mrtdump mask */
  struct timeformat tf_route;		/* Time format for 'show route' */
  struct timeformat tf_proto;		/* Time format for 'show protocol' */
  struct timeformat tf_log;		/* Time format for the logfile */
  struct timeformat tf_base;		/* Time format for other purposes */
  u32 gr_wait;				/* Graceful restart wait timeout (sec) */

  int cli_debug;			/* Tracing of CLI connections and commands */
  int latency_debug;			/* I/O loop tracks duration of each event */
  u32 latency_limit;			/* Events with longer duration are logged (us) */
  u32 watchdog_warning;			/* I/O loop watchdog limit for warning (us) */
  u32 watchdog_timeout;			/* Watchdog timeout (in seconds, 0 = disabled) */
  HASH(struct symbol) sym_hash;		/* Lexer: symbol hash table */
  struct config *fallback;		/* Link to regular config for CLI parsing */
  int obstacle_count;			/* Number of items blocking freeing of this config */
  int shutdown;				/* This is a pseudo-config for daemon shutdown */
  btime load_time;			/* When we've got this configuration */
};

struct conf_state {
  void *buffer;				/* Internal lexer state */
  const char *name;			/* Current file name */
  uint lino;				/* Current line */
};

enum conf_order_flag {
  CO_CLI = 1,				/* Parse CLI, not regular config */
  CO_SYNC = 2,				/* Run parser synchronously */
  CO_FILENAME = 4,			/* Use the order buffer as filename */
} PACKED;

/* This struct is meant to be inherited and customized by caller */
struct conf_order {
  resource r;
  struct config *new_config;		/* Outputs the allocated config here */
  struct cf_context *ctx;		/* Internal config context, do not set */
  struct conf_state *state;		/* Internal config state, do not set */

  struct pool *pool;			/* If set, use this resource pool */
  struct linpool *lp;			/* If set, use this linpool */
  const char *buf;			/* Buffer to parse or filename */
  uint len;				/* Buffer length */
  enum conf_order_flag flags;

  int (*cf_read_hook)(struct conf_order *order, byte *buf, uint max);
  void (*cf_include)(struct conf_order *order, const char *name, uint len);
  int (*cf_outclude)(struct conf_order *order);
  void (*cf_error)(struct conf_order *order, const char *msg, va_list args);
  void (*cf_done)(struct conf_order *order);
};

/* Please don't use these variables in protocols. Use proto_config->global instead. */
extern struct config *config;		/* Currently active configuration */

/**
 * Parse configuration
 *
 * Arguments:
 * @order provides callbacks to read config files
 *
 * This function queues 
 * Return value:
 * 1 on success; order->new_config is then set to the parsed config
 * 0 on fail; order->new_config is undefined
 **/
void config_parse(struct conf_order *order);

/** Callback for returning error from parser hooks */
void cf_error(struct cf_context *, const char *msg, ...) NORET;

void config_free(struct config *);
int config_commit(struct config *, int type, uint timeout);
int config_confirm(void);
int config_undo(void);
void config_init(void);
void config_add_obstacle(struct config *);
void config_del_obstacle(struct config *);
void order_shutdown(void);

#define RECONFIG_NONE	0
#define RECONFIG_HARD	1
#define RECONFIG_SOFT	2
#define RECONFIG_UNDO	3
#define RECONFIG_CHECK	4

#define CONF_DONE	0
#define CONF_PROGRESS	1
#define CONF_QUEUED	2
#define CONF_UNQUEUED	3
#define CONF_CONFIRM	4
#define CONF_SHUTDOWN	-1
#define CONF_NOTHING	-2

/* Pools */

void *cf_alloc(struct cf_context *ctx, unsigned size);
void *cf_allocu(struct cf_context *ctx, unsigned size);
void *cf_allocz(struct cf_context *ctx, unsigned size);
void cf_copy_list(struct cf_context *ctx, list *dest, list *src, unsigned node_size);
char *cf_strdup(struct cf_context *ctx, const char *c);

/* Lexer */

struct symbol {
  struct symbol *next;
  struct sym_scope *scope;
  int class;
  int aux;
  void *aux2;
  void *def;
  char name[1];
};

struct sym_scope {
  struct sym_scope *next;		/* Next on scope stack */
  struct symbol *name;			/* Name of this scope */
  int active;				/* Currently entered */
};

#define SYM_MAX_LEN 64

/* Remember to update cf_symbol_class_name() */
#define SYM_VOID 0
#define SYM_PROTO 1
#define SYM_TEMPLATE 2
#define SYM_FUNCTION 3
#define SYM_FILTER 4
#define SYM_TABLE 5

#define SYM_VARIABLE 0x100	/* 0x100-0x1ff are variable types */
#define SYM_CONSTANT 0x200	/* 0x200-0x2ff are variable types */

#define SYM_TYPE(s) (((struct f_val *) (s)->def)->type)
#define SYM_VAL(s) (((struct f_val *) (s)->def)->val)

struct symbol *cf_find_symbol(struct config *cfg, byte *c);

char *cf_symbol_class_name(struct symbol *sym);

static inline int cf_symbol_is_constant(struct symbol *sym)
{ return (sym->class & 0xff00) == SYM_CONSTANT; }

/* Sysdep hooks */

void sysdep_preconfig(struct cf_context *ctx);
int sysdep_commit(struct config *, struct config *);
void sysdep_shutdown_done(void);

#endif

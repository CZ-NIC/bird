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
  list mpls_domains;			/* Configured MPLS domains (struct mpls_domain_config) */
  list logfiles;			/* Configured log files (sysdep) */
  list tests;				/* Configured unit tests (f_bt_test_suite) */
  list symbols;				/* Configured symbols in config order */

  int mrtdump_file;			/* Configured MRTDump file (sysdep, fd in unix) */
  const char *syslog_name;		/* Name used for syslog (NULL -> no syslog) */
  struct rtable_config *def_tables[NET_MAX]; /* Default routing tables for each network */
  struct iface_patt *router_id_from;	/* Configured list of router ID iface patterns */

  u32 router_id;			/* Our Router ID */
  u32 proto_default_debug;		/* Default protocol debug mask */
  u32 proto_default_mrtdump;		/* Default protocol mrtdump mask */
  u32 channel_default_debug;		/* Default channel debug mask */
  struct timeformat tf_route;		/* Time format for 'show route' */
  struct timeformat tf_proto;		/* Time format for 'show protocol' */
  struct timeformat tf_log;		/* Time format for the logfile */
  struct timeformat tf_base;		/* Time format for other purposes */
  u32 gr_wait;				/* Graceful restart wait timeout (sec) */
  const char *hostname;			/* Hostname */

  int cli_debug;			/* Tracing of CLI connections and commands */
  int latency_debug;			/* I/O loop tracks duration of each event */
  u32 latency_limit;			/* Events with longer duration are logged (us) */
  u32 watchdog_warning;			/* I/O loop watchdog limit for warning (us) */
  u32 watchdog_timeout;			/* Watchdog timeout (in seconds, 0 = disabled) */
  char *err_msg;			/* Parser error message */
  int err_lino;				/* Line containing error */
  int err_chno;				/* Character where the parser stopped */
  char *err_file_name;			/* File name containing error */
  char *file_name;			/* Name of main configuration file */
  int file_fd;				/* File descriptor of main configuration file */

  struct sym_scope *root_scope;		/* Scope for root symbols */
  struct sym_scope *current_scope;	/* Current scope where we are actually in while parsing */
  int obstacle_count;			/* Number of items blocking freeing of this config */
  int shutdown;				/* This is a pseudo-config for daemon shutdown */
  int gr_down;				/* This is a pseudo-config for graceful restart */
  btime load_time;			/* When we've got this configuration */
};

/* Please don't use these variables in protocols. Use proto_config->global instead. */
extern struct config *config;		/* Currently active configuration */
extern struct config *new_config;	/* Configuration being parsed */

struct config *config_alloc(const char *name);
int config_parse(struct config *);
int cli_parse(struct config *);
void config_free(struct config *);
void config_free_old(void);
int config_commit(struct config *, int type, uint timeout);
int config_confirm(void);
int config_undo(void);
int config_status(void);
btime config_timer_status(void);
void config_init(void);
void cf_error(const char *msg, ...) NORET;
#define cf_warn(msg, args...)  log(L_WARN "%s:%d:%d: " msg, ifs->file_name, ifs->lino, ifs->chno - ifs->toklen + 1, ##args)
void config_add_obstacle(struct config *);
void config_del_obstacle(struct config *);
void order_shutdown(int gr);

#define RECONFIG_NONE	0
#define RECONFIG_HARD	1
#define RECONFIG_SOFT	2
#define RECONFIG_UNDO	3

#define CONF_DONE	0
#define CONF_PROGRESS	1
#define CONF_QUEUED	2
#define CONF_UNQUEUED	3
#define CONF_CONFIRM	4
#define CONF_SHUTDOWN	-1
#define CONF_NOTHING	-2


/* Pools */
extern pool *config_pool;
extern linpool *cfg_mem;

#define cfg_alloc(size) lp_alloc(cfg_mem, size)
#define cfg_allocu(size) lp_allocu(cfg_mem, size)
#define cfg_allocz(size) lp_allocz(cfg_mem, size)
char *cfg_strdup(const char *c);
void cfg_copy_list(list *dest, list *src, unsigned node_size);

/* Lexer */

extern int (*cf_read_hook)(byte *buf, uint max, int fd);

struct keyword {
  byte *name;
  int value;
};

struct symbol {
  node n;				/* In list of symbols in config */
  struct symbol *next;
  struct sym_scope *scope;
  int class;				/* SYM_* */
  uint flags;				/* SYM_FLAG_* */

  union {
    struct proto_config *proto;		/* For SYM_PROTO and SYM_TEMPLATE */
    const struct f_line *function;	/* For SYM_FUNCTION */
    const struct filter *filter;	/* For SYM_FILTER */
    struct rtable_config *table;	/* For SYM_TABLE */
    struct f_dynamic_attr *attribute;	/* For SYM_ATTRIBUTE */
    struct mpls_domain_config *mpls_domain;	/* For SYM_MPLS_DOMAIN */
    struct mpls_range_config *mpls_range;	/* For SYM_MPLS_RANGE */
    struct f_val *val;			/* For SYM_CONSTANT */
    uint offset;			/* For SYM_VARIABLE */
    const struct keyword *keyword;	/* For SYM_KEYWORD */
    const struct f_method *method;	/* For SYM_METHOD */
  };

  char name[0];
};

struct sym_scope {
  struct sym_scope *next;		/* Next on scope stack */
  struct symbol *name;			/* Name of this scope */

  HASH(struct symbol) hash;		/* Local symbol hash */

  uint slots;				/* Variable slots */
  byte soft_scopes;			/* Number of soft scopes above */
  byte active:1;			/* Currently entered */
  byte block:1;				/* No independent stack frame */
  byte readonly:1;			/* Do not add new symbols */
};

extern struct sym_scope *global_root_scope;
extern pool *global_root_scope_pool;
extern linpool *global_root_scope_linpool;


#define SYM_MAX_LEN 64

/* Remember to update cf_symbol_class_name() */
#define SYM_VOID 0
#define SYM_PROTO 1
#define SYM_TEMPLATE 2
#define SYM_FUNCTION 3
#define SYM_FILTER 4
#define SYM_TABLE 5
#define SYM_ATTRIBUTE 6
#define SYM_KEYWORD 7
#define SYM_METHOD 8
#define SYM_MPLS_DOMAIN 9
#define SYM_MPLS_RANGE 10

#define SYM_VARIABLE 0x100	/* 0x100-0x1ff are variable types */
#define SYM_VARIABLE_RANGE SYM_VARIABLE ... (SYM_VARIABLE | 0xff)
#define SYM_CONSTANT 0x200	/* 0x200-0x2ff are variable types */
#define SYM_CONSTANT_RANGE SYM_CONSTANT ... (SYM_CONSTANT | 0xff)

#define SYM_TYPE(s) ((s)->val->type)
#define SYM_VAL(s) ((s)->val->val)

/* Symbol flags */
#define SYM_FLAG_SAME 0x1	/* For SYM_FUNCTION and SYM_FILTER */

struct include_file_stack {
  void *buffer;				/* Internal lexer state */
  char *file_name;			/* File name */
  int fd;				/* File descriptor */
  int lino;				/* Current line num */
  int chno;				/* Current char num (on current line) */
  int toklen;				/* Current token length */
  int depth;				/* Include depth, 0 = cannot include */

  struct include_file_stack *prev;	/* Previous record in stack */
  struct include_file_stack *up;	/* Parent (who included this file) */
};

extern struct include_file_stack *ifs;

int cf_lex(void);
void cf_lex_init(int is_cli, struct config *c);
void cf_lex_unwind(void);

struct symbol *cf_find_symbol_scope(const struct sym_scope *scope, const byte *c);
static inline struct symbol *cf_find_symbol_cfg(const struct config *cfg, const byte *c)
{ return cf_find_symbol_scope(cfg->root_scope, c); }

#define cf_find_symbol(where, what) _Generic(*(where), \
    struct config: cf_find_symbol_cfg, \
    struct sym_scope: cf_find_symbol_scope \
    )((where), (what))

struct symbol *cf_get_symbol(struct config *conf, const byte *c);
struct symbol *cf_default_name(struct config *conf, char *template, int *counter);
struct symbol *cf_localize_symbol(struct config *conf, struct symbol *sym);

static inline int cf_symbol_is_local(struct config *conf, struct symbol *sym)
{ return (sym->scope == conf->current_scope) && !conf->current_scope->soft_scopes; }

/* internal */
struct symbol *cf_new_symbol(struct sym_scope *scope, pool *p, struct linpool *lp, const byte *c);

/**
 * cf_define_symbol - define meaning of a symbol
 * @sym: symbol to be defined
 * @type: symbol class to assign
 * @def: class dependent data
 *
 * Defines new meaning of a symbol. If the symbol is an undefined
 * one (%SYM_VOID), it's just re-defined to the new type. If it's defined
 * in different scope, a new symbol in current scope is created and the
 * meaning is assigned to it. If it's already defined in the current scope,
 * an error is reported via cf_error().
 *
 * Result: Pointer to the newly defined symbol. If we are in the top-level
 * scope, it's the same @sym as passed to the function.
 */
#define cf_define_symbol(conf_, osym_, type_, var_, def_) ({ \
    struct symbol *sym_ = cf_localize_symbol(conf_, osym_); \
    sym_->class = type_; \
    sym_->var_ = def_; \
    sym_; })

#define cf_create_symbol(conf_, name_, type_, var_, def_) \
  cf_define_symbol(conf_, cf_get_symbol(conf_, name_), type_, var_, def_)

void cf_push_scope(struct config *, struct symbol *);
void cf_pop_scope(struct config *);
void cf_push_soft_scope(struct config *);
void cf_pop_soft_scope(struct config *);

static inline void cf_push_block_scope(struct config *conf)
{ cf_push_scope(conf, NULL); conf->current_scope->block = 1; }

static inline void cf_pop_block_scope(struct config *conf)
{ ASSERT(conf->current_scope->block); cf_pop_scope(conf); }

char *cf_symbol_class_name(struct symbol *sym);

/* Parser */

extern char *cf_text;
int cf_parse(void);

/* Sysdep hooks */

void sysdep_preconfig(struct config *);
int sysdep_commit(struct config *, struct config *);
void sysdep_shutdown_done(void);

#endif

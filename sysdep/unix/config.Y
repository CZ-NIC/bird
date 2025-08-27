/*
 *	BIRD -- UNIX Configuration
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "sysdep/unix/unix.h"
#include <stdio.h>

CF_DEFINES

static struct log_config *this_log;
static struct cli_config *this_cli_config;
static struct thread_group_config *this_thread_group;

CF_DECLS

CF_KEYWORDS(LOG, SYSLOG, ALL, DEBUG, TRACE, INFO, REMOTE, WARNING, ERROR, AUTH, FATAL, BUG, STDERR, SOFT, UDP, PORT, CLI)
CF_KEYWORDS(NAME, CONFIRM, UNDO, CHECK, TIMEOUT, DEBUG, LATENCY, LIMIT, WATCHDOG, WARNING, STATUS)
CF_KEYWORDS(PING, WAKEUP, SOCKETS, SCHEDULING, EVENTS, TIMERS, ALLOCATOR)
CF_KEYWORDS(GRACEFUL, RESTART, FIXED, V2)
CF_KEYWORDS(THREAD, THREADS, GROUP, MIN, MAX, TIME, LATENCY, DEFAULT)

%type <i> log_mask log_mask_list log_cat cfg_timeout debug_unix latency_debug_mask latency_debug_flag latency_debug_list
%type <t> cfg_name
%type <t> syslog_name

CF_GRAMMAR

conf: log_config ;

log_begin: { this_log = cfg_allocz(sizeof(struct log_config)); };

log_config: LOG log_begin log_file log_mask ';' {
    this_log->mask = $4;
    add_tail(&new_config->logfiles, &this_log->n);
  }
 ;

syslog_name:
   NAME text { $$ = $2; }
 | { $$ = bird_name; }
 ;

log_limit:
   /* empty */
 | expr text { this_log->limit = $1; this_log->backup = $2; }
 ;

log_file:
   text log_limit {
     if (!parse_and_exit)
     {
       this_log->rf = rf_open(new_config->pool, $1, RF_APPEND, this_log->limit);
       if (!this_log->rf) cf_error("Unable to open log file '%s': %m", $1);
     }
     this_log->filename = $1;
   }
 | FIXED text expr {
     if (!parse_and_exit)
     {
       this_log->rf = rf_open(new_config->pool, $2, RF_FIXED, this_log->limit = $3);
       if (!this_log->rf) cf_error("Unable to open log file '%s': %m", $2);
     }
     this_log->filename = $2;
   }
 | SYSLOG syslog_name { this_log->rf = NULL; new_config->syslog_name = $2; }
 | STDERR { this_log->rf = &rf_stderr; this_log->terminal_flag = 1; }
 | UDP log_udp_host log_udp_port { this_log->rf = NULL; }
 ;

log_udp_host: text_or_ipa
{
  if ($1.type == T_STRING)
    this_log->udp_host = $1.val.s;
  else if ($1.type == T_IP)
    this_log->udp_ip = $1.val.ip;
  else bug("Bad text_or_ipa");
};

log_udp_port:
    /* empty */ { this_log->udp_port = 514; }
  | PORT expr { check_u16($2); this_log->udp_port = $2; }
  ;

log_mask:
   ALL { $$ = ~0; }
 | '{' log_mask_list '}' { $$ = $2; }
 ;

log_mask_list:
   log_cat { $$ = 1 << $1; }
 | log_mask_list ',' log_cat { $$ = $1 | (1 << $3); }
 ;

log_cat:
   DEBUG { $$ = L_DEBUG[0]; }
 | TRACE { $$ = L_TRACE[0]; }
 | INFO { $$ = L_INFO[0]; }
 | REMOTE { $$ = L_REMOTE[0]; }
 | WARNING { $$ = L_WARN[0]; }
 | ERROR { $$ = L_ERR[0]; }
 | AUTH { $$ = L_AUTH[0]; }
 | FATAL { $$ = L_FATAL[0]; }
 | BUG { $$ = L_BUG[0]; }
 ;


conf: mrtdump_base ;

mrtdump_base:
   MRTDUMP PROTOCOLS mrtdump_mask ';' { new_config->proto_default_mrtdump = $3; }
 | MRTDUMP text ';' {
     if (!parse_and_exit)
     {
       struct rfile *f = rf_open(new_config->pool, $2, RF_APPEND, 0);
       if (!f) cf_error("Unable to open MRTDump file '%s': %m", $2);
       new_config->mrtdump_file = f;
     }
   }
 ;

conf: cli ;

cli: CLI text cli_opts {
  this_cli_config->name = $2;
  cli_config_add_tail(&new_config->cli, this_cli_config);
  this_cli_config = NULL;
} ;

cli_opts: cli_opts_begin '{' cli_opts_block '}' ';' | cli_opts_begin ';' ;

cli_opts_begin: {
  this_cli_config = cfg_alloc(sizeof *this_cli_config);
  *this_cli_config = (typeof (*this_cli_config)) {
    .config = new_config,
    .mode = 0660,
  };
};

cli_opts_block:
  /* EMPTY */
  | cli_opts_block RESTRICT ';' { this_cli_config->restricted = 1; }
  | cli_opts_block V2 ATTRIBUTES ';' { this_cli_config->v2attributes = 1; }
;

conf: THREADS expr {
  if ($2 < 1) cf_error("Number of threads must be at least one.");
  if (!new_config->thread_group_simple &&
      !EMPTY_TLIST(thread_group_config, &new_config->thread_group))
    cf_error("Mixing of `threads NUM` and `threads worker {}` is not allowed.");

  if (new_config->thread_group_simple == -1)
    THEAD(thread_group_config, &new_config->thread_group)->thread_count = $2;

  new_config->thread_group_simple = $2;
};

conf: thread_group ;

thread_group: thread_group_start thread_group_opt_list thread_group_end ;

thread_group_start: THREAD GROUP symbol {
  switch (new_config->thread_group_simple) {
    case -1: cf_error("Put `threads` block before any protocol or table definition.");
    case 0: break;
    default: cf_error("Mixing of `threads NUM` and `threads worker {}` is not allowed.");
  }

  this_thread_group = cfg_alloc(sizeof *this_thread_group);
  *this_thread_group = strcmp($3->name, "express") ?
    thread_group_config_default_worker :
    thread_group_config_default_express;
  this_thread_group->symbol = cf_define_symbol(new_config, $3, SYM_THREAD_GROUP, thread_group, this_thread_group);
};

thread_group_opt:
   MAX TIME expr_us { this_thread_group->params.max_time = $3; }
 | MIN TIME expr_us { this_thread_group->params.min_time = $3; }
 | MAX LATENCY expr_us { this_thread_group->params.max_latency = $3; }
 | THREADS expr { this_thread_group->thread_count = $2; }
 | WAKEUP TIME expr_us { this_thread_group->params.wakeup_time = $3; }
 | DEFAULT bool {
    if ($2) {
      if (new_config->default_thread_group && new_config->default_thread_group != this_thread_group) {
        cf_error("Too many default thread groups, already have %s",
          new_config->default_thread_group->symbol->name);
      }
      new_config->default_thread_group = this_thread_group;
    }
  }
 ;

thread_group_opts:
   /* empty */
  | thread_group_opts thread_group_opt ';'
  ;

thread_group_opt_list:
   /* empty */
 | '{' thread_group_opts '}'
 ;

thread_group_end: {
  if (this_thread_group->params.max_time > 60 S_)
    cf_error("Loop time maximum is 60 seconds, got %t", this_thread_group->params.max_time);
  if (this_thread_group->params.max_latency < this_thread_group->params.max_time)
    cf_error("Loop time maximum can't be higher than its latency limit");
  if (this_thread_group->params.min_time > this_thread_group->params.max_time)
    cf_error("Loop time minimm can't be higher than maximum");
  if (this_thread_group->params.wakeup_time < 1 S_)
    cf_error("Too low idle wakeup time, expected at least 1 second");

  thread_group_config_add_tail(&new_config->thread_group, this_thread_group);
  this_thread_group = NULL;
};


conf: debug_unix ;

debug_unix:
   DEBUG LATENCY latency_debug_mask { new_config->latency_debug = $3; }
 | DEBUG LATENCY LIMIT expr_us { new_config->latency_limit = $4; }
 | WATCHDOG WARNING expr_us { new_config->watchdog_warning = $3; }
 | WATCHDOG TIMEOUT expr_us { new_config->watchdog_timeout = ($3 + 999999) TO_S; }
 ;

latency_debug_mask:
   ALL { $$ = ~0; }
 | OFF { $$ = 0; }
 | '{' latency_debug_list '}' { $$ = $2; }
 ;

latency_debug_list: latency_debug_flag | latency_debug_list ',' latency_debug_flag { $$ = $1 | $3; };

latency_debug_flag:
   PING		{ $$ = DL_PING; }
 | WAKEUP	{ $$ = DL_WAKEUP; }
 | SOCKETS	{ $$ = DL_SOCKETS; }
 | SCHEDULING	{ $$ = DL_SCHEDULING; }
 | ALLOCATOR	{ $$ = DL_ALLOCATOR; }
 | EVENTS	{ $$ = DL_EVENTS; }
 | TIMERS	{ $$ = DL_TIMERS; }
 ;


/* Unix specific commands */

CF_CLI_HELP(CONFIGURE, ..., [[Reload configuration]])

CF_CLI(CONFIGURE, cfg_name cfg_timeout, [\"<file>\"] [timeout [<sec>]], [[Reload configuration]])
{ cmd_reconfig($2, RECONFIG_HARD, $3); } ;

CF_CLI(CONFIGURE SOFT, cfg_name cfg_timeout, [\"<file>\"] [timeout [<sec>]], [[Reload configuration and ignore changes in filters]])
{ cmd_reconfig($3, RECONFIG_SOFT, $4); } ;

/* Hack to get input completion for 'timeout' */
CF_CLI_CMD(CONFIGURE TIMEOUT, [<sec>], [[Reload configuration with undo timeout]])
CF_CLI_CMD(CONFIGURE SOFT TIMEOUT, [<sec>], [[Reload configuration with undo timeout]])

CF_CLI(CONFIGURE CONFIRM,,, [[Confirm last configuration change - deactivate undo timeout]])
{ cmd_reconfig_confirm(); } ;

CF_CLI(CONFIGURE UNDO,,, [[Undo last configuration change]])
{ cmd_reconfig_undo(); } ;

CF_CLI(CONFIGURE STATUS,,, [[Show configuration status]])
{ cmd_reconfig_status(); } ;

CF_CLI(CONFIGURE CHECK, cfg_name, [\"<file>\"], [[Parse configuration and check its validity]])
{ cmd_check_config($3); } ;

CF_CLI(DOWN,,, [[Shut the daemon down]])
{ cmd_shutdown(); } ;

CF_CLI_HELP(GRACEFUL, restart, [[Shut the daemon down for graceful restart]])

CF_CLI(GRACEFUL RESTART,,, [[Shut the daemon down for graceful restart]])
{ cmd_graceful_restart(); } ;

CF_CLI(SHOW THREADS,,, [[Write out thread information]])
{ cmd_show_threads(0); } ;

CF_CLI(SHOW THREADS ALL,,, [[Write out thread and IO loop information]])
{ cmd_show_threads(1); } ;

cfg_name:
   /* empty */ { $$ = NULL; }
 | text
 ;

cfg_timeout:
   /* empty */ { $$ = 0; }
 | TIMEOUT { $$ = UNIX_DEFAULT_CONFIGURE_TIMEOUT; }
 | TIMEOUT expr { $$ = $2; }
 ;

CF_CODE

CF_END

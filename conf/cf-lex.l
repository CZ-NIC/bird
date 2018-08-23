/*
 *	BIRD -- Configuration Lexer
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Lexical analyzer
 *
 * The lexical analyzer used for configuration files and CLI commands
 * is generated using the |flex| tool accompanied by a couple of
 * functions maintaining the hash tables containing information about
 * symbols and keywords.
 *
 * Each symbol is represented by a &symbol structure containing name
 * of the symbol, its lexical scope, symbol class (%SYM_PROTO for a
 * name of a protocol, %SYM_CONSTANT for a constant etc.) and class
 * dependent data.  When an unknown symbol is encountered, it's
 * automatically added to the symbol table with class %SYM_VOID.
 *
 * The keyword tables are generated from the grammar templates
 * using the |gen_keywords.m4| script.
 */

%{
#undef REJECT     /* Avoid name clashes */

#define PARSER 1

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "conf/conf.h"
#include "conf/parser.h"
#include "conf/cf-parse.tab.h"
#include "lib/string.h"
#include "lib/hash.h"

struct keyword {
  byte *name;
  int value;
  struct keyword *next;
};

#include "conf/keywords.h"

/* Could be defined by Bison in cf-parse.tab.h, inteferes with SYM hash */
#ifdef SYM
#undef SYM
#endif



#define KW_KEY(n)		n->name
#define KW_NEXT(n)		n->next
#define KW_EQ(a,b)		!strcmp(a,b)
#define KW_FN(k)		cf_hash(k)
#define KW_ORDER		8 /* Fixed */

HASH(struct keyword) kw_hash;

#define YY_NO_UNPUT
#define CTX cfx_get_extra(yyscanner)
#define COR (CTX->order)
#define CST (CTX->order->state)
#define YY_INPUT(buf,result,max) result = COR->cf_read_hook(COR, buf, max);
#define YY_FATAL_ERROR(...) cf_error(CTX, __VA_ARGS__)

#define cf_lval (* (cfx_get_lval(yyscanner)))

static void cf_include(char *arg, int alen, yyscan_t yyscanner);
static int check_eof(yyscan_t yyscanner);

%}

%option noyywrap
%option noinput
%option nounput
%option noreject

%option reentrant bison-bridge
%option extra-type="struct cf_context *"

%x COMMENT CCOMM CLI

ALPHA [a-zA-Z_]
DIGIT [0-9]
XIGIT [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
WHITE [ \t]
include   ^{WHITE}*include{WHITE}*\".*\"{WHITE}*;

%%
{include} {
  char *start, *end;

  if (!COR->cf_include)
    YY_FATAL_ERROR("Include not allowed in CLI");

  start = strchr(yytext, '"');
  start++;

  end = strchr(start, '"');
  *end = 0;

  if (start == end)
    YY_FATAL_ERROR("Include with empty argument");

  cf_include(start, end-start, yyscanner);
}

{DIGIT}+:{DIGIT}+ {
  uint len1 UNUSED, len2;
  u64 l;
  char *e;

  errno = 0;
  l = strtoul(yytext, &e, 10);
  if (e && (*e != ':') || (errno == ERANGE) || (l >> 32))
    YY_FATAL_ERROR("ASN out of range");

  if (l >> 16)
  {
    len1 = 32;
    len2 = 16;
    cf_lval.i64 = (2ULL << 48) | (((u64) l) << len2);
  }
  else
  {
    len1 = 16;
    len2 = 32;
    cf_lval.i64 = 0 | (((u64) l) << len2);
  }

  errno = 0;
  l = strtoul(e+1, &e, 10);
  if (e && *e || (errno == ERANGE) || (l >> len2))
    YY_FATAL_ERROR("Number out of range");
  cf_lval.i64 |= l;

  return VPN_RD;
}

[02]:{DIGIT}+:{DIGIT}+ {
  uint len1, len2;
  u64 l;
  char *e;

  if (yytext[0] == '0')
  {
    cf_lval.i64 = 0;
    len1 = 16;
    len2 = 32;
  }
  else
  {
    cf_lval.i64 = 2ULL << 48;
    len1 = 32;
    len2 = 16;
  }

  errno = 0;
  l = strtoul(yytext+2, &e, 10);
  if (e && (*e != ':') || (errno == ERANGE) || (l >> len1))
    YY_FATAL_ERROR("ASN out of range");
  cf_lval.i64 |= ((u64) l) << len2;

  errno = 0;
  l = strtoul(e+1, &e, 10);
  if (e && *e || (errno == ERANGE) || (l >> len2))
    YY_FATAL_ERROR("Number out of range");
  cf_lval.i64 |= l;

  return VPN_RD;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+:{DIGIT}+ {
  unsigned long int l;
  ip4_addr ip4;
  char *e;

  cf_lval.i64 = 1ULL << 48;

  e = strchr(yytext, ':');
  *e++ = '\0';
  if (!ip4_pton(yytext, &ip4))
    YY_FATAL_ERROR("Invalid IPv4 address %s in Route Distinguisher", yytext);
  cf_lval.i64 |= ((u64) ip4_to_u32(ip4)) << 16;

  errno = 0;
  l = strtoul(e, &e, 10);
  if (e && *e || (errno == ERANGE) || (l >> 16))
    YY_FATAL_ERROR("Number out of range");
  cf_lval.i64 |= l;

  return VPN_RD;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+ {
  if (!ip4_pton(yytext, &cf_lval.ip4))
    YY_FATAL_ERROR("Invalid IPv4 address %s", yytext);
  return IP4;
}

({XIGIT}*::|({XIGIT}*:){3,})({XIGIT}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+) {
  if (!ip6_pton(yytext, &cf_lval.ip6))
    YY_FATAL_ERROR("Invalid IPv6 address %s", yytext);
  return IP6;
}

0x{XIGIT}+ {
  char *e;
  unsigned long int l;
  errno = 0;
  l = strtoul(yytext+2, &e, 16);
  if (e && *e || errno == ERANGE || (unsigned long int)(unsigned int) l != l)
    YY_FATAL_ERROR("Number out of range");
  cf_lval.i = l;
  return NUM;
}

{DIGIT}+ {
  char *e;
  unsigned long int l;
  errno = 0;
  l = strtoul(yytext, &e, 10);
  if (e && *e || errno == ERANGE || (unsigned long int)(unsigned int) l != l)
    YY_FATAL_ERROR("Number out of range");
  cf_lval.i = l;
  return NUM;
}

else: {
  /* Hack to distinguish if..else from else: in case */
  return ELSECOL;
}

({ALPHA}{ALNUM}*|[']({ALNUM}|[-]|[\.]|[:])*[']) {
  if(*yytext == '\'') {
    yytext[yyleng-1] = 0;
    yytext++;
  }

  struct keyword *k = HASH_FIND(kw_hash, KW, yytext);
  if (k)
  {
    if (k->value > 0)
      return k->value;
    else
    {
      cf_lval.i = -k->value;
      return ENUM;
    }
  }

  cf_lval.s = cf_get_symbol(CTX, yytext);
  return SYM;
}

<CLI>(.|\n) {
  BEGIN(INITIAL);
  yyless(0);
  return CLI_MARKER;
}

\.\. {
  return DDOT;
}

[={}:;,.()+*/%<>~\[\]?!\|-] {
  return yytext[0];
}

["][^"\n]*["] {
  yytext[yyleng-1] = 0;
  cf_lval.t = cf_strdup(CTX, yytext+1);
  yytext[yyleng-1] = '"';
  return TEXT;
}

["][^"\n]*\n	YY_FATAL_ERROR("Unterminated string");

<INITIAL,COMMENT><<EOF>>	{ if (check_eof(yyscanner)) return END; }

{WHITE}+

\n	CST->lino++;

#	BEGIN(COMMENT);

\/\*	BEGIN(CCOMM);

.	YY_FATAL_ERROR("Unknown character");

<COMMENT>\n {
  CST->lino++;
  BEGIN(INITIAL);
}

<COMMENT>.

<CCOMM>\*\/	BEGIN(INITIAL);
<CCOMM>\n	CST->lino++;
<CCOMM>\/\*	YY_FATAL_ERROR("Comment nesting not supported");
<CCOMM><<EOF>>	YY_FATAL_ERROR("Unterminated comment");
<CCOMM>.

\!\= return NEQ;
\!\~ return NMA;
\<\= return LEQ;
\>\= return GEQ;
\&\& return AND;
\|\| return OR;

\[\= return PO;
\=\] return PC;

%%

uint
cf_hash(byte *c)
{
  uint h = 13 << 24;

  while (*c)
    h = h + (h >> 2) + (h >> 5) + ((uint) *c++ << 24);
  return h;
}

static void
cf_init_state(struct cf_context *ctx, struct conf_state *cs)
{
  cs->buffer = yy_create_buffer(NULL, YY_BUF_SIZE, ctx->yyscanner);
}

struct conf_state *
cf_new_state(struct cf_context *ctx, const char *name)
{
  struct conf_state *cs = cfg_alloc(sizeof(struct conf_state));
  *cs = (struct conf_state) {
    .name = cfg_strdup(name),
    .lino = 1,
  };
  cf_init_state(ctx, cs);
  return cs;
}

void
cf_free_state(struct cf_context *ctx, struct conf_state *cs)
{
  yy_delete_buffer(cs->buffer, ctx->yyscanner);
  /* The state structure is allocated from linpool, will be auto-freed. */
}

void
cf_scan_bytes(struct cf_context *ctx, const char *buf, uint len)
{
  yy_scan_bytes(buf, len, ctx->yyscanner);
}

static void
cf_include(char *arg, int alen, yyscan_t yyscanner)
{
  COR->cf_include(COR, arg, alen);
  yy_switch_to_buffer(CST->buffer, yyscanner);
}

static int
check_eof(yyscan_t yyscanner)
{
  if (!COR->cf_outclude)
    return 1;

  if (COR->cf_outclude(COR))
    return 1;

  yy_switch_to_buffer(CST->buffer, yyscanner);
  return 0;
}

void
cf_init_kh(void)
{
  HASH_INIT(kw_hash, &root_pool, KW_ORDER);

  struct keyword *k;
  for (k=keyword_list; k->name; k++)
    HASH_INSERT(kw_hash, KW, k);
}

/**
 * cf_new_context - initialize the lexer
 * @is_cli: true if we're going to parse CLI command, false for configuration
 * @c: configuration structure
 *
 * cf_new_context() initializes the lexical analyzer and prepares it for
 * parsing of a new input.
 */
struct cf_context *
cf_new_context(int is_cli, struct conf_order *order)
{
  struct cf_context *ctx = order->ctx = lp_allocz(order->new_config->mem, sizeof(struct cf_context));
  *ctx = (struct cf_context) {
    .new_config = order->new_config,
    .cfg_mem = order->new_config->mem,
    .order = order,
  };

  cfx_lex_init_extra(ctx, &(ctx->yyscanner));
  struct yyguts_t *yyg = ctx->yyscanner;

  cf_init_state(ctx, order->state);
  yy_switch_to_buffer(order->state->buffer, yyg);

  if (is_cli)
    BEGIN(CLI);
  else
    BEGIN(INITIAL);

  ctx->sym_scope = cfg_allocz(sizeof(struct sym_scope));
  ctx->sym_scope->active = 1;

  return ctx;
}

void
cf_free_context(struct cf_context *ctx)
{
  cfx_lex_destroy(ctx->yyscanner);
}

/**
 * DOC: Parser
 *
 * Both the configuration and CLI commands are analyzed using a syntax
 * driven parser generated by the |bison| tool from a grammar which
 * is constructed from information gathered from grammar snippets by
 * the |gen_parser.m4| script.
 *
 * Grammar snippets are files (usually with extension |.Y|) contributed
 * by various BIRD modules in order to provide information about syntax of their
 * configuration and their CLI commands. Each snipped consists of several
 * sections, each of them starting with a special keyword: |CF_HDR| for
 * a list of |#include| directives needed by the C code, |CF_DEFINES|
 * for a list of C declarations, |CF_DECLS| for |bison| declarations
 * including keyword definitions specified as |CF_KEYWORDS|, |CF_GRAMMAR|
 * for the grammar rules, |CF_CODE| for auxiliary C code and finally
 * |CF_END| at the end of the snippet.
 *
 * To create references between the snippets, it's possible to define
 * multi-part rules by utilizing the |CF_ADDTO| macro which adds a new
 * alternative to a multi-part rule.
 *
 * CLI commands are defined using a |CF_CLI| macro. Its parameters are:
 * the list of keywords determining the command, the list of parameters,
 * help text for the parameters and help text for the command.
 *
 * Values of |enum| filter types can be defined using |CF_ENUM| with
 * the following parameters: name of filter type, prefix common for all
 * literals of this type and names of all the possible values.
 */

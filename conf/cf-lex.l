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

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <unistd.h>
#include <libgen.h>
#include <glob.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/stat.h>

#define PARSER 1

#include "nest/bird.h"
#include "nest/route.h"
#include "nest/protocol.h"
#include "filter/filter.h"
#include "filter/f-inst.h"
#include "conf/conf.h"
#include "conf/cf-parse.tab.h"
#include "lib/string.h"
#include "lib/hash.h"

#include "conf/keywords.h"

/* Could be defined by Bison in cf-parse.tab.h, inteferes with SYM hash */
#ifdef SYM
#undef SYM
#endif


static uint cf_hash(const byte *c);

#define SYM_KEY(n)		n->name
#define SYM_NEXT(n)		n->next
#define SYM_EQ(a,b)		!strcmp(a,b)
#define SYM_FN(k)		cf_hash(k)
#define SYM_ORDER		4 /* Initial */

#define SYM_REHASH		sym_rehash
#define SYM_PARAMS		/8, *1, 2, 2, 4, 20


HASH_DEFINE_REHASH_FN(SYM, struct symbol)

struct sym_scope *global_root_scope;
pool *global_root_scope_pool;
linpool *global_root_scope_linpool;

linpool *cfg_mem;

int (*cf_read_hook)(byte *buf, unsigned int max, int fd);
struct include_file_stack *ifs;
static struct include_file_stack *ifs_head;

#define QUOTED_BUFFER_SIZE  4096
static BUFFER_(char) quoted_buffer;
static char quoted_buffer_data[QUOTED_BUFFER_SIZE];
static inline void quoted_buffer_init(void) {
  quoted_buffer.used = 0;
  quoted_buffer.size = QUOTED_BUFFER_SIZE;
  quoted_buffer.data = quoted_buffer_data;
}

#define MAX_INCLUDE_DEPTH 8

#define YY_INPUT(buf,result,max) result = cf_read_hook(buf, max, ifs->fd);
#define YY_NO_UNPUT
#define YY_FATAL_ERROR(msg) cf_error(msg)
#define YY_USER_ACTION ifs->chno += yyleng; ifs->toklen = yyleng;

static void cf_include(char *arg, int alen);
static int check_eof(void);

static enum yytokentype cf_lex_symbol(const char *data);

%}

%option noyywrap
%option noinput
%option nounput
%option noreject

%x COMMENT CCOMM CLI QUOTED APOSTROPHED INCLUDE

ALPHA [a-zA-Z_]
DIGIT [0-9]
XIGIT [0-9a-fA-F]
ALNUM [a-zA-Z_0-9]
WHITE [ \t]

%%
^{WHITE}*include{WHITE}*\" {
  if (!ifs->depth)
    cf_error("Include not allowed in CLI");

  BEGIN(INCLUDE);
}

<INCLUDE>[^"\n]+["]{WHITE}*; {
  char *start, *end;

  start = yytext;

  end = strchr(start, '"');
  *end = 0;

  if (start == end)
    cf_error("Include with empty argument");

  cf_include(start, end-start);

  BEGIN(INITIAL);
}

<INCLUDE>["]	        cf_error("Include with empty argument");
<INCLUDE>.		cf_error("Unterminated include");
<INCLUDE>\n		cf_error("Unterminated include");
<INCLUDE><<EOF>>	cf_error("Unterminated include");


{DIGIT}+:{DIGIT}+ {
  uint len1 UNUSED, len2;
  u64 l;
  char *e;

  errno = 0;
  l = bstrtoul10(yytext, &e);
  if (!e || (*e != ':') || (errno == ERANGE) || (l >> 32))
    cf_error("ASN out of range");

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
  l = bstrtoul10(e+1, &e);
  if (!e || *e || (errno == ERANGE) || (l >> len2))
    cf_error("Number out of range");
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
  l = bstrtoul10(yytext+2, &e);
  if (!e || (*e != ':') || (errno == ERANGE) || (l >> len1))
    cf_error("ASN out of range");
  cf_lval.i64 |= ((u64) l) << len2;

  errno = 0;
  l = bstrtoul10(e+1, &e);
  if (!e || *e || (errno == ERANGE) || (l >> len2))
    cf_error("Number out of range");
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
    cf_error("Invalid IPv4 address %s in Route Distinguisher", yytext);
  cf_lval.i64 |= ((u64) ip4_to_u32(ip4)) << 16;

  errno = 0;
  l = bstrtoul10(e, &e);
  if (!e || *e || (errno == ERANGE) || (l >> 16))
    cf_error("Number out of range");
  cf_lval.i64 |= l;

  return VPN_RD;
}

{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+ {
  if (!ip4_pton(yytext, &cf_lval.ip4))
    cf_error("Invalid IPv4 address %s", yytext);
  return IP4;
}

({XIGIT}{2}){16,}|{XIGIT}{2}(:{XIGIT}{2}){15,}|hex:({XIGIT}{2}*|{XIGIT}{2}(:{XIGIT}{2})*) {
  char *s = yytext;
  struct adata *bs;

  /* Skip 'hex:' prefix */
  if (s[0] == 'h' && s[1] == 'e' && s[2] == 'x' && s[3] == ':')
    s += 4;

  int len = bstrhextobin(s, NULL);
  if (len < 0)
    cf_error("Invalid hex string");

  bs = cfg_allocz(sizeof(struct adata) + len);
  bs->length = bstrhextobin(s, bs->data);
  ASSERT(bs->length == len);

  cf_lval.bs = bs;
  return BYTETEXT;
}

({XIGIT}*::|({XIGIT}*:){3,})({XIGIT}*|{DIGIT}+\.{DIGIT}+\.{DIGIT}+\.{DIGIT}+) {
  if (!ip6_pton(yytext, &cf_lval.ip6))
    cf_error("Invalid IPv6 address %s", yytext);
  return IP6;
}

0x{XIGIT}+ {
  char *e;
  unsigned long int l;
  errno = 0;
  l = bstrtoul16(yytext+2, &e);
  if (!e || *e || errno == ERANGE || (unsigned long int)(unsigned int) l != l)
    cf_error("Number out of range");
  cf_lval.i = l;
  return NUM;
}

{DIGIT}+ {
  char *e;
  unsigned long int l;
  errno = 0;
  l = bstrtoul10(yytext, &e);
  if (!e || *e || errno == ERANGE || (unsigned long int)(unsigned int) l != l)
    cf_error("Number out of range");
  cf_lval.i = l;
  return NUM;
}

else: {
  /* Hack to distinguish if..else from else: in case */
  return ELSECOL;
}

['] {
  BEGIN(APOSTROPHED);
  quoted_buffer_init();
}

<APOSTROPHED>{ALNUM}|[-]|[.:]	BUFFER_PUSH(quoted_buffer) = yytext[0];
<APOSTROPHED>\n			cf_error("Unterminated symbol");
<APOSTROPHED><<EOF>>		cf_error("Unterminated symbol");
<APOSTROPHED>['] {
  BEGIN(INITIAL);
  BUFFER_PUSH(quoted_buffer) = 0;
  return cf_lex_symbol(quoted_buffer_data);
}
<APOSTROPHED>.			cf_error("Invalid character in apostrophed symbol");

({ALPHA}{ALNUM}*) {
  return cf_lex_symbol(yytext);
}

<CLI>(.|\n) {
  BEGIN(INITIAL);
  return CLI_MARKER;
}

\.\. {
  return DDOT;
}

[={}:;,.()+*/%<>~\[\]?!\|-] {
  return yytext[0];
}

["] {
  BEGIN(QUOTED);
  quoted_buffer_init();
}

<QUOTED>\n	cf_error("Unterminated string");
<QUOTED><<EOF>> cf_error("Unterminated string");
<QUOTED>["]	{
  BEGIN(INITIAL);
  BUFFER_PUSH(quoted_buffer) = 0;
  cf_lval.t = cfg_strdup(quoted_buffer_data);
  return TEXT;
}

<QUOTED>.	BUFFER_PUSH(quoted_buffer) = yytext[0];

<INITIAL,COMMENT><<EOF>>	{ if (check_eof()) return END; }

{WHITE}+

\n	ifs->lino++; ifs->chno = 0;

#	BEGIN(COMMENT);

\/\*	BEGIN(CCOMM);

.	cf_error("Unknown character");

<COMMENT>\n {
  ifs->lino++;
  ifs->chno = 0;
  BEGIN(INITIAL);
}

<COMMENT>.

<CCOMM>\*\/	BEGIN(INITIAL);
<CCOMM>\n	ifs->lino++; ifs->chno = 0;
<CCOMM>\/\*	cf_error("Comment nesting not supported");
<CCOMM><<EOF>>	cf_error("Unterminated comment");
<CCOMM>.

\!\= return NEQ;
\!\~ return NMA;
\<\= return LEQ;
\>\= return GEQ;
\&\& return AND;
\|\| return OR;
\-\> return IMP;

\[\= return PO;
\=\] return PC;

%%

static uint
cf_hash(const byte *c)
{
  uint h = 13 << 24;

  while (*c)
    h = h + (h >> 2) + (h >> 5) + ((uint) *c++ << 24);
  return h;
}

/*
 * IFS stack - it contains structures needed for recursive processing
 * of include in config files. On the top of the stack is a structure
 * for currently processed file. Other structures are either for
 * active files interrupted because of include directive (these have
 * fd and flex buffer) or for inactive files scheduled to be processed
 * later (when parent requested including of several files by wildcard
 * match - these do not have fd and flex buffer yet).
 *
 * FIXME: Most of these ifs and include functions are really sysdep/unix.
 */

static struct include_file_stack *
push_ifs(struct include_file_stack *old)
{
  struct include_file_stack *ret;
  ret = cfg_allocz(sizeof(struct include_file_stack));
  ret->lino = 1;
  ret->prev = old;
  return ret;
}

static struct include_file_stack *
pop_ifs(struct include_file_stack *old)
{
 yy_delete_buffer(old->buffer);
 close(old->fd);
 return old->prev;
}

static void
enter_ifs(struct include_file_stack *new)
{
  if (!new->buffer)
    {
      new->fd = open(new->file_name, O_RDONLY);
      if (new->fd < 0)
        {
          ifs = ifs->up;
	  cf_error("Unable to open included file %s: %m", new->file_name);
        }

      new->buffer = yy_create_buffer(NULL, YY_BUF_SIZE);
    }

  yy_switch_to_buffer(new->buffer);
}

/**
 * cf_lex_unwind - unwind lexer state during error
 *
 * cf_lex_unwind() frees the internal state on IFS stack when the lexical
 * analyzer is terminated by cf_error().
 */
void
cf_lex_unwind(void)
{
  struct include_file_stack *n;

  for (n = ifs; n != ifs_head; n = n->prev)
    {
      /* Memory is freed automatically */
      if (n->buffer)
	yy_delete_buffer(n->buffer);
      if (n->fd)
        close(n->fd);
    }

  ifs = ifs_head;
}

static void
cf_include(char *arg, int alen)
{
  struct include_file_stack *base_ifs = ifs;
  int new_depth, rv, i;
  char *patt;
  glob_t g = {};

  new_depth = ifs->depth + 1;
  if (new_depth > MAX_INCLUDE_DEPTH)
    cf_error("Max include depth reached");

  /* expand arg to properly handle relative filenames */
  if (*arg != '/')
    {
      int dlen = strlen(ifs->file_name);
      char *dir = alloca(dlen + 1);
      patt = alloca(dlen + alen + 2);
      memcpy(dir, ifs->file_name, dlen + 1);
      sprintf(patt, "%s/%s", dirname(dir), arg);
    }
  else
    patt = arg;

  /* Skip globbing if there are no wildcards, mainly to get proper
     response when the included config file is missing */
  if (!strpbrk(arg, "?*["))
    {
      ifs = push_ifs(ifs);
      ifs->file_name = cfg_strdup(patt);
      ifs->depth = new_depth;
      ifs->up = base_ifs;
      enter_ifs(ifs);
      return;
    }

  /* Expand the pattern */
  rv = glob(patt, GLOB_ERR | GLOB_NOESCAPE, NULL, &g);
  if (rv == GLOB_ABORTED)
    cf_error("Unable to match pattern %s: %m", patt);
  if ((rv != 0) || (g.gl_pathc <= 0))
    return;

  /*
   * Now we put all found files to ifs stack in reverse order, they
   * will be activated and processed in order as ifs stack is popped
   * by pop_ifs() and enter_ifs() in check_eof().
   */
  for(i = g.gl_pathc - 1; i >= 0; i--)
    {
      char *fname = g.gl_pathv[i];
      struct stat fs;

      if (stat(fname, &fs) < 0)
	{
	  globfree(&g);
	  cf_error("Unable to stat included file %s: %m", fname);
	}

      if (fs.st_mode & S_IFDIR)
        continue;

      /* Prepare new stack item */
      ifs = push_ifs(ifs);
      ifs->file_name = cfg_strdup(fname);
      ifs->depth = new_depth;
      ifs->up = base_ifs;
    }

  globfree(&g);
  enter_ifs(ifs);
}

static int
check_eof(void)
{
  if (ifs == ifs_head)
    {
      /* EOF in main config file */
      ifs->lino = 1; /* Why this? */
      return 1;
    }

  ifs = pop_ifs(ifs);
  enter_ifs(ifs);
  return 0;
}

static inline void cf_swap_soft_scope(struct config *conf);

struct symbol *
cf_new_symbol(struct sym_scope *scope, pool *p, struct linpool *lp, const byte *c)
{
  if (scope->readonly)
    cf_error("Unknown symbol %s", c);

  struct symbol *s;

  uint l = strlen(c);
  if (l > SYM_MAX_LEN)
    cf_error("Symbol too long");

  s = lp_alloc(lp, sizeof(struct symbol) + l + 1);
  *s = (struct symbol) { .scope = scope, .class = SYM_VOID, };
  strcpy(s->name, c);

  if (!scope->hash.data)
    HASH_INIT(scope->hash, p, SYM_ORDER);

  HASH_INSERT2(scope->hash, SYM, p, s);

  if (new_config && (scope == new_config->root_scope))
    add_tail(&(new_config->symbols), &(s->n));

  return s;
}

/**
 * cf_find_symbol_scope - find a symbol by name
 * @scope: config scope
 * @c: symbol name
 *
 * This functions searches the symbol table in the scope @scope for a symbol of
 * given name. First it examines the current scope, then the underlying one
 * and so on until it either finds the symbol and returns a pointer to its
 * &symbol structure or reaches the end of the scope chain and returns %NULL to
 * signify no match.
 */
struct symbol *
cf_find_symbol_scope(const struct sym_scope *scope, const byte *c)
{
  struct symbol *s;

  /* Find the symbol here or anywhere below */
  while (scope)
    if (scope->hash.data && (s = HASH_FIND(scope->hash, SYM, c)))
      return s;
    else
      scope = scope->next;

  return NULL;
}

/**
 * cf_get_symbol - get a symbol by name
 * @c: symbol name
 *
 * This functions searches the symbol table of the currently parsed config
 * (@new_config) for a symbol of given name. It returns either the already
 * existing symbol or a newly allocated undefined (%SYM_VOID) symbol if no
 * existing symbol is found.
 */
struct symbol *
cf_get_symbol(struct config *conf, const byte *c)
{
  return cf_find_symbol_scope(conf->current_scope, c) ?: (
      cf_swap_soft_scope(conf),
      cf_new_symbol(conf->current_scope, conf->pool, conf->mem, c)
      );
}

/**
 * cf_localize_symbol - get the local instance of given symbol
 * @sym: the symbol to localize
 *
 * This functions finds the symbol that is local to current scope
 * for purposes of cf_define_symbol().
 */
struct symbol *
cf_localize_symbol(struct config *conf, struct symbol *sym)
{
  /* If the symbol type is void, it has been recently allocated just in this scope. */
  if (!sym->class)
    return sym;

  /* If the scope is the current, it is already defined in this scope. */
  if (cf_symbol_is_local(conf, sym))
    cf_error("Symbol '%s' already defined", sym->name);

  /* Not allocated here yet, doing it now. */
  cf_swap_soft_scope(conf);
  return cf_new_symbol(conf->current_scope, conf->pool, conf->mem, sym->name);
}

struct symbol *
cf_default_name(struct config *conf, char *template, int *counter)
{
  char buf[SYM_MAX_LEN];
  struct symbol *s;
  char *perc = strchr(template, '%');

  for(;;)
    {
      bsprintf(buf, template, ++(*counter));
      s = cf_get_symbol(conf, buf);
      if (s->class == SYM_VOID)
	return s;
      if (!perc)
	break;
    }
  cf_error("Unable to generate default name");
}

static enum yytokentype
cf_lex_symbol(const char *data)
{
  /* Have we defined such a symbol? */
  struct symbol *sym = cf_get_symbol(new_config, data);
  cf_lval.s = sym;

  switch (sym->class)
  {
    case SYM_KEYWORD:
    {
      int val = sym->keyword->value;
      if (val > 0) return val;
      cf_lval.i = -val;
      return ENUM;
    }
    case SYM_METHOD:
      return (sym->method->arg_num > 1) ? CF_SYM_METHOD_ARGS : CF_SYM_METHOD_BARE;
    case SYM_VOID:
      return CF_SYM_UNDEFINED;
    default:
      return CF_SYM_KNOWN;
  }
}

void f_type_methods_register(void);

/**
 * cf_lex_init - initialize the lexer
 * @is_cli: true if we're going to parse CLI command, false for configuration
 * @c: configuration structure
 *
 * cf_lex_init() initializes the lexical analyzer and prepares it for
 * parsing of a new input.
 */
void
cf_lex_init(int is_cli, struct config *c)
{
  if (!global_root_scope_pool)
  {
    global_root_scope_pool = rp_new(&root_pool, "Keywords pool");
    global_root_scope_linpool = lp_new(global_root_scope_pool);
    global_root_scope = lp_allocz(global_root_scope_linpool, sizeof(*global_root_scope));

    for (const struct keyword *k = keyword_list; k->name; k++)
    {
      struct symbol *sym = cf_new_symbol(global_root_scope, global_root_scope_pool, global_root_scope_linpool, k->name);
      sym->class = SYM_KEYWORD;
      sym->keyword = k;
    }

    global_root_scope->readonly = 1;

    f_type_methods_register();
  }

  ifs_head = ifs = push_ifs(NULL);
  if (!is_cli)
    {
      ifs->file_name = c->file_name;
      ifs->fd = c->file_fd;
      ifs->depth = 1;
    }

  yyrestart(NULL);
  ifs->buffer = YY_CURRENT_BUFFER;

  if (is_cli)
    BEGIN(CLI);
  else
    BEGIN(INITIAL);

  c->root_scope = c->current_scope = cfg_allocz(sizeof(struct sym_scope));
  c->root_scope->active = 1;

  if (is_cli)
    c->current_scope->next = config->root_scope;
  else
    c->current_scope->next = global_root_scope;
}

/**
 * cf_push_scope - enter new scope
 * @sym: symbol representing scope name
 *
 * If we want to enter a new scope to process declarations inside
 * a nested block, we can just call cf_push_scope() to push a new
 * scope onto the scope stack which will cause all new symbols to be
 * defined in this scope and all existing symbols to be sought for
 * in all scopes stored on the stack.
 */
void
cf_push_scope(struct config *conf, struct symbol *sym)
{
  struct sym_scope *s = cfg_allocz(sizeof(struct sym_scope));

  s->next = conf->current_scope;
  conf->current_scope = s;
  s->active = 1;
  s->name = sym;
  s->slots = 0;
}

/**
 * cf_pop_scope - leave a scope
 *
 * cf_pop_scope() pops the topmost scope from the scope stack,
 * leaving all its symbols in the symbol table, but making them
 * invisible to the rest of the config.
 */
void
cf_pop_scope(struct config *conf)
{
  ASSERT(!conf->current_scope->soft_scopes);

  conf->current_scope->active = 0;
  conf->current_scope = conf->current_scope->next;

  ASSERT(conf->current_scope);
}

/**
 * cf_push_soft_scope - enter new soft scope
 *
 * If we want to enter a new anonymous scope that most likely will not contain
 * any symbols, we can use cf_push_soft_scope() insteas of cf_push_scope().
 * Such scope will be converted to a regular scope on first use.
 */
void
cf_push_soft_scope(struct config *conf)
{
  if (conf->current_scope->soft_scopes < 0xfe)
    conf->current_scope->soft_scopes++;
  else
    cf_push_block_scope(conf);
}

/**
 * cf_pop_soft_scope - leave a soft scope
 *
 * Leave a soft scope entered by cf_push_soft_scope().
 */
void
cf_pop_soft_scope(struct config *conf)
{
  if (conf->current_scope->soft_scopes)
    conf->current_scope->soft_scopes--;
  else
    cf_pop_block_scope(conf);
}

/**
 * cf_swap_soft_scope - convert soft scope to regular scope
 *
 * Soft scopes cannot hold symbols, so they must be converted to regular scopes
 * on first use. It is done automatically by cf_new_symbol().
 */
static inline void
cf_swap_soft_scope(struct config *conf)
{
  if (conf->current_scope->soft_scopes)
  {
    conf->current_scope->soft_scopes--;
    cf_push_block_scope(conf);
  }
}

/**
 * cf_symbol_class_name - get name of a symbol class
 * @sym: symbol
 *
 * This function returns a string representing the class
 * of the given symbol.
 */
char *
cf_symbol_class_name(struct symbol *sym)
{
  switch (sym->class)
    {
    case SYM_VOID:
      return "undefined";
    case SYM_PROTO:
      return "protocol";
    case SYM_TEMPLATE:
      return "protocol template";
    case SYM_FUNCTION:
      return "function";
    case SYM_FILTER:
      return "filter";
    case SYM_TABLE:
      return "routing table";
    case SYM_ATTRIBUTE:
      return "custom attribute";
    case SYM_MPLS_DOMAIN:
      return "MPLS domain";
    case SYM_MPLS_RANGE:
      return "MPLS label range";
    case SYM_CONSTANT_RANGE:
      return "constant";
    case SYM_VARIABLE_RANGE:
      return "variable";
    default:
      return "unknown type";
    }
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

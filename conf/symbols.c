/*
 *	BIRD Internet Routing Daemon -- Symbol Handling
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *	(c) 2018 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "conf/conf.h"
#include "conf/parser.h"
#include "lib/hash.h"

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
cf_push_scope(struct cf_context *ctx, struct symbol *sym)
{
  struct sym_scope *s = cfg_alloc(sizeof(struct sym_scope));

  s->next = ctx->sym_scope;
  ctx->sym_scope = s;
  s->active = 1;
  s->name = sym;
}

/**
 * cf_pop_scope - leave a scope
 *
 * cf_pop_scope() pops the topmost scope from the scope stack,
 * leaving all its symbols in the symbol table, but making them
 * invisible to the rest of the config.
 */
void
cf_pop_scope(struct cf_context *ctx)
{
  ctx->sym_scope->active = 0;
  ctx->sym_scope = ctx->sym_scope->next;
  ASSERT(ctx->sym_scope);
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
  if (cf_symbol_is_constant(sym))
    return "constant";

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
    default:
      return "unknown type";
    }
}

#define SYM_KEY(n)		n->name, n->scope->active
#define SYM_NEXT(n)		n->next
#define SYM_EQ(a,s1,b,s2)	!strcmp(a,b) && s1 == s2
#define SYM_FN(k,s)		cf_hash(k)
#define SYM_ORDER		6 /* Initial */

#define SYM_REHASH		sym_rehash
#define SYM_PARAMS		/8, *1, 2, 2, 6, 20

HASH_DEFINE_REHASH_FN(SYM, struct symbol)


static struct symbol *
cf_new_symbol(struct cf_context *ctx, byte *c)
{
  struct symbol *s;

  uint l = strlen(c);
  if (l > SYM_MAX_LEN)
    cf_error(ctx, "Symbol too long");

  s = cfg_alloc(sizeof(struct symbol) + l);
  s->scope = ctx->sym_scope;
  s->class = SYM_VOID;
  s->def = NULL;
  s->aux = 0;
  strcpy(s->name, c);

  if (!ctx->new_config->sym_hash.data)
    HASH_INIT(ctx->new_config->sym_hash, ctx->new_config->pool, SYM_ORDER);

  HASH_INSERT2(ctx->new_config->sym_hash, SYM, ctx->new_config->pool, s);

  return s;
}

/**
 * cf_find_symbol - find a symbol by name
 * @cfg: specificed config
 * @c: symbol name
 *
 * This functions searches the symbol table in the config @cfg for a symbol of
 * given name. First it examines the current scope, then the second recent one
 * and so on until it either finds the symbol and returns a pointer to its
 * &symbol structure or reaches the end of the scope chain and returns %NULL to
 * signify no match.
 */
struct symbol *
cf_find_symbol(struct config *cfg, byte *c)
{
  struct symbol *s;

  if (cfg->sym_hash.data &&
      (s = HASH_FIND(cfg->sym_hash, SYM, c, 1)))
    return s;

  if (cfg->fallback &&
      cfg->fallback->sym_hash.data &&
      (s = HASH_FIND(cfg->fallback->sym_hash, SYM, c, 1)))
    return s;

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
cf_get_symbol(struct cf_context *ctx, byte *c)
{
  return cf_find_symbol(ctx->new_config, c) ?: cf_new_symbol(ctx, c);
}

struct symbol *
cf_default_name(struct cf_context *ctx, char *template, int *counter)
{
  char buf[SYM_MAX_LEN];
  struct symbol *s;
  char *perc = strchr(template, '%');

  for(;;)
    {
      bsprintf(buf, template, ++(*counter));
      s = cf_get_symbol(ctx, buf);
      if (s->class == SYM_VOID)
	return s;
      if (!perc)
	break;
    }
  cf_error(ctx, "Unable to generate default name");
}

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
 * an error is reported via YY_FATAL_ERROR().
 *
 * Result: Pointer to the newly defined symbol. If we are in the top-level
 * scope, it's the same @sym as passed to the function.
 */
struct symbol *
cf_define_symbol(struct cf_context *ctx, struct symbol *sym, int type, void *def)
{
  if (sym->class)
    {
      if (sym->scope == ctx->sym_scope)
	cf_error(ctx, "Symbol already defined");
      sym = cf_new_symbol(ctx, sym->name);
    }
  sym->class = type;
  sym->def = def;
  return sym;
}

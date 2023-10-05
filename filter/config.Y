/*
 *	BIRD - filters
 *
 *	Copyright 1998--2000 Pavel Machek
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
	FIXME: priority of ! should be lower
 */

CF_HDR

#include "filter/f-inst.h"
#include "filter/data.h"

CF_DEFINES

static inline u32 pair(u32 a, u32 b) { return (a << 16) | b; }
static inline u32 pair_a(u32 p) { return p >> 16; }
static inline u32 pair_b(u32 p) { return p & 0xFFFF; }

static struct symbol *this_function;
static struct sym_scope *this_for_scope;

static struct f_method_scope {
  struct f_inst *object;
  struct sym_scope *main;
  struct sym_scope scope;
} f_method_scope_stack[32];
static int f_method_scope_pos = -1;

#define FM  (f_method_scope_stack[f_method_scope_pos])

static inline void f_method_call_start(struct f_inst *object)
{
  if (object->type == T_VOID)
    cf_error("Can't infer type to properly call a method, please assign the value to a variable");
  if (++f_method_scope_pos >= (int) ARRAY_SIZE(f_method_scope_stack))
    cf_error("Too many nested method calls");

  struct sym_scope *scope = f_type_method_scope(object->type);
  if (!scope)
    cf_error("No methods defined for type %s", f_type_name(object->type));

  FM = (struct f_method_scope) {
    .object = object,
    .main = new_config->current_scope,
    .scope = {
      .next = global_root_scope,
      .hash = scope->hash,
      .active = 1,
      .block = 1,
      .readonly = 1,
    },
  };
  new_config->current_scope = &FM.scope;
}

static inline void f_method_call_args(void)
{
  ASSERT_DIE(FM.scope.active);
  FM.scope.active = 0;

  new_config->current_scope = FM.main;
}

static inline void f_method_call_end(void)
{
  ASSERT_DIE(f_method_scope_pos >= 0);
  if (FM.scope.active) {
    ASSERT_DIE(&FM.scope == new_config->current_scope);
    new_config->current_scope = FM.main;

    FM.scope.active = 0;
  }

  f_method_scope_pos--;
}

static int
f_new_var(struct sym_scope *s)
{
  /*
   * - A variable is an offset on vstack from vbase.
   * - Vbase is set on filter start / function call.
   * - Scopes contain (non-frame) block scopes inside filter/function scope
   * - Each scope knows number of vars in that scope
   * - Offset is therefore a sum of 'slots' up to filter/function scope
   * - New variables are added on top of vstk, so intermediate values cannot
   *   be there during FI_VAR_INIT. I.e. no 'var' inside 'term'.
   * - Also, each f_line must always have its scope, otherwise a variable may
   *   be defined but not initialized if relevant f_line is not executed.
   */

  int offset = s->slots++;

  while (s->block)
  {
    s = s->next;
    ASSERT(s);
    offset += s->slots;
  }

  if (offset >= 0xff)
    cf_error("Too many variables, at most 255 allowed");

  return offset;
}

/*
 * Sets and their items are during parsing handled as lists, linked
 * through left ptr. The first item in a list also contains a pointer
 * to the last item in a list (right ptr). For convenience, even items
 * are handled as one-item lists. Lists are merged by f_merge_items().
 */
static int
f_valid_set_type(int type)
{
  switch (type)
  {
  case T_INT:
  case T_PAIR:
  case T_QUAD:
  case T_ENUM:
  case T_IP:
  case T_EC:
  case T_LC:
  case T_RD:
    return 1;

  default:
    return 0;
  }
}

static inline struct f_tree *
f_new_item(struct f_val from, struct f_val to)
{
  struct f_tree *t = f_new_tree();
  t->right = t;
  t->from = from;
  t->to = to;
  return t;
}

static inline struct f_tree *
f_merge_items(struct f_tree *a, struct f_tree *b)
{
  if (!a) return b;
  a->right->left = b;
  a->right = b->right;
  b->right = NULL;
  return a;
}

static inline struct f_tree *
f_new_pair_item(int fa, int ta, int fb, int tb)
{
  check_u16(fa);
  check_u16(ta);
  check_u16(fb);
  check_u16(tb);

  if ((ta < fa) || (tb < fb))
    cf_error( "From value cannot be higher that To value in pair sets");

  struct f_tree *t = f_new_tree();
  t->right = t;
  t->from.type = t->to.type = T_PAIR;
  t->from.val.i = pair(fa, fb);
  t->to.val.i = pair(ta, tb);
  return t;
}

static inline struct f_tree *
f_new_pair_set(int fa, int ta, int fb, int tb)
{
  check_u16(fa);
  check_u16(ta);
  check_u16(fb);
  check_u16(tb);

  if ((ta < fa) || (tb < fb))
    cf_error( "From value cannot be higher that To value in pair sets");

  struct f_tree *lst = NULL;
  int i;

  for (i = fa; i <= ta; i++)
    lst = f_merge_items(lst, f_new_pair_item(i, i, fb, tb));

  return lst;
}

#define CC_ALL 0xFFFF
#define EC_ALL 0xFFFFFFFF
#define LC_ALL 0xFFFFFFFF

static struct f_tree *
f_new_ec_item(u32 kind, u32 ipv4_used, u32 key, u32 vf, u32 vt)
{
  u64 fm, to;

  if ((kind != EC_GENERIC) && (ipv4_used || (key >= 0x10000))) {
    check_u16(vf);
    if (vt == EC_ALL)
      vt = 0xFFFF;
    else
      check_u16(vt);
  }

  if (kind == EC_GENERIC) {
    fm = ec_generic(key, vf);
    to = ec_generic(key, vt);
  }
  else if (ipv4_used) {
    fm = ec_ip4(kind, key, vf);
    to = ec_ip4(kind, key, vt);
  }
  else if (key < 0x10000) {
    fm = ec_as2(kind, key, vf);
    to = ec_as2(kind, key, vt);
  }
  else {
    fm = ec_as4(kind, key, vf);
    to = ec_as4(kind, key, vt);
  }

  struct f_tree *t = f_new_tree();
  t->right = t;
  t->from.type = t->to.type = T_EC;
  t->from.val.ec = fm;
  t->to.val.ec = to;
  return t;
}

static struct f_tree *
f_new_lc_item(u32 f1, u32 t1, u32 f2, u32 t2, u32 f3, u32 t3)
{
  struct f_tree *t = f_new_tree();
  t->right = t;
  t->from.type = t->to.type = T_LC;
  t->from.val.lc = (lcomm) {f1, f2, f3};
  t->to.val.lc = (lcomm) {t1, t2, t3};
  return t;
}

static inline struct f_inst *
f_const_empty(enum f_type t)
{
  switch (t) {
    case T_PATH:
    case T_CLIST:
    case T_ECLIST:
    case T_LCLIST:
      return f_new_inst(FI_CONSTANT, (struct f_val) {
	.type = t,
	.val.ad = &null_adata,
      });
    case T_ROUTE:
      return f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_ROUTE });
    default:
      return f_new_inst(FI_CONSTANT, (struct f_val) {});
  }
}

/*
 * Remove all new lines and doubled whitespaces
 * and convert all tabulators to spaces
 * and return a copy of string
 */
char *
assert_copy_expr(const char *start, size_t len)
{
  /* XXX: Allocates maybe a little more memory than we really finally need */
  char *str = cfg_alloc(len + 1);

  char *dst = str;
  const char *src = start - 1;
  const char *end = start + len;
  while (++src < end)
  {
    if (*src == '\n')
      continue;

    /* Skip doubled whitespaces */
    if (src != start)
    {
      const char *prev = src - 1;
      if ((*src == ' ' || *src == '\t') && (*prev == ' ' || *prev == '\t'))
	continue;
    }

    if (*src == '\t')
      *dst = ' ';
    else
      *dst = *src;

    dst++;
  }
  *dst = '\0';

  return str;
}

/*
 * assert_done - create f_instruction of bt_assert
 * @expr: expression in bt_assert()
 * @start: pointer to first char of test expression
 * @end: pointer to the last char of test expression
 */
static struct f_inst *
assert_done(struct f_inst *expr, const char *start, const char *end)
{
  return f_new_inst(FI_ASSERT, expr,
    (end >= start) ?
      assert_copy_expr(start, end - start + 1)
    : "???");
}

static struct f_inst *
f_lval_getter(struct f_lval *lval)
{
  switch (lval->type) {
    case F_LVAL_VARIABLE:	return f_new_inst(FI_VAR_GET, lval->sym);
    case F_LVAL_SA:		return f_new_inst(FI_RTA_GET, lval->rte, lval->sa);
    case F_LVAL_EA:		return f_new_inst(FI_EA_GET, lval->rte, lval->da);
    default:			bug("Unknown lval type");
  }
}

static struct f_inst *
f_lval_setter(struct f_lval *lval, struct f_inst *expr)
{
  switch (lval->type) {
    case F_LVAL_VARIABLE:	return f_new_inst(FI_VAR_SET, expr, lval->sym);
    case F_LVAL_SA:		return f_new_inst(FI_RTA_SET, expr, lval->sa);
    case F_LVAL_EA:		return f_new_inst(FI_EA_SET, expr, lval->da);
    default:			bug("Unknown lval type");
  }
}

static struct f_inst *
assert_assign(struct f_lval *lval, struct f_inst *expr, const char *start, const char *end)
{
  struct f_inst *setter = f_lval_setter(lval, expr),
		*getter = f_lval_getter(lval);

  struct f_inst *checker = f_new_inst(FI_EQ, expr, getter);
  setter->next = checker;

  return assert_done(setter, start, end);
}

CF_DECLS

CF_KEYWORDS_EXCLUSIVE(IN)
CF_KEYWORDS(FUNCTION, PRINT, PRINTN, UNSET, RETURN,
	ACCEPT, REJECT, ERROR,
	INT, BOOL, IP, PREFIX, RD, PAIR, QUAD, EC, LC,
	SET, STRING, BYTESTRING, BGPMASK, BGPPATH, CLIST, ECLIST, LCLIST,
	IF, THEN, ELSE, CASE,
	FOR, DO,
	TRUE, FALSE, RT, RO, UNKNOWN, GENERIC,
	FROM, GW, NET, PROTO, SOURCE, SCOPE, DEST, IFNAME, IFINDEX, WEIGHT, GW_MPLS, ONLINK,
	PREFERENCE,
	ROA_CHECK,
	DEFINED,
	ADD, DELETE, RESET,
	PREPEND,
	EMPTY,
	FILTER, WHERE, EVAL, ATTRIBUTE,
	FROM_HEX,
	BT_ASSERT, BT_TEST_SUITE, BT_CHECK_ASSIGN, BT_TEST_SAME, FORMAT)

%nonassoc THEN
%nonassoc ELSE

%type <xp> cmds_int cmd_prep
%type <x> term term_bs cmd cmd_var cmds cmds_scoped constant constructor var var_list var_list_r function_call symbol_value bgp_path_expr bgp_path bgp_path_tail term_dot_method method_name_cont
%type <fda> dynamic_attr
%type <fsa> static_attr
%type <f> filter where_filter
%type <fl> filter_body function_body
%type <flv> lvalue
%type <i> type function_vars function_type
%type <fa> function_argsn function_args
%type <ecs> ec_kind
%type <fret> break_command
%type <i32> cnum
%type <e> pair_item ec_item lc_item set_item switch_item ec_items set_items switch_items switch_body
%type <trie> fprefix_set
%type <v> set_atom switch_atom fipa
%type <px> fprefix
%type <t> get_cf_position
%type <s> for_var

CF_GRAMMAR

conf: filter_def ;
filter_def:
   FILTER symbol {
     $2 = cf_define_symbol(new_config, $2, SYM_FILTER, filter, NULL);
     cf_push_scope( new_config, $2 );
     this_function = NULL;
   } filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .sym = $2, .root = $4 };
     $2->filter = f;

     cf_pop_scope(new_config);
   }
 ;

conf: filter_eval ;
filter_eval:
   EVAL term { cf_eval_int($2); }
 ;

conf: custom_attr ;
custom_attr: ATTRIBUTE type symbol ';' {
  cf_define_symbol(new_config, $3, SYM_ATTRIBUTE, attribute, ca_lookup(new_config->pool, $3->name, $2)->fda);
};

conf: bt_test_suite ;
bt_test_suite:
 BT_TEST_SUITE '(' symbol_known ',' text ')' {
  cf_assert_symbol($3, SYM_FUNCTION);
  struct f_bt_test_suite *t = cfg_allocz(sizeof(struct f_bt_test_suite));
  t->fn = $3->function;
  t->fn_name = $3->name;
  t->dsc = $5;

  add_tail(&new_config->tests, &t->n);
 }
 ;

conf: bt_test_same ;
bt_test_same:
 BT_TEST_SAME '(' symbol_known ',' symbol_known ',' NUM ')' {
  cf_assert_symbol($3, SYM_FUNCTION);
  cf_assert_symbol($5, SYM_FUNCTION);
  struct f_bt_test_suite *t = cfg_allocz(sizeof(struct f_bt_test_suite));
  t->fn = $3->function;
  t->cmp = $5->function;
  t->result = $7;
  t->fn_name = $3->name;
  t->dsc = $5->name;
  add_tail(&new_config->tests, &t->n);
 }
 ;

type:
   INT { $$ = T_INT; }
 | BOOL { $$ = T_BOOL; }
 | IP { $$ = T_IP; }
 | RD { $$ = T_RD; }
 | PREFIX { $$ = T_NET; }
 | PAIR { $$ = T_PAIR; }
 | QUAD { $$ = T_QUAD; }
 | EC { $$ = T_EC; }
 | LC { $$ = T_LC; }
 | STRING { $$ = T_STRING; }
 | BYTESTRING { $$ = T_BYTESTRING; }
 | BGPMASK { $$ = T_PATH_MASK; }
 | BGPPATH { $$ = T_PATH; }
 | CLIST { $$ = T_CLIST; }
 | ECLIST { $$ = T_ECLIST; }
 | LCLIST { $$ = T_LCLIST; }
 | ROUTE { $$ = T_ROUTE; }
 | type SET {
	switch ($1) {
	  case T_INT:
	  case T_PAIR:
	  case T_QUAD:
	  case T_EC:
	  case T_LC:
	  case T_RD:
	  case T_IP:
	       $$ = T_SET;
	       break;

	  case T_NET:
	       $$ = T_PREFIX_SET;
	    break;

	  default:
		cf_error( "You can't create sets of this type." );
	}
   }
 ;

function_argsn:
   /* EMPTY */ { $$ = NULL; }
 | function_argsn type symbol ';' {
     if ($3->scope->slots >= 0xfe) cf_error("Too many declarations, at most 255 allowed");
     $$ = cfg_alloc(sizeof(struct f_arg));
     $$->arg = cf_define_symbol(new_config, $3, SYM_VARIABLE | $2, offset, sym_->scope->slots++);
     $$->next = $1;
   }
 ;

function_args:
   '(' ')' { $$ = NULL; }
 | '(' function_argsn type symbol ')' {
     $$ = cfg_alloc(sizeof(struct f_arg));
     $$->arg = cf_define_symbol(new_config, $4, SYM_VARIABLE | $3, offset, sym_->scope->slots++);
     $$->next = $2;
   }
 ;

function_vars:
   /* EMPTY */ { $$ = 0; }
 | function_vars type symbol ';' {
     cf_define_symbol(new_config, $3, SYM_VARIABLE | $2, offset, f_new_var(sym_->scope));
     $$ = $1 + 1;
   }
 ;

function_type:
   /* EMPTY */ { $$ = T_VOID; }
 | IMP type { $$ = $2; }
 ;

filter_body: function_body ;

filter:
   symbol_known {
     cf_assert_symbol($1, SYM_FILTER);
     $$ = $1->filter;
   }
 | {
     cf_push_scope(new_config, NULL);
     this_function = NULL;
   } filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .root = $2 };
     $$ = f;

     cf_pop_scope(new_config);
   }
 ;

where_filter:
   WHERE term {
     /* Construct 'IF term THEN { ACCEPT; } ELSE { REJECT; }' */
     $$ = f_new_where($2);
   }
 ;

function_body:
   function_vars '{' cmds '}' {
     $$ = f_linearize($3, 0);
     $$->vars = $1;
   }
 ;

conf: function_def ;

function_def:
   FUNCTION symbol {
     DBG( "Beginning of function %s\n", $2->name );
     this_function = cf_define_symbol(new_config, $2, SYM_FUNCTION, function, NULL);
     cf_push_scope(new_config, this_function);
   } function_args function_type {
     /* Make dummy f_line for storing function prototype */
     struct f_line *dummy = cfg_allocz(sizeof(struct f_line));
     this_function->function = dummy;

     dummy->return_type = $5;

     /* Revert the args */
     while ($4) {
       struct f_arg *tmp = $4;
       $4 = $4->next;

       tmp->next = dummy->arg_list;
       dummy->arg_list = tmp;
       dummy->args++;
     }
   } function_body {
     $7->args = this_function->function->args;
     $7->arg_list = this_function->function->arg_list;
     $7->return_type = this_function->function->return_type;
     $2->function = $7;
     cf_pop_scope(new_config);
   }
 ;

/* Programs */

cmds: /* EMPTY */ { $$ = NULL; }
 | cmds_int { $$ = $1.begin; }
 ;

cmds_scoped: { cf_push_soft_scope(new_config); } cmds { cf_pop_soft_scope(new_config); $$ = $2; } ;

cmd_var: var | cmd ;

cmd_prep: cmd_var {
  $$.begin = $$.end = $1;
  if ($1)
    while ($$.end->next)
      $$.end = $$.end->next;
}
 ;

cmds_int: cmd_prep
 | cmds_int cmd_prep {
  if (!$1.begin)
    $$ = $2;
  else if (!$2.begin)
    $$ = $1;
  else {
    $$.begin = $1.begin;
    $$.end = $2.end;
    $1.end->next = $2.begin;
  }
 }
 ;

/*
 * Complex types, their bison value is struct f_val
 */
fipa:
   IP4 %prec PREFIX_DUMMY { $$.type = T_IP; $$.val.ip = ipa_from_ip4($1); }
 | IP6 %prec PREFIX_DUMMY { $$.type = T_IP; $$.val.ip = ipa_from_ip6($1); }
 ;



/*
 * Set constants. They are also used in switch cases. We use separate
 * nonterminals for switch (set_atom/switch_atom, set_item/switch_item ...)
 * to elude a collision between symbol (in expr) in set_atom and symbol
 * as a function call in switch case cmds.
 */

set_atom:
   NUM    { $$.type = T_INT; $$.val.i = $1; }
 | fipa   { $$ = $1; }
 | VPN_RD { $$.type = T_RD; $$.val.ec = $1; }
 | ENUM   { $$.type = pair_a($1); $$.val.i = pair_b($1); }
 | '(' term ')' {
     $$ = cf_eval($2, T_VOID);
     if (!f_valid_set_type($$.type)) cf_error("Set-incompatible type");
   }
 | symbol_known {
     cf_assert_symbol($1, SYM_CONSTANT);
     if (!f_valid_set_type(SYM_TYPE($1))) cf_error("%s: set-incompatible type", $1->name);
     $$ = *$1->val;
   }
 ;

switch_atom:
   NUM   { $$.type = T_INT; $$.val.i = $1; }
 | '(' term ')' { $$ = cf_eval($2, T_INT); }
 | fipa  { $$ = $1; }
 | ENUM  { $$.type = pair_a($1); $$.val.i = pair_b($1); }
 ;

cnum:
   term { $$ = cf_eval_int($1); }

pair_item:
   '(' cnum ',' cnum ')'		{ $$ = f_new_pair_item($2, $2, $4, $4); }
 | '(' cnum ',' cnum DDOT cnum ')'	{ $$ = f_new_pair_item($2, $2, $4, $6); }
 | '(' cnum ',' '*' ')'			{ $$ = f_new_pair_item($2, $2, 0, CC_ALL); }
 | '(' cnum DDOT cnum ',' cnum ')'	{ $$ = f_new_pair_set($2, $4, $6, $6); }
 | '(' cnum DDOT cnum ',' cnum DDOT cnum ')' { $$ = f_new_pair_set($2, $4, $6, $8); }
 | '(' cnum DDOT cnum ',' '*' ')'	{ $$ = f_new_pair_item($2, $4, 0, CC_ALL); }
 | '(' '*' ',' cnum ')'			{ $$ = f_new_pair_set(0, CC_ALL, $4, $4); }
 | '(' '*' ',' cnum DDOT cnum ')'	{ $$ = f_new_pair_set(0, CC_ALL, $4, $6); }
 | '(' '*' ',' '*' ')'			{ $$ = f_new_pair_item(0, CC_ALL, 0, CC_ALL); }
 | '(' cnum ',' cnum ')' DDOT '(' cnum ',' cnum ')'
   { $$ = f_new_pair_item($2, $8, $4, $10); }
 ;

ec_kind:
   RT { $$ = EC_RT; }
 | RO { $$ = EC_RO; }
 | UNKNOWN NUM { $$ = $2; }
 | GENERIC { $$ = EC_GENERIC; }
 ;

ec_item:
   '(' ec_kind ',' cnum ',' cnum ')'		{ $$ = f_new_ec_item($2, 0, $4, $6, $6); }
 | '(' ec_kind ',' cnum ',' cnum DDOT cnum ')'	{ $$ = f_new_ec_item($2, 0, $4, $6, $8); }
 | '(' ec_kind ',' cnum ',' '*' ')'		{ $$ = f_new_ec_item($2, 0, $4, 0, EC_ALL); }
 ;

lc_item:
   '(' cnum ',' cnum ',' cnum ')'	    { $$ = f_new_lc_item($2, $2, $4, $4, $6, $6); }
 | '(' cnum ',' cnum ',' cnum DDOT cnum ')' { $$ = f_new_lc_item($2, $2, $4, $4, $6, $8); }
 | '(' cnum ',' cnum ',' '*' ')'	    { $$ = f_new_lc_item($2, $2, $4, $4, 0, LC_ALL); }
 | '(' cnum ',' cnum DDOT cnum ',' '*' ')'  { $$ = f_new_lc_item($2, $2, $4, $6, 0, LC_ALL); }
 | '(' cnum ',' '*' ',' '*' ')'		    { $$ = f_new_lc_item($2, $2, 0, LC_ALL, 0, LC_ALL); }
 | '(' cnum DDOT cnum ',' '*' ',' '*' ')'   { $$ = f_new_lc_item($2, $4, 0, LC_ALL, 0, LC_ALL); }
 | '(' '*' ',' '*' ',' '*' ')'		    { $$ = f_new_lc_item(0, LC_ALL, 0, LC_ALL, 0, LC_ALL); }
 | '(' cnum ',' cnum ',' cnum ')' DDOT '(' cnum ',' cnum ',' cnum ')'
   { $$ = f_new_lc_item($2, $10, $4, $12, $6, $14); }
;

set_item:
   pair_item
 | ec_item
 | lc_item
 | set_atom { $$ = f_new_item($1, $1); }
 | set_atom DDOT set_atom { $$ = f_new_item($1, $3); }
 ;

switch_item:
   pair_item
 | ec_item
 | lc_item
 | switch_atom { $$ = f_new_item($1, $1); }
 | switch_atom DDOT switch_atom { $$ = f_new_item($1, $3); }
 ;

ec_items:
   ec_item
 | ec_items ',' ec_item { $$ = f_merge_items($1, $3); }
 ;

set_items:
   set_item
 | set_items ',' set_item { $$ = f_merge_items($1, $3); }
 ;

switch_items:
   switch_item
 | switch_items ',' switch_item { $$ = f_merge_items($1, $3); }
 ;

fprefix:
   net_ip_	{ $$.net = $1; $$.lo = $1.pxlen; $$.hi = $1.pxlen; }
 | net_ip_ '+'	{ $$.net = $1; $$.lo = $1.pxlen; $$.hi = net_max_prefix_length[$1.type]; }
 | net_ip_ '-'	{ $$.net = $1; $$.lo = 0; $$.hi = $1.pxlen; }
 | net_ip_ '{' NUM ',' NUM '}' {
     $$.net = $1; $$.lo = $3; $$.hi = $5;
     if (($3 > $5) || ($5 > net_max_prefix_length[$1.type]))
       cf_error("Invalid prefix pattern range: {%u, %u}", $3, $5);
   }
 ;

fprefix_set:
   fprefix { $$ = f_new_trie(cfg_mem, 0); trie_add_prefix($$, &($1.net), $1.lo, $1.hi); }
 | fprefix_set ',' fprefix { $$ = $1; if (!trie_add_prefix($$, &($3.net), $3.lo, $3.hi)) cf_error("Mixed IPv4/IPv6 prefixes in prefix set"); }
 ;

switch_body: /* EMPTY */ { $$ = NULL; }
 | switch_body switch_items ':' cmds_scoped  {
     /* Fill data fields */
     struct f_tree *t;
     for (t = $2; t; t = t->left)
       t->data = $4;
     $$ = f_merge_items($1, $2);
   }
 | switch_body ELSECOL cmds_scoped {
     struct f_tree *t = f_new_tree();
     t->from.type = t->to.type = T_VOID;
     t->right = t;
     t->data = $3;
     $$ = f_merge_items($1, t);
 }
 ;

bgp_path_expr:
   symbol_value { $$ = $1; }
 | '(' term ')' { $$ = $2; }
 ;

bgp_path:
   PO  bgp_path_tail PC  { $$ = $2; }
 ;

bgp_path_tail:
   NUM bgp_path_tail		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .asn = $1, .kind = PM_ASN, }, }); $$->next = $2;  }
 | NUM DDOT NUM bgp_path_tail	{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .from = $1, .to = $3, .kind = PM_ASN_RANGE }, }); $$->next = $4; }
 | '[' ']' bgp_path_tail { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .set = NULL, .kind = PM_ASN_SET }, }); $$->next = $3; }
 | '[' set_items ']' bgp_path_tail {
   if ($2->from.type != T_INT) cf_error("Only integer sets allowed in path mask");
   $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .set = build_tree($2), .kind = PM_ASN_SET }, }); $$->next = $4;
 }
 | '*' bgp_path_tail		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .kind = PM_ASTERISK }, }); $$->next = $2; }
 | '?' bgp_path_tail		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .kind = PM_QUESTION }, }); $$->next = $2; }
 | '+' bgp_path_tail 		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .kind = PM_LOOP }, }); $$->next = $2; }
 | bgp_path_expr bgp_path_tail	{ $$ = $1; $$->next = $2; }
 | 				{ $$ = NULL; }
 ;

constant:
   NUM      { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_INT, .val.i = $1, }); }
 | TRUE     { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_BOOL, .val.i = 1, }); }
 | FALSE    { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_BOOL, .val.i = 0, }); }
 | TEXT     { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_STRING, .val.s = $1, }); }
 | BYTETEXT { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_BYTESTRING, .val.bs = $1, }); }
 | fipa     { $$ = f_new_inst(FI_CONSTANT, $1); }
 | VPN_RD   { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_RD, .val.ec = $1, }); }
 | net_     { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_NET, .val.net = $1, }); }
 | '[' ']' { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_SET, .val.t = NULL, }); }
 | '[' set_items ']' {
     DBG( "We've got a set here..." );
     $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_SET, .val.t = build_tree($2), });
     DBG( "ook\n" );
 }
 | '[' fprefix_set ']' { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PREFIX_SET, .val.ti = $2, }); }
 | ENUM	  { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = $1 >> 16, .val.i = $1 & 0xffff, }); }
 ;

constructor:
   '(' term ',' term ')' { $$ = f_new_inst(FI_PAIR_CONSTRUCT, $2, $4); }
 | '(' ec_kind ',' term ',' term ')' { $$ = f_new_inst(FI_EC_CONSTRUCT, $4, $6, $2); }
 | '(' term ',' term ',' term ')' { $$ = f_new_inst(FI_LC_CONSTRUCT, $2, $4, $6); }
 | bgp_path { $$ = f_new_inst(FI_PATHMASK_CONSTRUCT, $1); }
 ;


/* This generates the function_call variable list backwards */
var_list_r:
   /* EMPTY */ { $$ = NULL; }
 | term { $$ = $1; }
 | var_list_r ',' term { $$ = $3; $$->next = $1; }
 ;

var_list: var_list_r
   {
     $$ = NULL;

     /* Revert the var_list_r */
     while ($1) {
       struct f_inst *tmp = $1;
       $1 = $1->next;

       tmp->next = $$;
       $$ = tmp;
     }
   }
 ;

function_call:
   symbol_known '(' var_list ')'
   {
     if ($1->class != SYM_FUNCTION)
       cf_error("You can't call something which is not a function. Really.");

     $$ = f_new_inst(FI_CALL, $3, $1);
   }
 ;

symbol_value: symbol_known
  {
    switch ($1->class) {
      case SYM_CONSTANT_RANGE:
	$$ = f_new_inst(FI_CONSTANT, *($1->val));
	break;
      case SYM_VARIABLE_RANGE:
	$$ = f_new_inst(FI_VAR_GET, $1);
	break;
      case SYM_ATTRIBUTE:
	$$ = f_new_inst(FI_EA_GET, f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_ROUTE, .val.rte = NULL }), *$1->attribute);
	break;
      default:
	cf_error("Can't get value of symbol %s", $1->name);
    }
  }
 ;

static_attr:
   FROM    { $$ = f_new_static_attr(T_IP,         SA_FROM,	0); }
 | GW      { $$ = f_new_static_attr(T_IP,         SA_GW,	0); }
 | NET     { $$ = f_new_static_attr(T_NET,	  SA_NET,	1); }
 | PROTO   { $$ = f_new_static_attr(T_STRING,     SA_PROTO,	1); }
 | SOURCE  { $$ = f_new_static_attr(T_ENUM_RTS,   SA_SOURCE,	1); }
 | SCOPE   { $$ = f_new_static_attr(T_ENUM_SCOPE, SA_SCOPE,	0); }
 | DEST    { $$ = f_new_static_attr(T_ENUM_RTD,   SA_DEST,	0); }
 | IFNAME  { $$ = f_new_static_attr(T_STRING,     SA_IFNAME,	0); }
 | IFINDEX { $$ = f_new_static_attr(T_INT,        SA_IFINDEX,	1); }
 | WEIGHT  { $$ = f_new_static_attr(T_INT,        SA_WEIGHT,	0); }
 | PREFERENCE { $$ = f_new_static_attr(T_INT,	  SA_PREF,	0); }
 | GW_MPLS { $$ = f_new_static_attr(T_INT,        SA_GW_MPLS,	0); }
 | ONLINK  { $$ = f_new_static_attr(T_BOOL,       SA_ONLINK,	0); }
 ;

term_dot_method: term '.' { f_method_call_start($1); } method_name_cont { f_method_call_end(); $$ = $4; };
method_name_cont:
   CF_SYM_METHOD_BARE {
     $$ = f_dispatch_method($1, FM.object, NULL, 1);
   }
 | CF_SYM_METHOD_ARGS {
     f_method_call_args();
   } '(' var_list ')' {
     $$ = f_dispatch_method($1, FM.object, $4, 1);
   }
 | static_attr {
     if (FM.object->type != T_ROUTE)
       cf_error("Getting a route attribute from %s, need a route", f_type_name(FM.object->type));
     $$ = f_new_inst(FI_RTA_GET, FM.object, $1);
   }
 | dynamic_attr {
     if (FM.object->type != T_ROUTE)
       cf_error("Getting a route attribute from %s, need a route", f_type_name(FM.object->type));
     $$ = f_new_inst(FI_EA_GET, FM.object, $1);
   }
 ;

term:
   '(' term ')'		{ $$ = $2; }
 | term '+' term	{ $$ = f_new_inst(FI_ADD, $1, $3); }
 | term '-' term	{ $$ = f_new_inst(FI_SUBTRACT, $1, $3); }
 | term '*' term	{ $$ = f_new_inst(FI_MULTIPLY, $1, $3); }
 | term '/' term	{ $$ = f_new_inst(FI_DIVIDE, $1, $3); }
 | term AND term	{ $$ = f_new_inst(FI_AND, $1, $3); }
 | term OR  term	{ $$ = f_new_inst(FI_OR, $1, $3); }
 | term '=' term	{ $$ = f_new_inst(FI_EQ, $1, $3); }
 | term NEQ term	{ $$ = f_new_inst(FI_NEQ, $1, $3); }
 | term '<' term	{ $$ = f_new_inst(FI_LT, $1, $3); }
 | term LEQ term	{ $$ = f_new_inst(FI_LTE, $1, $3); }
 | term '>' term	{ $$ = f_new_inst(FI_LT, $3, $1); }
 | term GEQ term	{ $$ = f_new_inst(FI_LTE, $3, $1); }
 | term '~' term	{ $$ = f_new_inst(FI_MATCH, $1, $3); }
 | term NMA term	{ $$ = f_new_inst(FI_NOT_MATCH, $1, $3); }
 | '!' term		{ $$ = f_new_inst(FI_NOT, $2); }
 | DEFINED '(' term ')' { $$ = f_new_inst(FI_DEFINED, $3); }

 | symbol_value   { $$ = $1; }
 | constant { $$ = $1; }
 | constructor { $$ = $1; }

 | static_attr { $$ = f_new_inst(FI_RTA_GET, f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_ROUTE, .val.rte = NULL }), $1); }

 | dynamic_attr { $$ = f_new_inst(FI_EA_GET, f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_ROUTE, .val.rte = NULL }), $1); }

 | term_dot_method

 | '+' EMPTY '+' { $$ = f_new_inst(FI_CONSTANT, val_empty(T_PATH)); }
 | '-' EMPTY '-' { $$ = f_new_inst(FI_CONSTANT, val_empty(T_CLIST)); }
 | '-' '-' EMPTY '-' '-' { $$ = f_new_inst(FI_CONSTANT, val_empty(T_ECLIST)); }
 | '-' '-' '-' EMPTY '-' '-' '-' { $$ = f_new_inst(FI_CONSTANT, val_empty(T_LCLIST)); }

| PREPEND '(' term ',' term ')' { $$ = f_dispatch_method_x("prepend", $3->type, $3, $5); }
 | ADD '(' term ',' term ')' { $$ = f_dispatch_method_x("add", $3->type, $3, $5); }
 | DELETE '(' term ',' term ')' { $$ = f_dispatch_method_x("delete", $3->type, $3, $5); }
 | FILTER '(' term ',' term ')' { $$ = f_dispatch_method_x("filter", $3->type, $3, $5); }

 | ROA_CHECK '(' rtable ')' { $$ = f_new_inst(FI_ROA_CHECK_IMPLICIT, $3); }
 | ROA_CHECK '(' rtable ',' term ',' term ')' { $$ = f_new_inst(FI_ROA_CHECK_EXPLICIT, $5, $7, $3); }

 | FORMAT '(' term ')' {  $$ = f_new_inst(FI_FORMAT, $3); }

 | term_bs
 | function_call
 ;

term_bs:
   FROM_HEX '(' term ')' { $$ = f_new_inst(FI_FROM_HEX, $3); }
 ;

break_command:
   ACCEPT { $$ = F_ACCEPT; }
 | REJECT { $$ = F_REJECT; }
 | ERROR { $$ = F_ERROR; }
 ;

var:
   type symbol '=' term ';' {
     struct symbol *sym = cf_define_symbol(new_config, $2, SYM_VARIABLE | $1, offset, f_new_var(sym_->scope));
     $$ = f_new_inst(FI_VAR_INIT, $4, sym);
   }
 | type symbol ';' {
     struct symbol *sym = cf_define_symbol(new_config, $2, SYM_VARIABLE | $1, offset, f_new_var(sym_->scope));
     $$ = f_new_inst(FI_VAR_INIT0, sym);
   }
 ;

for_var:
   type symbol { $$ = cf_define_symbol(new_config, $2, SYM_VARIABLE | $1, offset, f_new_var(sym_->scope)); }
 | CF_SYM_KNOWN { cf_error("Use of a pre-defined variable in for loop is not allowed"); }
 ;

cmd:
   '{' cmds_scoped '}' {
     $$ = $2;
   }
 | IF term THEN cmd {
     $$ = f_new_inst(FI_CONDITION, $2, $4, NULL);
   }
 | IF term THEN cmd ELSE cmd {
     $$ = f_new_inst(FI_CONDITION, $2, $4, $6);
   }
 | FOR {
     /* Reserve space for walk data on stack */
     cf_push_block_scope(new_config);
     new_config->current_scope->slots += 2;
   } for_var IN
   /* Parse term in the parent scope */
   { this_for_scope = new_config->current_scope; new_config->current_scope = this_for_scope->next; }
   term
   { new_config->current_scope = this_for_scope; this_for_scope = NULL; }
   DO cmd {
     cf_pop_block_scope(new_config);
     $$ = f_for_cycle($3, $6, $9);
   }
 | symbol_known '=' term ';' {
     switch ($1->class) {
       case SYM_VARIABLE_RANGE:
	 $$ = f_new_inst(FI_VAR_SET, $3, $1);
	 break;
       case SYM_ATTRIBUTE:
	 $$ = f_new_inst(FI_EA_SET, $3, *$1->attribute);
	 break;
       default:
	 cf_error("Can't assign to symbol %s", $1->name);
     }
   }
 | RETURN term ';' {
     DBG( "Ook, we'll return the value\n" );
     if (!this_function)
       cf_error("Can't return from a non-function, use accept or reject instead.");
     if (this_function->function->return_type == T_VOID)
     {
       if ($2->type != T_VOID)
	 cf_warn("Inferring function %s return type from its return value: %s", this_function->name, f_type_name($2->type));
       ((struct f_line *) this_function->function)->return_type = $2->type;
     }
     else if (this_function->function->return_type != $2->type)
       cf_error("Can't return type %s from function %s, expected %s",
		f_type_name($2->type), this_function->name, f_type_name(this_function->function->return_type));

     $$ = f_new_inst(FI_RETURN, $2);
   }
 | dynamic_attr '=' term ';' {
     $$ = f_new_inst(FI_EA_SET, $3, $1);
   }
 | static_attr '=' term ';' {
     if ($1.readonly)
       cf_error( "This static attribute is read-only.");
     $$ = f_new_inst(FI_RTA_SET, $3, $1);
   }
 | UNSET '(' dynamic_attr ')' ';' {
     $$ = f_new_inst(FI_EA_UNSET, $3);
   }
 | UNSET '(' symbol_known ')' ';' {
     switch ($3->class) {
       case SYM_ATTRIBUTE:
	 $$ = f_new_inst(FI_EA_UNSET, *$3->attribute);
	 break;
       default:
	 cf_error("Can't unset symbol %s", $3->name);
     }
 }
 | break_command var_list_r ';' {
    $$ = f_print($2, !!$2, $1);
   }
 | PRINT var_list_r ';' {
    $$ = f_print($2, 1, F_NOP);
   }
 | PRINTN var_list_r ';' {
    $$ = f_print($2, 0, F_NOP);
   }
 | function_call ';' { $$ = f_new_inst(FI_DROP_RESULT, $1); }
 | CASE term '{' switch_body '}' {
      $$ = f_new_inst(FI_SWITCH, $2, $4);
   }
 | lvalue '.' {
     f_method_call_start(f_lval_getter(&$1));
   } method_name_cont ';' {
     f_method_call_end();
     $$ = f_lval_setter(&$1, $4);
   }
 | BT_ASSERT '(' get_cf_position term get_cf_position ')' ';' { $$ = assert_done($4, $3 + 1, $5 - 1); }
 | BT_CHECK_ASSIGN '(' get_cf_position lvalue get_cf_position ',' term ')' ';' { $$ = assert_assign(&$4, $7, $3 + 1, $5 - 1); }
 ;

get_cf_position:
{
  $$ = cf_text;
};

lvalue:
   CF_SYM_KNOWN {
     switch ($1->class)
     {
       case SYM_VARIABLE_RANGE:
	 $$ = (struct f_lval) { .type = F_LVAL_VARIABLE, .sym = $1, .rte = f_const_empty(T_ROUTE) };
         break;
       case SYM_ATTRIBUTE:
         $$ = (struct f_lval) { .type = F_LVAL_EA, .da = *($1->attribute), .rte = f_const_empty(T_ROUTE) };
	 break;
       default:
	 cf_error("Variable name or custom attribute name required");
     }
   }
 | static_attr { $$ = (struct f_lval) { .type = F_LVAL_SA, .sa = $1, .rte = f_const_empty(T_ROUTE) }; }
 | dynamic_attr { $$ = (struct f_lval) { .type = F_LVAL_EA, .da = $1, .rte = f_const_empty(T_ROUTE) }; }
 ;

CF_END

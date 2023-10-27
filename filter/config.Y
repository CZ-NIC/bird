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

static struct f_method_scope {
  struct f_inst *object;
} f_method_scope_stack[32];
static int f_method_scope_pos = -1;

#define FM  (f_method_scope_stack[f_method_scope_pos])

static inline void f_push_method_scope(struct f_inst *object)
{
  if (++f_method_scope_pos >= (int) ARRAY_SIZE(f_method_scope_stack))
    cf_error("Too many nested method calls");
  FM = (struct f_method_scope) {
    .object = object,
  };
}

static inline void f_pop_method_scope(void)
{
  ASSERT_DIE(f_method_scope_pos >= 0);
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
f_generate_empty(const struct symbol *sym)
{
  if (sym->class != SYM_ATTRIBUTE)
    cf_error("Can't empty %s: not an attribute", sym->name);

  const struct ea_class *def = sym->attribute;
  const struct f_val empty = f_get_empty(def->type);
  if (empty.type == T_VOID)
    cf_error("Can't empty attribute %s", def->name);

  return f_new_inst(FI_EA_SET, f_new_inst(FI_CONSTANT, empty), def);
}

static inline struct f_inst *
f_implicit_roa_check(struct rtable_config *tab)
{
  const struct ea_class *def = ea_class_find("bgp_path");
  if (!def)
    cf_error("Fatal: Couldn't find BGP path attribute definition.");

  struct f_static_attr fsa = f_new_static_attr(T_NET, SA_NET, 1);

  return f_new_inst(FI_ROA_CHECK,
	    f_new_inst(FI_RTA_GET, fsa),
	    f_new_inst(FI_AS_PATH_LAST, f_new_inst(FI_EA_GET, def)),
	    tab);
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
    case F_LVAL_SA:		return f_new_inst(FI_RTA_GET, lval->sa);
    case F_LVAL_EA:		return f_new_inst(FI_EA_GET, lval->da);
    case F_LVAL_ATTR_BIT:
      {
	struct f_inst *c = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_INT, .val.i = (1U << lval->fab.bit)});
	return f_new_inst(FI_EQ, c, f_new_inst(FI_BITAND, f_new_inst(FI_EA_GET, lval->fab.class), c));
      }
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
    case F_LVAL_ATTR_BIT:	return f_new_inst(FI_CONDITION, expr,
	f_new_inst(FI_EA_SET,
	  f_new_inst(FI_BITOR,
	    f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_INT, .val.i = (1U << lval->fab.bit)}),
	    f_new_inst(FI_EA_GET, lval->fab.class)
	  ),
	  lval->fab.class),
	f_new_inst(FI_EA_SET,
	  f_new_inst(FI_BITAND,
	    f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_INT, .val.i = ~(1U << lval->fab.bit)}),
	    f_new_inst(FI_EA_GET, lval->fab.class)
	  ),
	  lval->fab.class)
	);
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

CF_KEYWORDS(FUNCTION, PRINT, PRINTN, UNSET, RETURN,
	ACCEPT, REJECT, ERROR,
	INT, BOOL, IP, TYPE, PREFIX, RD, PAIR, QUAD, EC, LC,
	SET, STRING, BYTESTRING, BGPMASK, BGPPATH, CLIST, ECLIST, LCLIST,
	IF, THEN, ELSE, CASE,
	FOR, IN, DO,
	TRUE, FALSE, RT, RO, UNKNOWN, GENERIC,
	FROM, GW, NET, MASK, PROTO, SCOPE, DEST, IFNAME, IFINDEX, WEIGHT, GW_MPLS,
	ROA_CHECK, ASN, SRC, DST,
	IS_V4, IS_V6,
	LEN, MAXLEN,
	DATA, DATA1, DATA2,
	DEFINED,
	ADD, DELETE, RESET,
	PREPEND, FIRST, LAST, LAST_NONAGGREGATED,
	MIN, MAX,
	EMPTY,
	FILTER, WHERE, EVAL, ATTRIBUTE,
	FROM_HEX,
	BT_ASSERT, BT_TEST_SUITE, BT_CHECK_ASSIGN, BT_TEST_SAME, FORMAT, STACKS)

%nonassoc THEN
%nonassoc ELSE

%type <xp> cmds_int cmd_prep
%type <x> term term_bs cmd cmd_var cmds cmds_scoped constant constructor print_list var var_list function_call symbol_value bgp_path_expr bgp_path bgp_path_tail method_cmd method_term
%type <fsa> static_attr
%type <f> filter where_filter
%type <fl> filter_body function_body
%type <flv> lvalue
%type <i> type function_vars
%type <fa> function_argsn function_args
%type <ecs> ec_kind
%type <fret> break_command
%type <i32> cnum
%type <e> pair_item ec_item lc_item set_item switch_item set_items switch_items switch_body
%type <trie> fprefix_set
%type <v> set_atom switch_atom fipa
%type <px> fprefix
%type <t> get_cf_position
%type <s> for_var

CF_GRAMMAR

conf: FILTER STACKS expr expr ';' {
  new_config->filter_vstk = $3;
  new_config->filter_estk = $4;
 }
 ;

conf: filter_def ;
filter_def:
   FILTER symbol {
     $2 = cf_define_symbol(new_config, $2, SYM_FILTER, filter, NULL);
     cf_enter_filters();
     cf_push_scope( new_config, $2 );
   } filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .sym = $2, .root = $4 };
     $2->filter = f;

     cf_pop_scope(new_config);
     cf_exit_filters();
   }
 ;

conf: filter_eval ;
filter_eval:
   EVAL term { cf_eval_int($2); }
 ;

conf: custom_attr ;
custom_attr: ATTRIBUTE type symbol ';' {
  if (($3->class == SYM_ATTRIBUTE) && ($3->scope == new_config->root_scope))
    cf_error("Duplicate attribute %s definition", $3->name);

  cf_define_symbol(new_config, $3, SYM_ATTRIBUTE, attribute,
      ea_register_alloc(new_config->pool, (struct ea_class) {
	.name = $3->name,
	.type = $2,
	})->class);
};

conf: bt_test_suite ;
bt_test_suite:
 BT_TEST_SUITE '(' CF_SYM_KNOWN ',' text ')' {
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
 BT_TEST_SAME '(' CF_SYM_KNOWN ',' CF_SYM_KNOWN ',' NUM ')' {
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

filter_body: function_body ;

filter:
   CF_SYM_KNOWN {
     cf_assert_symbol($1, SYM_FILTER);
     $$ = $1->filter;
   }
 | {
     cf_enter_filters();
     cf_push_scope(new_config, NULL);
   } filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .root = $2 };
     $$ = f;

     cf_pop_scope(new_config);
     cf_exit_filters();
   }
 ;

where_filter:
   WHERE {
     cf_enter_filters();
   } term {
     /* Construct 'IF term THEN { ACCEPT; } ELSE { REJECT; }' */
     $$ = f_new_where($3);
     cf_exit_filters();
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
     $2 = cf_define_symbol(new_config, $2, SYM_FUNCTION, function, NULL);
     cf_enter_filters();
     cf_push_scope(new_config, $2);
   } function_args {
     /* Make dummy f_line for storing function prototype */
     struct f_line *dummy = cfg_allocz(sizeof(struct f_line));
     $2->function = dummy;

     /* Revert the args */
     while ($4) {
       struct f_arg *tmp = $4;
       $4 = $4->next;

       tmp->next = dummy->arg_list;
       dummy->arg_list = tmp;
       dummy->args++;
     }
   } function_body {
     $6->args = $2->function->args;
     $6->arg_list = $2->function->arg_list;
     $2->function = $6;
     cf_pop_scope(new_config);
     cf_exit_filters();
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
     $$ = cf_eval_tmp($2, T_VOID);
     if (!f_valid_set_type($$.type)) cf_error("Set-incompatible type");
   }
 | CF_SYM_KNOWN {
     cf_assert_symbol($1, SYM_CONSTANT);
     if (!f_valid_set_type(SYM_TYPE($1))) cf_error("%s: set-incompatible type", $1->name);
     $$ = *$1->val;
   }
 ;

switch_atom:
   NUM   { $$.type = T_INT; $$.val.i = $1; }
 | '(' term ')' { $$ = cf_eval_tmp($2, T_INT); }
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


/* This generates the function_call variable list backwards. */
var_list: /* EMPTY */ { $$ = NULL; }
 | term { $$ = $1; }
 | var_list ',' term { $$ = $3; $$->next = $1; }

function_call:
   CF_SYM_KNOWN '(' var_list ')'
   {
     if ($1->class != SYM_FUNCTION)
       cf_error("You can't call something which is not a function. Really.");

     /* Revert the var_list */
     struct f_inst *args = NULL;
     while ($3) {
       struct f_inst *tmp = $3;
       $3 = $3->next;

       tmp->next = args;
       args = tmp;
     }

     $$ = f_new_inst(FI_CALL, args, $1);
   }
 ;

symbol_value: CF_SYM_KNOWN
  {
    switch ($1->class) {
      case SYM_CONSTANT_RANGE:
	$$ = f_new_inst(FI_CONSTANT, *($1->val));
	break;
      case SYM_VARIABLE_RANGE:
	$$ = f_new_inst(FI_VAR_GET, $1);
	break;
      case SYM_ATTRIBUTE:
	$$ = f_new_inst(FI_EA_GET, $1->attribute);
	break;
      default:
	cf_error("Can't get value of symbol %s", $1->name);
    }
  }
 ;

static_attr:
   GW      { $$ = f_new_static_attr(T_IP,         SA_GW,	0); }
 | NET     { $$ = f_new_static_attr(T_NET,	  SA_NET,	1); }
 | PROTO   { $$ = f_new_static_attr(T_STRING,     SA_PROTO,	1); }
 | DEST    { $$ = f_new_static_attr(T_ENUM_RTD,   SA_DEST,	0); }
 | IFNAME  { $$ = f_new_static_attr(T_STRING,     SA_IFNAME,	0); }
 | IFINDEX { $$ = f_new_static_attr(T_INT,        SA_IFINDEX,	1); }
 | WEIGHT  { $$ = f_new_static_attr(T_INT,        SA_WEIGHT,	0); }
 | GW_MPLS { $$ = f_new_static_attr(T_INT,        SA_GW_MPLS,	0); }
 ;

method_term:
   IS_V4 { $$ = f_new_inst(FI_IS_V4, FM.object); }
 | TYPE { $$ = f_new_inst(FI_TYPE, FM.object); }
 | IP { $$ = f_new_inst(FI_IP, FM.object); }
 | RD { $$ = f_new_inst(FI_ROUTE_DISTINGUISHER, FM.object); }
 | LEN { $$ = f_new_inst(FI_LENGTH, FM.object); }
 | MAXLEN { $$ = f_new_inst(FI_ROA_MAXLEN, FM.object); }
 | ASN { $$ = f_new_inst(FI_ASN, FM.object); }
 | SRC { $$ = f_new_inst(FI_NET_SRC, FM.object); }
 | DST { $$ = f_new_inst(FI_NET_DST, FM.object); }
 | MASK '(' term ')' { $$ = f_new_inst(FI_IP_MASK, FM.object, $3); }
 | FIRST { $$ = f_new_inst(FI_AS_PATH_FIRST, FM.object); }
 | LAST  { $$ = f_new_inst(FI_AS_PATH_LAST, FM.object); }
 | LAST_NONAGGREGATED  { $$ = f_new_inst(FI_AS_PATH_LAST_NAG, FM.object); }
 | DATA { $$ = f_new_inst(FI_PAIR_DATA, FM.object); }
 | DATA1 { $$ = f_new_inst(FI_LC_DATA1, FM.object); }
 | DATA2 { $$ = f_new_inst(FI_LC_DATA2, FM.object); }
 | MIN  { $$ = f_new_inst(FI_MIN, FM.object); }
 | MAX  { $$ = f_new_inst(FI_MAX, FM.object); }
 ;

method_cmd:
   EMPTY		{ $$ = f_new_inst(FI_CONSTANT, f_get_empty(FM.object->i_FI_EA_GET.da->type)); }
 | PREPEND '(' term ')'	{ $$ = f_new_inst(FI_PATH_PREPEND, FM.object, $3 ); }
 | ADD '(' term ')'	{ $$ = f_new_inst(FI_CLIST_ADD, FM.object, $3 ); }
 | DELETE '(' term ')'	{ $$ = f_new_inst(FI_CLIST_DEL, FM.object, $3 ); }
 | FILTER '(' term ')'	{ $$ = f_new_inst(FI_CLIST_FILTER, FM.object, $3 ); }
 ;

term:
   '(' term ')'		{ $$ = $2; }
 | term '+' term	{ $$ = f_new_inst(FI_ADD, $1, $3); }
 | term '-' term	{ $$ = f_new_inst(FI_SUBTRACT, $1, $3); }
 | term '*' term	{ $$ = f_new_inst(FI_MULTIPLY, $1, $3); }
 | term '/' term	{ $$ = f_new_inst(FI_DIVIDE, $1, $3); }
 | term '&' term	{ $$ = f_new_inst(FI_BITAND, $1, $3); }
 | term '|' term	{ $$ = f_new_inst(FI_BITOR, $1, $3); }
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

 | static_attr { $$ = f_new_inst(FI_RTA_GET, $1); }

 | term '.' {
     f_push_method_scope($1);
   } method_term {
     f_pop_method_scope();
     $$ = $4;
   }

 | '+' EMPTY '+' { $$ = f_new_inst(FI_CONSTANT, f_get_empty(T_PATH)); }
 | '-' EMPTY '-' { $$ = f_new_inst(FI_CONSTANT, f_get_empty(T_CLIST)); }
 | '-' '-' EMPTY '-' '-' { $$ = f_new_inst(FI_CONSTANT, f_get_empty(T_ECLIST)); }
 | '-' '-' '-' EMPTY '-' '-' '-' { $$ = f_new_inst(FI_CONSTANT, f_get_empty(T_LCLIST)); }
 | PREPEND '(' term ',' term ')' { $$ = f_new_inst(FI_PATH_PREPEND, $3, $5); }
 | ADD '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_ADD, $3, $5); }
 | DELETE '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_DEL, $3, $5); }
 | FILTER '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_FILTER, $3, $5); }

 | ROA_CHECK '(' rtable ')' { $$ = f_implicit_roa_check($3); }
 | ROA_CHECK '(' rtable ',' term ',' term ')' { $$ = f_new_inst(FI_ROA_CHECK, $5, $7, $3); }

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

print_list: /* EMPTY */ { $$ = NULL; }
 | term { $$ = $1; }
 | term ',' print_list {
     ASSERT($1);
     ASSERT($1->next == NULL);
     $1->next = $3;
     $$ = $1;
   }
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
 | CF_SYM_KNOWN { $$ = $1; cf_assert_symbol($1, SYM_VARIABLE); }
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
   { new_config->current_scope->active = 0; } term { new_config->current_scope->active = 1; }
   DO cmd {
     cf_pop_block_scope(new_config);
     $$ = f_new_inst(FI_FOR_INIT, $6, $3);
     $$->next = f_new_inst(FI_FOR_NEXT, $3, $9);
   }
 | CF_SYM_KNOWN '=' term ';' {
     switch ($1->class) {
       case SYM_VARIABLE_RANGE:
	 $$ = f_new_inst(FI_VAR_SET, $3, $1);
	 break;
       case SYM_ATTRIBUTE:
	 if ($1->attribute->readonly)
	   cf_error("Attribute %s is read-only", $1->attribute->name);
	 $$ = f_new_inst(FI_EA_SET, $3, $1->attribute);
	 break;
       default:
	 cf_error("Can't assign to symbol %s", $1->name);
     }
   }
 | RETURN term ';' {
     DBG( "Ook, we'll return the value\n" );
     $$ = f_new_inst(FI_RETURN, $2);
   }
 | static_attr '=' term ';' {
     if ($1.readonly)
       cf_error( "This static attribute is read-only.");
     $$ = f_new_inst(FI_RTA_SET, $3, $1);
   }
 | UNSET '(' CF_SYM_KNOWN ')' ';' {
     if ($3->class != SYM_ATTRIBUTE)
       cf_error("Can't unset %s", $3->name);
     if ($3->attribute->readonly)
       cf_error("Attribute %s is read-only", $3->attribute->name);
     $$ = f_new_inst(FI_EA_UNSET, $3->attribute);
   }
 | break_command print_list ';' {
    struct f_inst *breaker = f_new_inst(FI_DIE, $1);
    if ($2) {
      struct f_inst *printer = f_new_inst(FI_PRINT, $2);
      struct f_inst *flusher = f_new_inst(FI_FLUSH);
      printer->next = flusher;
      flusher->next = breaker;
      $$ = printer;
    } else
      $$ = breaker;
   }
 | PRINT print_list ';' {
    $$ = f_new_inst(FI_PRINT, $2);
    $$->next = f_new_inst(FI_FLUSH);
   }
 | PRINTN print_list ';' {
    $$ = f_new_inst(FI_PRINT, $2);
   }
 | function_call ';' { $$ = f_new_inst(FI_DROP_RESULT, $1); }
 | CASE term '{' switch_body '}' {
      $$ = f_new_inst(FI_SWITCH, $2, $4);
   }

 | lvalue '.' {
     f_push_method_scope(f_lval_getter(&$1));
   } method_cmd ';' {
     f_pop_method_scope();
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
	 $$ = (struct f_lval) { .type = F_LVAL_VARIABLE, .sym = $1 };
         break;
       case SYM_ATTRIBUTE:
         $$ = (struct f_lval) { .type = F_LVAL_EA, .da = $1->attribute };
	 break;
       default:
	 cf_error("Variable name or attribute name required");
     }
   }
 | static_attr { $$ = (struct f_lval) { .type = F_LVAL_SA, .sa = $1 }; }
 ;

CF_END

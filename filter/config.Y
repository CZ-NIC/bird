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

#define f_generate_complex(fi_code, da, arg) \
  f_new_inst(FI_EA_SET, f_new_inst(fi_code, f_new_inst(FI_EA_GET, da), arg), da)

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
f_generate_empty(struct f_dynamic_attr dyn)
{
  struct f_val empty;

  switch (dyn.type & EAF_TYPE_MASK) {
    case EAF_TYPE_AS_PATH:
      empty = f_const_empty_path;
      break;
    case EAF_TYPE_INT_SET:
      empty = f_const_empty_clist;
      break;
    case EAF_TYPE_EC_SET:
      empty = f_const_empty_eclist;
      break;
    case EAF_TYPE_LC_SET:
      empty = f_const_empty_lclist;
      break;
    default:
      cf_error("Can't empty that attribute");
  }

  return f_new_inst(FI_EA_SET, f_new_inst(FI_CONSTANT, empty), dyn);
}

#if 0

static inline struct f_inst *
f_generate_dpair(struct f_inst *t1, struct f_inst *t2)
{
  struct f_inst *rv;

  if ((t1->fi_code == FI_CONSTANT) && (t2->fi_code == FI_CONSTANT)) {
    if ((t1->val.type != T_INT) || (t2->val.type != T_INT))
      cf_error( "Can't operate with value of non-integer type in pair constructor");

    check_u16(t1->a[1].i);
    check_u16(t2->a[1].i);

    rv = f_new_inst(FI_CONSTANT);
    rv->val = (struct f_val) {
      .type = T_PAIR,
      .val.i = pair(t1->a[1].i, t2->a[1].i),
    };
  }
  else {
    rv = f_new_inst(FI_PAIR_CONSTRUCT);
    rv->a[0].p = t1;
    rv->a[1].p = t2;
  }

  return rv;
}

static inline struct f_inst *
f_generate_ec(u16 kind, struct f_inst *tk, struct f_inst *tv)
{
  struct f_inst *rv;
  int c1 = 0, c2 = 0, ipv4_used = 0;
  u32 key = 0, val2 = 0;

  if (tk->fi_code == FI_CONSTANT) {
    c1 = 1;
    struct f_val *val = &(tk->val);

    if (val->type == T_INT) {
      ipv4_used = 0; key = val->val.i;
    }
    else if (tk->val.type == T_QUAD) {
      ipv4_used = 1; key = val->val.i;
    }
    else if ((val->type == T_IP) && ipa_is_ip4(val->val.ip)) {
      ipv4_used = 1; key = ipa_to_u32(val->val.ip);
    }
    else
      cf_error("Can't operate with key of non-integer/IPv4 type in EC constructor");
  }

  if (tv->fi_code == FI_CONSTANT) {
    if (tv->val.type != T_INT)
      cf_error("Can't operate with value of non-integer type in EC constructor");
    c2 = 1;
    val2 = tv->val.val.i;
  }

  if (c1 && c2) {
    u64 ec;

    if (kind == EC_GENERIC) {
      ec = ec_generic(key, val2);
    }
    else if (ipv4_used) {
      check_u16(val2);
      ec = ec_ip4(kind, key, val2);
    }
    else if (key < 0x10000) {
      ec = ec_as2(kind, key, val2);
    }
    else {
      check_u16(val2);
      ec = ec_as4(kind, key, val2);
    }

    rv = f_new_inst(FI_CONSTANT);
    rv->val = (struct f_val) {
      .type = T_EC,
      .val.ec = ec,
    };
  }
  else {
    rv = f_new_inst(FI_EC_CONSTRUCT);
    rv->aux = kind;
    rv->a[0].p = tk;
    rv->a[1].p = tv;
  }

  return rv;
}

static inline struct f_inst *
f_generate_lc(struct f_inst *t1, struct f_inst *t2, struct f_inst *t3)
{
  struct f_inst *rv;

  if ((t1->fi_code == FI_CONSTANT) && (t2->fi_code == FI_CONSTANT) && (t3->fi_code == FI_CONSTANT)) {
    if ((t1->val.type != T_INT) || (t2->val.type != T_INT) || (t3->val.type != T_INT))
      cf_error( "LC - Can't operate with value of non-integer type in tuple constructor");

    rv = f_new_inst(FI_CONSTANT);
    rv->val = (struct f_val) {
      .type = T_LC,
      .val.lc = (lcomm) { t1->a[1].i, t2->a[1].i, t3->a[1].i },
    };
  }
  else
  {
    rv = f_new_inst(FI_LC_CONSTRUCT);
    rv->a[0].p = t1;
    rv->a[1].p = t2;
    rv->a[2].p = t3;
  }

  return rv;
}

static inline struct f_inst *
f_generate_path_mask(struct f_inst *t)
{
  uint len = 0;
  uint dyn = 0;
  for (const struct f_inst *tt = t; tt; tt = tt->next) {
    if (tt->fi_code != FI_CONSTANT)
      dyn++;
    len++;
  }

  if (dyn) {
    struct f_inst *pmc = f_new_inst(FI_PATHMASK_CONSTRUCT);
    pmc->a[0].p = t;
    pmc->a[1].i = len;
    return pmc;
  }

  struct f_path_mask *pm = cfg_allocz(sizeof(struct f_path_mask) + len * sizeof(struct f_path_mask_item));

  uint i = 0;
  for (const struct f_inst *tt = t; tt; tt = tt->next)
    pm->item[i++] = tt->val.val.pmi;

  pm->len = i;
  struct f_inst *pmc = f_new_inst(FI_CONSTANT);
  pmc->val = (struct f_val) { .type = T_PATH_MASK, .val.path_mask = pm, };

  return pmc;
}

#endif

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
assert_assign(struct f_lval *lval, struct f_inst *expr, const char *start, const char *end)
{
  struct f_inst *setter, *getter, *checker;
  switch (lval->type) {
    case F_LVAL_VARIABLE:
      setter = f_new_inst(FI_VAR_SET, expr, lval->sym);
      getter = f_new_inst(FI_VAR_GET, lval->sym);
      break;
    case F_LVAL_PREFERENCE:
      setter = f_new_inst(FI_PREF_SET, expr);
      getter = f_new_inst(FI_PREF_GET);
      break;
    case F_LVAL_SA:
      setter = f_new_inst(FI_RTA_SET, expr, lval->sa);
      getter = f_new_inst(FI_RTA_GET, lval->sa);
      break;
    case F_LVAL_EA:
      setter = f_new_inst(FI_EA_SET, expr, lval->da);
      getter = f_new_inst(FI_EA_GET, lval->da);
      break;
    default:
      bug("Unknown lval type");
  }

  checker = f_new_inst(FI_EQ, expr, getter);
  setter->next = checker;
  
  return assert_done(setter, start, end);
}

CF_DECLS

CF_KEYWORDS(FUNCTION, PRINT, PRINTN, UNSET, RETURN,
	ACCEPT, REJECT, ERROR, QUITBIRD,
	INT, BOOL, IP, TYPE, PREFIX, RD, PAIR, QUAD, EC, LC,
	SET, STRING, BGPMASK, BGPPATH, CLIST, ECLIST, LCLIST,
	IF, THEN, ELSE, CASE,
	TRUE, FALSE, RT, RO, UNKNOWN, GENERIC,
	FROM, GW, NET, MASK, PROTO, SOURCE, SCOPE, DEST, IFNAME, IFINDEX,
	PREFERENCE,
	ROA_CHECK, ASN, SRC,
	IS_V4, IS_V6,
	LEN, MAXLEN,
	DEFINED,
	ADD, DELETE, CONTAINS, RESET,
	PREPEND, FIRST, LAST, LAST_NONAGGREGATED, MATCH,
	EMPTY,
	FILTER, WHERE, EVAL, ATTRIBUTE,
	BT_ASSERT, BT_TEST_SUITE, BT_CHECK_ASSIGN, BT_TEST_SAME, FORMAT)

%nonassoc THEN
%nonassoc ELSE

%type <xp> cmds_int cmd_prep
%type <x> term block cmd cmds constant constructor print_list var_list function_call symbol_value bgp_path_expr bgp_path bgp_path_tail
%type <fda> dynamic_attr
%type <fsa> static_attr
%type <f> filter where_filter
%type <fl> filter_body function_body
%type <flv> lvalue
%type <i> type function_args function_vars
%type <ecs> ec_kind
%type <fret> break_command 
%type <i32> cnum
%type <e> pair_item ec_item lc_item set_item switch_item set_items switch_items switch_body
%type <trie> fprefix_set
%type <v> set_atom switch_atom fipa
%type <px> fprefix
%type <t> get_cf_position

CF_GRAMMAR

conf: filter_def ;
filter_def:
   FILTER symbol { $2 = cf_define_symbol($2, SYM_FILTER, filter, NULL); cf_push_scope( $2 ); }
     filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .sym = $2, .root = $4 };
     $2->filter = f;

     cf_pop_scope();
   }
 ;

conf: filter_eval ;
filter_eval:
   EVAL term { f_eval_int(f_linearize($2)); }
 ;

conf: custom_attr ;
custom_attr: ATTRIBUTE type symbol ';' {
  cf_define_symbol($3, SYM_ATTRIBUTE, attribute, ca_lookup(new_config->pool, $3->name, $2)->fda);
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
   /* EMPTY */
 | function_argsn type symbol ';' {
     if ($3->scope->slots >= 0xfe) cf_error("Too many declarations, at most 255 allowed");
     cf_define_symbol($3, SYM_VARIABLE | $2, offset, $3->scope->slots++);
   }
 ;

function_args:
   '(' ')' { $$ = 0; }
 | '(' function_argsn type symbol ')' {
     cf_define_symbol($4, SYM_VARIABLE | $3, offset, $4->scope->slots++);
     $$ = $4->scope->slots;
   }
 ;

function_vars:
   /* EMPTY */ { $$ = 0; }
 | function_vars type symbol ';' {
     cf_define_symbol($3, SYM_VARIABLE | $2, offset, $3->scope->slots++);
     $$ = $1 + 1;
   }
 ;

filter_body: function_body ;

filter:
   CF_SYM_KNOWN {
     cf_assert_symbol($1, SYM_FILTER);
     $$ = $1->filter;
   }
 | filter_body {
     struct filter *f = cfg_alloc(sizeof(struct filter));
     *f = (struct filter) { .root = $1 };
     $$ = f;
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
     $$ = f_linearize($3);
     $$->vars = $1;
   }
 ;

conf: function_def ;
function_def:
   FUNCTION symbol { DBG( "Beginning of function %s\n", $2->name );
     $2 = cf_define_symbol($2, SYM_FUNCTION, function, NULL);
     cf_push_scope($2);
   } function_args function_body {
     DBG("Definition of function %s with %u args and %u local vars.\n", $2->name, $4, $5->vars);
     $5->args = $4;
     $2->function = $5;
     cf_pop_scope();
   }
 ;

/* Programs */

cmds: /* EMPTY */ { $$ = NULL; }
 | cmds_int { $$ = $1.begin; }
 ;

cmd_prep: cmd {
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

block:
   cmd {
     $$=$1;
   }
 | '{' cmds '}' {
     $$=$2;
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
     if (f_eval(f_linearize($2), cfg_mem, &($$)) > F_RETURN) cf_error("Runtime error");
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
 | '(' term ')' { $$.type = T_INT; $$.val.i = f_eval_int(f_linearize($2)); }
 | fipa  { $$ = $1; }
 | ENUM  { $$.type = pair_a($1); $$.val.i = pair_b($1); }
 ;

cnum:
   term { $$ = f_eval_int(f_linearize($1)); }

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
   fprefix { $$ = f_new_trie(cfg_mem, sizeof(struct f_trie_node)); trie_add_prefix($$, &($1.net), $1.lo, $1.hi); }
 | fprefix_set ',' fprefix { $$ = $1; trie_add_prefix($$, &($3.net), $3.lo, $3.hi); }
 ;

switch_body: /* EMPTY */ { $$ = NULL; }
 | switch_body switch_items ':' cmds  {
     /* Fill data fields */
     struct f_tree *t;
     struct f_line *line = f_linearize($4);
     for (t = $2; t; t = t->left)
       t->data = line;
     $$ = f_merge_items($1, $2);
   }
 | switch_body ELSECOL cmds {
     struct f_tree *t = f_new_tree();
     t->from.type = t->to.type = T_VOID;
     t->right = t;
     t->data = f_linearize($3);
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
 | '[' set_items ']' bgp_path_tail {
   if ($2->from.type != T_INT) cf_error("Only integer sets allowed in path mask");
   $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .set = build_tree($2), .kind = PM_ASN_SET }, }); $$->next = $4;
 }
 | '*' bgp_path_tail		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .kind = PM_ASTERISK }, }); $$->next = $2; }
 | '?' bgp_path_tail		{ $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_PATH_MASK_ITEM, .val.pmi = { .kind = PM_QUESTION }, }); $$->next = $2; }
 | bgp_path_expr bgp_path_tail	{ $$ = $1; $$->next = $2; }
 | 				{ $$ = NULL; }
 ;

constant:
   NUM    { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_INT, .val.i = $1, }); }
 | TRUE   { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_BOOL, .val.i = 1, }); }
 | FALSE  { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_BOOL, .val.i = 0, }); }
 | TEXT   { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_STRING, .val.s = $1, }); }
 | fipa	  { $$ = f_new_inst(FI_CONSTANT, $1); }
 | VPN_RD { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_RD, .val.ec = $1, }); }
 | net_   { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_NET, .val.net = $1, }); }
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
   CF_SYM_KNOWN '(' var_list ')' {
     if ($1->class != SYM_FUNCTION)
       cf_error("You can't call something which is not a function. Really.");

     struct f_inst *fc = f_new_inst(FI_CALL, $1);
     uint args = 0;
     while ($3) {
       args++;
       struct f_inst *tmp = $3->next;
       $3->next = fc;

       fc = $3;
       $3 = tmp;
     }

     if (args != $1->function->args)
       cf_error("Function call '%s' got %u arguments, need %u arguments.",
	   $1->name, args, $1->function->args);

     $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_VOID });
     $$->next = fc;
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
	$$ = f_new_inst(FI_EA_GET, *$1->attribute);
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

 | PREFERENCE { $$ = f_new_inst(FI_PREF_GET); }

 | static_attr { $$ = f_new_inst(FI_RTA_GET, $1); }

 | dynamic_attr { $$ = f_new_inst(FI_EA_GET, $1); }

 | term '.' IS_V4 { $$ = f_new_inst(FI_IS_V4, $1); }
 | term '.' TYPE { $$ = f_new_inst(FI_TYPE, $1); }
 | term '.' IP { $$ = f_new_inst(FI_IP, $1); }
 | term '.' RD { $$ = f_new_inst(FI_ROUTE_DISTINGUISHER, $1); }
 | term '.' LEN { $$ = f_new_inst(FI_LENGTH, $1); }
 | term '.' MAXLEN { $$ = f_new_inst(FI_ROA_MAXLEN, $1); }
 | term '.' ASN { $$ = f_new_inst(FI_ROA_ASN, $1); }
 | term '.' SRC { $$ = f_new_inst(FI_SADR_SRC, $1); }
 | term '.' MASK '(' term ')' { $$ = f_new_inst(FI_IP_MASK, $1, $5); }
 | term '.' FIRST { $$ = f_new_inst(FI_AS_PATH_FIRST, $1); }
 | term '.' LAST  { $$ = f_new_inst(FI_AS_PATH_LAST, $1); }
 | term '.' LAST_NONAGGREGATED  { $$ = f_new_inst(FI_AS_PATH_LAST_NAG, $1); }

/* Communities */
/* This causes one shift/reduce conflict
 | dynamic_attr '.' ADD '(' term ')' { }
 | dynamic_attr '.' DELETE '(' term ')' { }
 | dynamic_attr '.' CONTAINS '(' term ')' { }
 | dynamic_attr '.' RESET{ }
*/

 | '+' EMPTY '+' { $$ = f_new_inst(FI_CONSTANT, f_const_empty_path); }
 | '-' EMPTY '-' { $$ = f_new_inst(FI_CONSTANT, f_const_empty_clist); }
 | '-' '-' EMPTY '-' '-' { $$ = f_new_inst(FI_CONSTANT, f_const_empty_eclist); }
 | '-' '-' '-' EMPTY '-' '-' '-' { $$ = f_new_inst(FI_CONSTANT, f_const_empty_lclist); }
 | PREPEND '(' term ',' term ')' { $$ = f_new_inst(FI_PATH_PREPEND, $3, $5); }
 | ADD '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_ADD, $3, $5); }
 | DELETE '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_DEL, $3, $5); }
 | FILTER '(' term ',' term ')' { $$ = f_new_inst(FI_CLIST_FILTER, $3, $5); }

 | ROA_CHECK '(' rtable ')' { $$ = f_new_inst(FI_ROA_CHECK_IMPLICIT, $3); }
 | ROA_CHECK '(' rtable ',' term ',' term ')' { $$ = f_new_inst(FI_ROA_CHECK_EXPLICIT, $5, $7, $3); }

 | FORMAT '(' term ')' {  $$ = f_new_inst(FI_FORMAT, $3); }

/* | term '.' LEN { $$->code = P('P','l'); } */

 | function_call
 ;

break_command:
   QUITBIRD { $$ = F_QUITBIRD; }
 | ACCEPT { $$ = F_ACCEPT; }
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

cmd:
   IF term THEN block {
     $$ = f_new_inst(FI_CONDITION, $2, $4, NULL);
   }
 | IF term THEN block ELSE block {
     $$ = f_new_inst(FI_CONDITION, $2, $4, $6);
   }
 | CF_SYM_KNOWN '=' term ';' {
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
 | PREFERENCE '=' term ';' {
     $$ = f_new_inst(FI_PREF_SET, $3);
   }
 | UNSET '(' dynamic_attr ')' ';' {
     $$ = f_new_inst(FI_EA_UNSET, $3);
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
      $$ = f_new_inst(FI_SWITCH, $2, build_tree($4));
   }

 | dynamic_attr '.' EMPTY ';' { $$ = f_generate_empty($1); }
 | dynamic_attr '.' PREPEND '(' term ')' ';'   { $$ = f_generate_complex( FI_PATH_PREPEND, $1, $5 ); }
 | dynamic_attr '.' ADD '(' term ')' ';'       { $$ = f_generate_complex( FI_CLIST_ADD, $1, $5 ); }
 | dynamic_attr '.' DELETE '(' term ')' ';'    { $$ = f_generate_complex( FI_CLIST_DEL, $1, $5 ); }
 | dynamic_attr '.' FILTER '(' term ')' ';'    { $$ = f_generate_complex( FI_CLIST_FILTER, $1, $5 ); }
 | BT_ASSERT '(' get_cf_position term get_cf_position ')' ';' { $$ = assert_done($4, $3 + 1, $5 - 1); }
 | BT_CHECK_ASSIGN '(' get_cf_position lvalue get_cf_position ',' term ')' ';' { $$ = assert_assign(&$4, $7, $3 + 1, $5 - 1); }
 ;

get_cf_position:
{
  $$ = cf_text;
};

lvalue:
   CF_SYM_KNOWN { cf_assert_symbol($1, SYM_VARIABLE); $$ = (struct f_lval) { .type = F_LVAL_VARIABLE, .sym = $1 }; }
 | PREFERENCE { $$ = (struct f_lval) { .type = F_LVAL_PREFERENCE }; }
 | static_attr { $$ = (struct f_lval) { .type = F_LVAL_SA, .sa = $1 }; }
 | dynamic_attr { $$ = (struct f_lval) { .type = F_LVAL_EA, .da = $1 }; };

CF_END

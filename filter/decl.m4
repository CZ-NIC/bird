m4_divert(-1)m4_dnl
#
#	BIRD -- Construction of per-instruction structures
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#
#
#	Global Diversions:
#	4	enum fi_code
#	5	enum fi_code to string
#	6	dump line item
#	7	dump line item callers
#	8	linearize
#	9	same (filter comparator)
#	1	union in struct f_inst
#	3	constructors + interpreter
#
#	Per-inst Diversions:
#	101	content of per-inst struct
#	102	constructor arguments
#	103	constructor body
#	104	dump line item content
#	105	linearize body
#	106	comparator body
#	107	struct f_line_item content
#	108	interpreter body
#
#	Diversions for TARGET=I: 7xx
#	Diversions for TARGET=C: 8xx
#	Diversions for TARGET=H: 9xx

# Flush the completed instruction
m4_define(FID_END, `m4_divert(-1)')

m4_dnl m4_debugmode(aceflqtx)

m4_define(FID_ZONE, `m4_divert($1) /* $2 for INST_NAME() */')
m4_define(FID_INST, `FID_ZONE(1, Instruction structure for config)')
m4_define(FID_LINE, `FID_ZONE(2, Instruction structure for interpreter)')
m4_define(FID_NEW, `FID_ZONE(3, Constructor)')
m4_define(FID_ENUM, `FID_ZONE(4, Code enum)')
m4_define(FID_ENUM_STR, `FID_ZONE(5, Code enum to string)')
m4_define(FID_DUMP, `FID_ZONE(6, Dump line)')
m4_define(FID_DUMP_CALLER, `FID_ZONE(7, Dump line caller)')
m4_define(FID_LINEARIZE, `FID_ZONE(8, Linearize)')
m4_define(FID_SAME, `FID_ZONE(9, Comparison)')
m4_define(FID_INTERPRET, `FID_ZONE(10, Interpret)')

m4_define(FID_STRUCT_IN, `m4_divert(101)')
m4_define(FID_NEW_ARGS, `m4_divert(102)')
m4_define(FID_NEW_BODY, `m4_divert(103)')
m4_define(FID_DUMP_BODY, `m4_divert(104)m4_define([[FID_DUMP_BODY_EXISTS]])')
m4_define(FID_LINEARIZE_BODY, `m4_divert(105)m4_define([[FID_LINEARIZE_BODY_EXISTS]])')
m4_define(FID_SAME_BODY, `m4_divert(106)')
m4_define(FID_LINE_IN, `m4_divert(107)')
m4_define(FID_INTERPRET_BODY, `m4_divert(108)')
m4_define(FID_INTERPRET_NEW, `m4_ifelse(TARGET, [[C]], [[m4_divert(108)]], [[m4_divert(-1)]])')
m4_define(FID_INTERPRET_EXEC, `m4_ifelse(TARGET, [[I]], [[m4_divert(108)]], [[m4_divert(-1)]])')

m4_define(FID_ALL, `FID_INTERPRET_BODY');

m4_define(FID_ALL_TARGETS, `m4_ifdef([[FID_CURDIV]], [[m4_divert(FID_CURDIV)m4_undefine([[FID_CURDIV]])]])')
m4_define(FID_C, `m4_ifelse(TARGET, [[C]], FID_ALL_TARGETS, [[m4_ifelse(m4_divnum, -1,, [[m4_define(FID_CURDIV, m4_divnum)]])m4_divert(-1)]])')
m4_define(FID_I, `m4_ifelse(TARGET, [[I]], FID_ALL_TARGETS, [[m4_ifelse(m4_divnum, -1,, [[m4_define(FID_CURDIV, m4_divnum)]])m4_divert(-1)]])')
m4_define(FID_H, `m4_ifelse(TARGET, [[H]], FID_ALL_TARGETS, [[m4_ifelse(m4_divnum, -1,, [[m4_define(FID_CURDIV, m4_divnum)]])m4_divert(-1)]])')
m4_define(FID_CI, `m4_ifelse(TARGET, [[H]], [[m4_define(FID_CURDIV, m4_divnum)m4_divert(-1)]], FID_ALL_TARGETS)')



m4_define(INST_FLUSH, `m4_ifdef([[INST_NAME]], [[
FID_ENUM
INST_NAME(),
FID_ENUM_STR
[INST_NAME()] = "INST_NAME()",
FID_INST
struct {
m4_undivert(101)
} i_[[]]INST_NAME();
FID_LINE
struct {
m4_undivert(107)
} i_[[]]INST_NAME();
FID_NEW
struct f_inst *f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)
)
FID_H
;
FID_C
{
  struct f_inst *what = cfg_allocz(sizeof(struct f_inst));
  what->fi_code = fi_code;
  what->lineno = ifs->lino;
  what->size = 1;
  what->constant = 1;
#define whati (&(what->i_]]INST_NAME()[[))
m4_undivert(103)
  if (!what->constant)
    return what;

  struct f_val res;
#define v1 f1->i_FI_CONSTANT.val
#define v2 f2->i_FI_CONSTANT.val
#define v3 f3->i_FI_CONSTANT.val
#define runtime cf_error

FID_I

case INST_NAME():
#define whati (&(what->i_]]INST_NAME()[[))
m4_ifelse(m4_eval(INST_INVAL() > 0), 1, [[if (fstk->vcnt < INST_INVAL()) runtime("Stack underflow"); fstk->vcnt -= INST_INVAL(); ]])

FID_CI

m4_undivert(108)
#undef whati

FID_I

break;

FID_C

  what->fi_code = FI_CONSTANT;
  what->i_FI_CONSTANT.val = res;
  return what;
#undef v1
#undef v2
#undef v3
#undef runtime
}

FID_DUMP_CALLER
case INST_NAME(): f_dump_line_item_]]INST_NAME()[[(item, indent + 1); break;

FID_DUMP
m4_ifdef([[FID_DUMP_BODY_EXISTS]],
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item_, const int indent)]],
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item UNUSED, const int indent UNUSED)]])
m4_undefine([[FID_DUMP_BODY_EXISTS]])
{
#define item (&(item_->i_]]INST_NAME()[[))
m4_undivert(104)
#undef item
}

FID_LINEARIZE
case INST_NAME(): {
#define whati (&(what->i_]]INST_NAME()[[))
#define item (&(dest->items[pos].i_]]INST_NAME()[[))
  m4_undivert(105)
#undef whati
#undef item
  dest->items[pos].fi_code = what->fi_code;
  dest->items[pos].lineno = what->lineno;
  break;
}
m4_undefine([[FID_LINEARIZE_BODY_EXISTS]])

FID_SAME
case INST_NAME():
#define f1 (&(f1_->i_]]INST_NAME()[[))
#define f2 (&(f2_->i_]]INST_NAME()[[))
m4_undivert(106)
#undef f1
#undef f2
break;
FID_ALL_TARGETS
FID_END
]])')

m4_define(INST, `m4_dnl
INST_FLUSH()m4_dnl
m4_define([[INST_NAME]], [[$1]])m4_dnl
m4_define([[INST_INVAL]], [[$2]])m4_dnl
FID_ALL() m4_dnl
')

m4_dnl FID_MEMBER call:
m4_dnl type
m4_dnl name in f_inst
m4_dnl name in f_line_item
m4_dnl comparator for same
m4_dnl dump format string
m4_dnl dump format args
m4_dnl interpreter body
m4_define(FID_MEMBER, `m4_dnl
FID_LINE_IN
$1 $2;
FID_STRUCT_IN
$1 $2;
FID_NEW_ARGS
, $1 $2
FID_NEW_BODY
whati->$2 = $2;
m4_ifelse($3,,,[[
FID_LINEARIZE_BODY
item->$3 = what->$2;
]])
m4_ifelse($4,,,[[
FID_SAME_BODY
if ($4) return 0;
]])
m4_ifelse($5,,,[[
FID_DUMP_BODY
debug("%s$5\n", INDENT, $6);
]])
m4_ifelse($7,,,[[
FID_INTERPRET_BODY
$7
]])
FID_ALL')

m4_define(ARG_ANY, `
FID_STRUCT_IN
struct f_inst * f$1;
FID_NEW_ARGS
, struct f_inst * f$1
FID_NEW_BODY
whati->f$1 = f$1;
if (!whati->f$1->constant)
  what->constant = 0;
for (const struct f_inst *child = f$1; child; child = child->next) what->size += child->size;
FID_LINEARIZE_BODY
pos = linearize(dest, what->f$1, pos);m4_dnl
FID_ALL()')

m4_define(ARG, `ARG_ANY($1)
FID_INTERPRET_BODY
if (v$1.type != $2) runtime("Argument $1 of instruction %s must be of type $2, got 0x%02x", f_instruction_name(what->fi_code), v$1.type)m4_dnl
FID_ALL()')

m4_define(LINEX, `FID_INTERPRET_EXEC
do {
  fstk->estk[fstk->ecnt].pos = 0;
  fstk->estk[fstk->ecnt].line = $1;
  fstk->estk[fstk->ecnt].ventry = fstk->vcnt;
  fstk->estk[fstk->ecnt].vbase = fstk->estk[fstk->ecnt-1].vbase;
  fstk->estk[fstk->ecnt].emask = 0;
  fstk->ecnt++;
} while (0)m4_dnl
FID_ALL()')

m4_define(LINE, `
FID_LINE_IN
const struct f_line * fl$1;
FID_STRUCT_IN
struct f_inst * f$1;
FID_NEW_ARGS
, struct f_inst * f$1
FID_NEW_BODY
whati->f$1 = f$1;
FID_DUMP_BODY
f_dump_line(item->fl$1, indent + 1);
FID_LINEARIZE_BODY
item->fl$1 = f_linearize(what->f$1);
FID_SAME_BODY
if (!f_same(f1->fl$1, f2->fl$1)) return 0;
FID_INTERPRET_EXEC
do { if (whati->fl$1) {
  LINEX(whati->fl$1) FID_INTERPRET_EXEC();
} } while(0)m4_dnl
FID_INTERPRET_NEW
return f$1 m4_dnl
FID_ALL()')

m4_define(RESULT_OK, `FID_INTERPRET_EXEC()fstk->vcnt++FID_INTERPRET_NEW(){}FID_ALL()')
m4_define(RESULT, `RESULT_VAL([[ (struct f_val) { .type = $1, .val.$2 = $3 } ]])')
m4_define(RESULT_VAL, `FID_INTERPRET_BODY()do { res = $1; RESULT_OK; } while (0)FID_ALL()')

m4_define(SYMBOL, `FID_MEMBER(struct symbol *, sym, sym,
[[strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)]], symbol %s, item->sym->name, struct symbol *sym = whati->sym)')
m4_define(VAL, `FID_MEMBER(struct f_val $1, val, val m4_ifelse($1,,,[0]), [[!val_same(&f1->val, &f2->val)]], value %s, val_dump(&item->val),)')
m4_define(FRET, `FID_MEMBER(enum filter_return, fret, fret, f1->fret != f2->fret, %s, filter_return_str(item->fret),)')
m4_define(ECS, `FID_MEMBER(enum ec_subtype, ecs, ecs, f1->ecs != f2->ecs, ec subtype %s, ec_subtype_str(item->ecs), enum ec_subtype ecs = whati->ecs)')
m4_define(RTC, `FID_MEMBER(const struct rtable_config *, rtc, rtc, [[strcmp(f1->rtc->name, f2->rtc->name)]], route table %s, item->rtc->name, struct rtable *table = whati->rtc->table)')
m4_define(STATIC_ATTR, `FID_MEMBER(struct f_static_attr, sa, sa, f1->sa.sa_code != f2->sa.sa_code,,, struct f_static_attr sa = whati->sa)')
m4_define(DYNAMIC_ATTR, `FID_MEMBER(struct f_dynamic_attr, da, da, f1->da.ea_code != f2->da.ea_code,,, struct f_dynamic_attr da = whati->da)')
m4_define(COUNT, `FID_MEMBER(uint, count, count, f1->count != f2->count, number %u, item->count)')
m4_define(TREE, `FID_MEMBER(const struct f_tree *, tree, tree, [[!same_tree(f1->tree, f2->tree)]], tree %p, item->tree, const struct f_tree *tree = whati->tree)')
m4_define(STRING, `FID_MEMBER(const char *, s, s, [[strcmp(f1->s, f2->s)]], string \"%s\", item->s)')

m4_define(FID_WR_PUT_LIST)
m4_define(FID_WR_DROP_LIST)

m4_define(FID_WR_IPUT, `m4_define([[FID_WR_CUR_DIRECT]], m4_eval(FID_WR_CUR_DIRECT + 1))m4_define([[FID_WR_PUT_LIST]], FID_WR_PUT_LIST[[]]FID_WR_DPUT($1)FID_WR_DPUT(FID_WR_CUR_DIRECT))m4_divert(FID_WR_CUR_DIRECT)')
m4_define(FID_WR_IDROP, `m4_define([[FID_WR_CUR_DIRECT]], m4_eval(FID_WR_CUR_DIRECT + 1))m4_define([[FID_WR_DROP_LIST]], FID_WR_DROP_LIST[[]]FID_WR_DPUT($1)FID_WR_DPUT(FID_WR_CUR_DIRECT))m4_divert(FID_WR_CUR_DIRECT)')

m4_define(FID_WR_DIRECT, `m4_define([[FID_WR_CUR_DIRECT]],$1)m4_ifelse(TARGET,[[$2]],[[m4_define([[FID_WR_PUT]], [[FID_WR_IPUT($]][[@)]])m4_define([[FID_WR_PUT_LIST]],FID_WR_PUT_LIST[[]]FID_WR_DPUT($1))]],[[m4_define([[FID_WR_PUT]], [[FID_WR_IDROP($]][[@)]])m4_define([[FID_WR_DROP_LIST]],FID_WR_DROP_LIST[[]]FID_WR_DPUT($1))]])m4_divert($1)')

m4_dnl m4_define(FID_WR_CUR_DIRECT,m4_ifelse(TARGET,`C',800,TARGET,`H',900,m4_errprint(`Bad TARGET: 'TARGET)m4_m4exit(1)))
m4_changequote([[,]])
FID_WR_DIRECT(700,I)
FID_WR_PUT(10)
FID_WR_DIRECT(800,C)
#include "nest/bird.h"
#include "filter/filter.h"
#include "filter/f-inst.h"

/* Instruction codes to string */
static const char * const f_instruction_name_str[] = {
FID_WR_PUT(5)
};

const char *
f_instruction_name(enum f_instruction_code fi)
{
  if (fi < (sizeof(f_instruction_name_str) / sizeof(f_instruction_name_str[0])))
    return f_instruction_name_str[fi];
  else
    bug("Got unknown instruction code: %d", fi);
}

/* Instruction constructors */
FID_WR_PUT(3)

/* Line dumpers */
#define INDENT (((const char *) f_dump_line_indent_str) + sizeof(f_dump_line_indent_str) - (indent) - 1)
static const char f_dump_line_indent_str[] = "                                ";

FID_WR_PUT(6)

void f_dump_line(const struct f_line *dest, uint indent)
{
  if (!dest) {
    debug("%sNo filter line (NULL)\n", INDENT);
    return;
  }
  debug("%sFilter line %p (len=%u)\n", INDENT, dest, dest->len);
  for (uint i=0; i<dest->len; i++) {
    const struct f_line_item *item = &dest->items[i];
    debug("%sInstruction %s at line %u\n", INDENT, f_instruction_name(item->fi_code), item->lineno);
    switch (item->fi_code) {
FID_WR_PUT(7)
      default: bug("Unknown instruction %x in f_dump_line", item->fi_code);
    }
  }
  debug("%sFilter line %p dump done\n", INDENT, dest);
}

/* Linearize */
static uint
linearize(struct f_line *dest, const struct f_inst *what_, uint pos)
{
  for ( ; what_; what_ = what_->next) {
    switch (what_->fi_code) {
FID_WR_PUT(8)
    }
    pos++;
  }
  return pos;
}

struct f_line *
f_linearize_concat(const struct f_inst * const inst[], uint count)
{
  uint len = 0;
  for (uint i=0; i<count; i++)
    for (const struct f_inst *what = inst[i]; what; what = what->next)
      len += what->size;

  struct f_line *out = cfg_allocz(sizeof(struct f_line) + sizeof(struct f_line_item)*len);

  for (uint i=0; i<count; i++)
    out->len = linearize(out, inst[i], out->len);

#if DEBUGGING
  f_dump_line(out, 0);
#endif
  return out;
}

/* Filter line comparison */
int
f_same(const struct f_line *fl1, const struct f_line *fl2)
{
  if ((!fl1) && (!fl2))
    return 1;
  if ((!fl1) || (!fl2))
    return 0;
  if (fl1->len != fl2->len)
    return 0;
  for (uint i=0; i<fl1->len; i++) {
#define f1_ (&(fl1->items[i]))
#define f2_ (&(fl2->items[i]))
    if (f1_->fi_code != f2_->fi_code)
      return 0;
    if (f1_->flags != f2_->flags)
      return 0;

    switch(f1_->fi_code) {
FID_WR_PUT(9)
    }
  }
#undef f1_
#undef f2_
  return 1;
}


FID_WR_DIRECT(900,H)
/* Filter instruction codes */
enum f_instruction_code {
FID_WR_PUT(4)
} PACKED;

/* Filter instruction structure for config */
struct f_inst {
  struct f_inst *next;			/* Next instruction */
  enum f_instruction_code fi_code;	/* Instruction code */
  int size;				/* How many instructions are underneath */
  int lineno;				/* Line number */
  uint constant:1;			/* This instruction has constant value */
  union {
    FID_WR_PUT(1)
  };
};

/* Filter line item */
struct f_line_item {
  enum f_instruction_code fi_code;	/* What to do */
  enum f_instruction_flags flags;	/* Flags, instruction-specific */
  uint lineno;				/* Where */
  union {
    FID_WR_PUT(2)
  };
};

/* Instruction constructors */
FID_WR_PUT(3)

m4_divert(-1)
m4_changequote(`,')

m4_m4wrap(`INST_FLUSH()m4_define(FID_WR_DPUT, [[m4_undivert($1)]])m4_divert(0)FID_WR_PUT_LIST[[]]m4_divert(-1)FID_WR_DROP_LIST[[]]')

m4_changequote([[,]])

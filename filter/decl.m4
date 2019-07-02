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
#	Final diversions
#	200+	completed text before it is flushed to output

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

m4_define(FID_STRUCT_IN, `m4_divert(101)')
m4_define(FID_NEW_ARGS, `m4_divert(102)')
m4_define(FID_NEW_BODY, `m4_divert(103)')
m4_define(FID_DUMP_BODY, `m4_divert(104)m4_define([[FID_DUMP_BODY_EXISTS]])')
m4_define(FID_LINEARIZE_BODY, `m4_divert(105)m4_define([[FID_LINEARIZE_BODY_EXISTS]])')
m4_define(FID_SAME_BODY, `m4_divert(106)')
m4_define(FID_LINE_IN, `m4_divert(107)')
m4_define(FID_INTERPRET_BODY, `m4_divert(108)')

m4_define(FID_ALL, `FID_INTERPRET_BODY');
m4_define(FID_HIC, `m4_ifelse(TARGET, [[H]], [[$1]], TARGET, [[I]], [[$2]], TARGET, [[C]], [[$3]])')

m4_define(FID_INTERPRET_EXEC, `FID_HIC(,[[FID_INTERPRET_BODY()]],[[m4_divert(-1)]])')
m4_define(FID_INTERPRET_NEW,  `FID_HIC(,[[m4_divert(-1)]],[[FID_INTERPRET_BODY()]])')
m4_define(NEVER_CONSTANT, `m4_define([[INST_NEVER_CONSTANT]])')
m4_define(FID_IFCONST, `m4_ifdef([[INST_NEVER_CONSTANT]],[[$2]],[[$1]])')

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
FID_HIC(
[[
struct f_inst *f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)
);]],
[[
  case INST_NAME():
  #define whati (&(what->i_]]INST_NAME()[[))
  m4_ifelse(m4_eval(INST_INVAL() > 0), 1, [[if (fstk->vcnt < INST_INVAL()) runtime("Stack underflow"); fstk->vcnt -= INST_INVAL(); ]])
  m4_undivert(108)
  #undef whati
  break;
]],
[[
struct f_inst *f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)
)
  {
    struct f_inst *what = fi_new(fi_code);
    FID_IFCONST([[uint constargs = 1;]])
  #define whati (&(what->i_]]INST_NAME()[[))
  m4_undivert(103)
    FID_IFCONST([[if (!constargs)]])
      return what;
    FID_IFCONST([[m4_undivert(108)]])
  #undef whati
  }
]])

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
m4_divert(-1)FID_FLUSH(101,200)
]])')

m4_define(INST, `m4_dnl
INST_FLUSH()m4_dnl
m4_define([[INST_NAME]], [[$1]])m4_dnl
m4_define([[INST_INVAL]], [[$2]])m4_dnl
m4_undefine([[INST_NEVER_CONSTANT]])m4_dnl
FID_ALL() m4_dnl
')

m4_define(FID_MEMBER, `m4_dnl
FID_LINE_IN
$1 $2;
FID_STRUCT_IN
$1 $2;
FID_NEW_ARGS
, $1 $2
FID_NEW_BODY
whati->$2 = $2;
FID_LINEARIZE_BODY
item->$2 = whati->$2;
m4_ifelse($3,,,[[
FID_SAME_BODY
if ($3) return 0;
]])
m4_ifelse($4,,,[[
FID_DUMP_BODY
debug("%s$4\n", INDENT, $5);
]])
FID_INTERPRET_EXEC
const $1 $2 = whati->$2
FID_ALL')

m4_define(ARG_ANY, `
FID_STRUCT_IN
struct f_inst * f$1;
FID_NEW_ARGS
, struct f_inst * f$1
FID_NEW_BODY
whati->f$1 = f$1;
for (const struct f_inst *child = f$1; child; child = child->next) {
  what->size += child->size;
FID_IFCONST([[
  if (child->fi_code != FI_CONSTANT)
    constargs = 0;
]])
}
FID_LINEARIZE_BODY
pos = linearize(dest, whati->f$1, pos);
FID_ALL()')

m4_define(ARG, `ARG_ANY($1)
FID_INTERPRET_EXEC()
if (v$1.type != $2) runtime("Argument $1 of instruction %s must be of type $2, got 0x%02x", f_instruction_name(what->fi_code), v$1.type)m4_dnl
FID_ALL()')

m4_define(LINEX, `FID_INTERPRET_EXEC()LINEX_($1)FID_INTERPRET_NEW()return $1 FID_ALL()')
m4_define(LINEX_, `do {
  fstk->estk[fstk->ecnt].pos = 0;
  fstk->estk[fstk->ecnt].line = $1;
  fstk->estk[fstk->ecnt].ventry = fstk->vcnt;
  fstk->estk[fstk->ecnt].vbase = fstk->estk[fstk->ecnt-1].vbase;
  fstk->estk[fstk->ecnt].emask = 0;
  fstk->ecnt++;
} while (0)')

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
item->fl$1 = f_linearize(whati->f$1);
FID_SAME_BODY
if (!f_same(f1->fl$1, f2->fl$1)) return 0;
FID_INTERPRET_EXEC
do { if (whati->fl$1) {
  LINEX_(whati->fl$1);
} } while(0)
FID_INTERPRET_NEW
return whati->f$1
FID_ALL()')

m4_define(RESULT, `RESULT_VAL([[ (struct f_val) { .type = $1, .val.$2 = $3 } ]])')
m4_define(RESULT_VAL, `FID_HIC(, [[do { res = $1; fstk->vcnt++; } while (0)]],
[[return fi_constant(what, $1)]])')
m4_define(RESULT_VOID, `RESULT_VAL([[ (struct f_val) { .type = T_VOID } ]])')

m4_define(SYMBOL, `FID_MEMBER(struct symbol *, sym, 
[[strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)]], symbol %s, item->sym->name)')
m4_define(RTC, `FID_MEMBER(struct rtable_config *, rtc, [[strcmp(f1->rtc->name, f2->rtc->name)]], route table %s, item->rtc->name)')
m4_define(STATIC_ATTR, `FID_MEMBER(struct f_static_attr, sa, f1->sa.sa_code != f2->sa.sa_code,,)')
m4_define(DYNAMIC_ATTR, `FID_MEMBER(struct f_dynamic_attr, da, f1->da.ea_code != f2->da.ea_code,,)')
m4_define(ACCESS_RTE, `NEVER_CONSTANT()')

m4_define(FID_WR_PUT_LIST)
m4_define(FID_WR_PUT_ALSO, `m4_define([[FID_WR_PUT_LIST]],FID_WR_PUT_LIST()[[FID_WR_DPUT(]]FID_WR_DIDX[[)FID_WR_DPUT(]]$1[[)]])m4_define([[FID_WR_DIDX]],m4_eval(FID_WR_DIDX+1))m4_divert(FID_WR_DIDX)')

m4_define(FID_WR_DIRECT, `m4_ifelse(TARGET,[[$1]],[[FID_WR_INIT()]],[[FID_WR_STOP()]])')
m4_define(FID_WR_INIT, `m4_define([[FID_WR_DIDX]],200)m4_define([[FID_WR_PUT]],[[FID_WR_PUT_ALSO($]][[@)]])m4_divert(200)')
m4_define(FID_WR_STOP, `m4_define([[FID_WR_PUT]])m4_divert(-1)')

m4_changequote([[,]])
FID_WR_DIRECT(I)
FID_WR_PUT(3)
FID_WR_DIRECT(C)

#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#endif

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

static inline struct f_inst *
fi_new(enum f_instruction_code fi_code)
{
  struct f_inst *what = cfg_allocz(sizeof(struct f_inst));
  what->lineno = ifs->lino;
  what->size = 1;
  what->fi_code = fi_code;
  return what;
}

static inline struct f_inst *
fi_constant(struct f_inst *what, struct f_val val)
{
  what->fi_code = FI_CONSTANT;
  what->i_FI_CONSTANT.val = val;
  return what;
}

#define v1 whati->f1->i_FI_CONSTANT.val
#define v2 whati->f2->i_FI_CONSTANT.val
#define v3 whati->f3->i_FI_CONSTANT.val
#define runtime(fmt, ...) cf_error("filter preevaluation, line %d: " fmt, ifs->lino, ##__VA_ARGS__)
#define fpool cfg_mem
#define falloc(size) cfg_alloc(size)
/* Instruction constructors */
FID_WR_PUT(3)
#undef v1
#undef v2
#undef v3

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
linearize(struct f_line *dest, const struct f_inst *what, uint pos)
{
  for ( ; what; what = what->next) {
    switch (what->fi_code) {
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

#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic pop
#endif

FID_WR_DIRECT(H)
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

m4_define(FID_FLUSH, `m4_ifelse($1,$2,,[[m4_undivert($1)FID_FLUSH(m4_eval($1+1),$2)]])')
m4_define(FID_WR_DPUT, `m4_undivert($1)')

m4_m4wrap(`INST_FLUSH()m4_divert(0)FID_WR_PUT_LIST()m4_divert(-1)FID_FLUSH(1,200)')

m4_changequote([[,]])

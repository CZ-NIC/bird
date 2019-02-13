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
#	8	postfixify
#	9	same (filter comparator)
#	1	struct f_inst_FI_...
#	2	union in struct f_inst
#	3	constructors
#
#	Per-inst Diversions:
#	101	content of struct f_inst_FI_...
#	102	constructor arguments
#	103	constructor body
#	104	dump line item content
#	105	postfixify body
#	106	comparator body
#
#	Diversions for TARGET=C: 8xx
#	Diversions for TARGET=H: 9xx

# Flush the completed instruction
m4_define(FID_END, `m4_divert(-1)')

m4_dnl m4_debugmode(aceflqtx)

m4_define(FID_ZONE, `m4_divert($1) /* $2 for INST_NAME() */')
m4_define(FID_STRUCT, `FID_ZONE(1, Per-instruction structure)')
m4_define(FID_UNION, `FID_ZONE(2, Union member)')
m4_define(FID_NEW, `FID_ZONE(3, Constructor)')
m4_define(FID_ENUM, `FID_ZONE(4, Code enum)')
m4_define(FID_ENUM_STR, `FID_ZONE(5, Code enum to string)')
m4_define(FID_DUMP, `FID_ZONE(6, Dump line)')
m4_define(FID_DUMP_CALLER, `FID_ZONE(7, Dump line caller)')
m4_define(FID_POSTFIXIFY, `FID_ZONE(8, Postfixify)')
m4_define(FID_SAME, `FID_ZONE(9, Comparison)')

m4_define(FID_STRUCT_IN, `m4_divert(101)')
m4_define(FID_NEW_ARGS, `m4_divert(102)')
m4_define(FID_NEW_BODY, `m4_divert(103)')
m4_define(FID_DUMP_BODY, `m4_divert(104)m4_define([[FID_DUMP_BODY_EXISTS]])')
m4_define(FID_POSTFIXIFY_BODY, `m4_divert(105)m4_define([[FID_POSTFIXIFY_BODY_EXISTS]])')
m4_define(FID_SAME_BODY, `m4_divert(106)')

m4_define(FID_ALL, `m4_ifdef([[FID_CURDIV]], [[m4_divert(FID_CURDIV)m4_undefine([[FID_CURDIV]])]])')
m4_define(FID_C, `m4_ifelse(TARGET, [[C]], FID_ALL, [[m4_define(FID_CURDIV, m4_divnum)m4_divert(-1)]])')
m4_define(FID_H, `m4_ifelse(TARGET, [[H]], FID_ALL, [[m4_define(FID_CURDIV, m4_divnum)m4_divert(-1)]])')


m4_define(INST_FLUSH, `m4_ifdef([[INST_NAME]], [[
FID_ENUM
INST_NAME(),
FID_ENUM_STR
[INST_NAME()] = "INST_NAME()",
FID_STRUCT
struct f_inst_[[]]INST_NAME() {
m4_undivert(101)
};
FID_UNION
struct f_inst_[[]]INST_NAME() i_[[]]INST_NAME();
FID_NEW
struct f_inst *f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)
)
FID_H
;
FID_C
{
  struct f_inst *what_ = cfg_allocz(sizeof(struct f_inst));
  what_->fi_code = fi_code;
  what_->lineno = ifs->lino;
  what_->size = 1;
  struct f_inst_[[]]INST_NAME() *what UNUSED = &(what_->i_[[]]INST_NAME());
m4_undivert(103)
  return what_;
}

FID_DUMP_CALLER
case INST_NAME(): f_dump_line_item_]]INST_NAME()[[(item, indent + 1); break;

FID_DUMP
m4_ifdef([[FID_DUMP_BODY_EXISTS]],
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item, const int indent)]]
,
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item UNUSED, const int indent UNUSED)]])
m4_undefine([[FID_DUMP_BODY_EXISTS]])
{
m4_undivert(104)
}
FID_ALL

FID_POSTFIXIFY
case INST_NAME(): {
m4_ifdef([[FID_POSTFIXIFY_BODY_EXISTS]], [[const struct f_inst_]]INST_NAME()[[ *what = &(what_->i_]]INST_NAME()[[);]], [[]])
  m4_undivert(105)
  dest->items[pos].fi_code = what_->fi_code;
  dest->items[pos].lineno = what_->lineno;
  break;
}
m4_undefine([[FID_POSTFIXIFY_BODY_EXISTS]])

FID_SAME
case INST_NAME():
m4_undivert(106)
break;

FID_END
]])')

m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])')

m4_dnl FID_MEMBER call:
m4_dnl type
m4_dnl name in f_inst
m4_dnl name in f_line_item
m4_dnl comparator for same
m4_dnl dump format string
m4_dnl dump format args
m4_define(FID_MEMBER, `m4_dnl
FID_STRUCT_IN
$1 $2;
FID_NEW_ARGS
, $1 $2
FID_NEW_BODY
what->$2 = $2;
m4_ifelse($3,,,[[
FID_POSTFIXIFY_BODY
dest->items[pos].$3 = what->$2;
]])
m4_ifelse($4,,,[[
FID_SAME_BODY
if ($4) return 0;
]])
m4_ifelse($5,,,[[
FID_DUMP_BODY
debug("%s$5\n", INDENT, $6);
]])
FID_END')

m4_define(ARG, `FID_MEMBER(const struct f_inst *, f$1,,,,)
FID_NEW_BODY
for (const struct f_inst *child = f$1; child; child = child->next) what_->size += child->size;
FID_POSTFIXIFY_BODY
pos = postfixify(dest, what->f$1, pos);
FID_END')
m4_define(ARG_ANY, `FID_MEMBER(const struct f_inst *, f$1,,,,)
FID_NEW_BODY
for (const struct f_inst *child = f$1; child; child = child->next) what_->size += child->size;
FID_POSTFIXIFY_BODY
pos = postfixify(dest, what->f$1, pos);
FID_END')
m4_define(LINE, `FID_MEMBER(const struct f_inst *, f$1,,[[!f_same(f1->lines[$2], f2->lines[$2])]],,)
FID_DUMP_BODY
f_dump_line(item->lines[$2], indent + 1);
FID_POSTFIXIFY_BODY
dest->items[pos].lines[$2] = f_postfixify(what->f$1);
FID_END')
m4_define(LINEP, `FID_STRUCT_IN
const struct f_line *fl$1;
FID_DUMP_BODY
f_dump_line(item->lines[$2], indent + 1)
FID_POSTFIXIFY_BODY
dest->items[pos].lines[$2] = what->fl$1;
FID_SAME_BODY
if (!f_same(f1->lines[$2], f2->lines[$2])) return 0;
FID_END')
m4_define(SYMBOL, `FID_MEMBER(const struct symbol *, sym, sym,
[[strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)]], symbol %s, item->sym->name)')
m4_define(VALI, `FID_MEMBER(struct f_val, vali, val, [[val_same(&f1->val, &f2->val)]], value %s, val_dump(&item->val))')
m4_define(VALP, `FID_MEMBER(const struct f_val *, valp,, [[val_same(&f1->val, &f2->val)]], value %s, val_dump(&item->val))
FID_POSTFIXIFY_BODY
dest->items[pos].val = *(what->valp);
FID_END')
m4_define(VAR, `m4_dnl
FID_STRUCT_IN
const struct f_val *valp;
const struct symbol *sym;
FID_NEW_ARGS
, const struct symbol *sym
FID_NEW_BODY
what->valp = (what->sym = sym)->def;
FID_POSTFIXIFY_BODY
dest->items[pos].vp = (dest->items[pos].sym = what->sym)->def;
FID_SAME_BODY
if (strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)) return 0;
FID_DUMP_BODY
debug("%svariable %s with value %s\n", INDENT, item->sym->name, val_dump(item->vp));
FID_END')
m4_define(FRET, `FID_MEMBER(enum filter_return, fret, fret, f1->fret != f2->fret, %s, filter_return_str(item->fret))')
m4_define(ECS, `FID_MEMBER(enum ec_subtype, ecs, ecs, f1->ecs != f2->ecs, ec subtype %s, ec_subtype_str(item->ecs))')
m4_define(RTC, `FID_MEMBER(const struct rtable_config *, rtc, rtc, [[strcmp(f1->rtc->name, f2->rtc->name)]], route table %s, item->rtc->name)')
m4_define(STATIC_ATTR, `FID_MEMBER(struct f_static_attr, sa, sa, f1->sa.sa_code != f2->sa.sa_code)')
m4_define(DYNAMIC_ATTR, `FID_MEMBER(struct f_dynamic_attr, da, da, f1->da.ea_code != f2->da.ea_code)')
m4_define(COUNT, `FID_MEMBER(uint, count, count, f1->count != f2->count, number %u, item->count)')
m4_define(TREE, `FID_MEMBER(const struct f_tree *, tree, tree, [[!same_tree(f1->tree, f2->tree)]], tree %p, item->tree)')
m4_define(STRING, `FID_MEMBER(const char *, s, s, [[strcmp(f1->s, f2->s)]], string \"%s\", item->s)')

m4_define(FID_WR_PUT_LIST)
m4_define(FID_WR_DROP_LIST)

m4_define(FID_WR_IPUT, `m4_define([[FID_WR_CUR_DIRECT]], m4_eval(FID_WR_CUR_DIRECT + 1))m4_define([[FID_WR_PUT_LIST]], FID_WR_PUT_LIST[[]]FID_WR_DPUT($1)FID_WR_DPUT(FID_WR_CUR_DIRECT))m4_divert(FID_WR_CUR_DIRECT)')
m4_define(FID_WR_IDROP, `m4_define([[FID_WR_CUR_DIRECT]], m4_eval(FID_WR_CUR_DIRECT + 1))m4_define([[FID_WR_DROP_LIST]], FID_WR_DROP_LIST[[]]FID_WR_DPUT($1)FID_WR_DPUT(FID_WR_CUR_DIRECT))m4_divert(FID_WR_CUR_DIRECT)')

m4_define(FID_WR_DIRECT, `m4_define([[FID_WR_CUR_DIRECT]],$1)m4_ifelse(TARGET,[[$2]],[[m4_define([[FID_WR_PUT]], [[FID_WR_IPUT($]][[@)]])m4_define([[FID_WR_PUT_LIST]],FID_WR_PUT_LIST[[]]FID_WR_DPUT($1))]],[[m4_define([[FID_WR_PUT]], [[FID_WR_IDROP($]][[@)]])m4_define([[FID_WR_DROP_LIST]],FID_WR_DROP_LIST[[]]FID_WR_DPUT($1))]])m4_divert($1)')

m4_dnl m4_define(FID_WR_CUR_DIRECT,m4_ifelse(TARGET,`C',800,TARGET,`H',900,m4_errprint(`Bad TARGET: 'TARGET)m4_m4exit(1)))
m4_changequote([[,]])
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
void f_dump_line(const struct f_line *dest, int indent);

FID_WR_PUT(6)

void f_dump_line(const struct f_line *dest, int indent)
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

/* Postfixify */
static uint
postfixify(struct f_line *dest, const struct f_inst *what_, uint pos)
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
f_postfixify_concat(const struct f_inst * const inst[], uint count)
{
  uint len = 0;
  for (uint i=0; i<count; i++)
    for (const struct f_inst *what = inst[i]; what; what = what->next)
      len += what->size;

  struct f_line *out = cfg_allocz(sizeof(struct f_line) + sizeof(struct f_line_item)*len);

  for (uint i=0; i<count; i++)
    out->len = postfixify(out, inst[i], out->len);

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
#define f1 (&(fl1->items[i]))
#define f2 (&(fl2->items[i]))
    if (f1->fi_code != f2->fi_code)
      return 0;
    if (f1->flags != f2->flags)
      return 0;

    switch(f1->fi_code) {
FID_WR_PUT(9)
    }
  }
  return 1;
}


FID_WR_DIRECT(900,H)
/* Filter instruction codes */
enum f_instruction_code {
FID_WR_PUT(4)
};

/* Per-instruction structures */
FID_WR_PUT(1)

struct f_inst {
  const struct f_inst *next;		/* Next instruction */
  enum f_instruction_code fi_code;	/* Instruction code */
  int size;				/* How many instructions are underneath */
  int lineno;				/* Line number */
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

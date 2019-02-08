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
#	1	struct f_inst_FI_...
#	2	union in struct f_inst
#	3	constructors
#
#	Per-inst Diversions:
#	11	content of struct f_inst_FI_...
#	12	constructor arguments
#	13	constructor body

# Flush the completed instruction

m4_define(FID_END, `m4_divert(-1)')

m4_define(FID_ZONE, `m4_divert($1) /* $2 for INST_NAME() */')
m4_define(FID_STRUCT, `FID_ZONE(1, Per-instruction structure)')
m4_define(FID_UNION, `FID_ZONE(2, Union member)')
m4_define(FID_NEW, `FID_ZONE(3, Constructor)')
m4_define(FID_ENUM, `FID_ZONE(4, Code enum)')

m4_define(FID_STRUCT_IN, `m4_divert(101)')
m4_define(FID_NEW_ARGS, `m4_divert(102)')
m4_define(FID_NEW_BODY, `m4_divert(103)')

m4_define(INST_FLUSH, `m4_ifdef([[INST_NAME]], [[
FID_ENUM
INST_NAME(),
FID_STRUCT
struct f_inst_[[]]INST_NAME() {
m4_undivert(101)
};
FID_UNION
struct f_inst_[[]]INST_NAME() i_[[]]INST_NAME();
FID_NEW
static inline struct f_inst *f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)
) {
  struct f_inst *what_ = cfg_allocz(sizeof(struct f_inst));
  what_->fi_code = fi_code;
  what_->lineno = ifs->lino;
  what_->size = 1;
  struct f_inst_[[]]INST_NAME() *what UNUSED = &(what_->i_[[]]INST_NAME());
m4_undivert(103)
  return what_;
}
FID_END
]])')

m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])')

m4_define(FID_MEMBER, `m4_dnl
FID_STRUCT_IN
$1 $2;
FID_NEW_ARGS
, $1 $2
FID_NEW_BODY
what->$2 = $2;
FID_END')

m4_define(ARG, `FID_MEMBER(const struct f_inst *, f$1)
FID_NEW_BODY
for (const struct f_inst *child = f$1; child; child = child->next) what_->size += child->size;
FID_END')
m4_define(ARG_ANY, `FID_MEMBER(const struct f_inst *, f$1)
FID_NEW_BODY
for (const struct f_inst *child = f$1; child; child = child->next) what_->size += child->size;
FID_END')
m4_define(LINE, `FID_MEMBER(const struct f_inst *, f$1)')
m4_define(LINEP, `FID_STRUCT_IN
const struct f_line *fl$1;
FID_END')
m4_define(SYMBOL, `FID_MEMBER(const struct symbol *, sym)')
m4_define(VALI, `FID_MEMBER(struct f_val, vali)')
m4_define(VALP, `FID_MEMBER(const struct f_val *, valp)')
m4_define(VAR, `m4_dnl
FID_STRUCT_IN
const struct f_val *valp;
const struct symbol *sym;
FID_NEW_ARGS
, const struct symbol *sym
FID_NEW_BODY
what->valp = (what->sym = sym)->def;
FID_END')
m4_define(FRET, `FID_MEMBER(enum filter_return, fret)')
m4_define(ECS, `FID_MEMBER(enum ec_subtype, ecs)')
m4_define(RTC, `FID_MEMBER(const struct rtable_config *, rtc)')
m4_define(STATIC_ATTR, `FID_MEMBER(struct f_static_attr, sa)')
m4_define(DYNAMIC_ATTR, `FID_MEMBER(struct f_dynamic_attr, da)')
m4_define(COUNT, `FID_MEMBER(uint, count)')
m4_define(TREE, `FID_MEMBER(const struct f_tree *, tree)')
m4_define(STRING, `FID_MEMBER(const char *, s)')

m4_m4wrap(`
INST_FLUSH()
m4_divert(0)
/* Filter instruction codes */
enum f_instruction_code {
m4_undivert(4)
};

/* Per-instruction structures */
m4_undivert(1)

struct f_inst {
  const struct f_inst *next;		/* Next instruction */
  enum f_instruction_code fi_code;	/* Instruction code */
  int size;				/* How many instructions are underneath */
  int lineno;				/* Line number */
  union {
    m4_undivert(2)
  };
};

/* Instruction constructors */
m4_undivert(3)
')

m4_changequote([[,]])

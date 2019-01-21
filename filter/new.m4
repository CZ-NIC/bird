m4_divert(-1)m4_dnl
#
#	BIRD -- Construction of per-instruction structures
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#
#
#	Diversions:
#	1	for prepared output
#	2	for function arguments
#	3	for function body

# Common aliases
m4_define(DNL, `m4_dnl')

m4_define(FNSTOP, `m4_divert(-1)')
m4_define(FNOUT, `m4_divert(1)')
m4_define(FNARG, `m4_divert(2)')
m4_define(FNBODY, `m4_divert(3)')

m4_define(INST,	`m4_define([[INST_NAME]], [[$1]])FNOUT()DNL
m4_undivert(2)DNL
m4_undivert(3)DNL
  return what;
}

struct f_inst *f_new_inst_$1(enum f_instruction_code fi_code
FNBODY()) {
  struct f_inst *what = cfg_allocz(sizeof(struct f_inst));
  what->fi_code = fi_code;
  what->lineno = ifs->lino;
FNSTOP()')

m4_define(WHAT, `what->i_[[]]INST_NAME()')

m4_define(FNMETAARG, `FNARG(), $1 $2
FNBODY() WHAT().$2 = $2;
FNSTOP()')
m4_define(ARG, `FNMETAARG(const struct f_inst *, f$1)')
m4_define(ARG_ANY, `FNMETAARG(const struct f_inst *, f$1)')
m4_define(LINE, `FNMETAARG(const struct f_inst *, f$1)')
m4_define(SYMBOL, `FNMETAARG(const struct symbol *, sym)')
m4_define(VALI, `FNMETAARG(struct f_val, vali)')
m4_define(VALP, `FNMETAARG(const struct f_val *, valp)')
m4_define(VAR, `FNARG(), const struct symbol * sym
FNBODY() WHAT().valp = (WHAT().sym = sym)->def;
FNSTOP()')
m4_define(FRET, `FNMETAARG(enum filter_return, fret)')
m4_define(ECS, `FNMETAARG(enum ec_subtype, ecs)')
m4_define(RTC, `FNMETAARG(const struct rtable_config *, rtc)')
m4_define(STATIC_ATTR, `FNMETAARG(struct f_static_attr, sa)')
m4_define(DYNAMIC_ATTR, `FNMETAARG(struct f_dynamic_attr, da)')
m4_define(COUNT, `FNMETAARG(uint, count)')
m4_define(TREE, `FNMETAARG(const struct f_tree *, tree)')
m4_define(STRING, `FNMETAARG(const char *, s)')
m4_define(NEW, `FNARG()$1
FNBODY()$2
FNSTOP()')

m4_m4wrap(`
FNOUT()
m4_undivert(2)
m4_undivert(3)

m4_divert(0)
#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "filter/f-inst-struct.h"

struct f_inst *f_new_inst_FI_NOP(enum f_instruction_code fi_code) {
  struct f_inst *what = cfg_allocz(sizeof(struct f_inst));
  what->fi_code = fi_code;
  what->lineno = ifs->lino;

m4_undivert(1)

  return what;
}
')

m4_changequote([[,]])

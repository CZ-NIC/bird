m4_divert(-1)m4_dnl
#
#	BIRD -- Definition of per-instruction structures
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#

# Common aliases
m4_define(DNL, `m4_dnl')

m4_define(INST,	`m4_divert(2)struct f_inst_$1 i_$1;
m4_divert(1)};
struct f_inst_$1 {
m4_divert(-1)'))
m4_define(ARG, `m4_divert(1)const struct f_inst *f$1;
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(1)const struct f_inst *f$1;
m4_divert(-1)')
m4_define(LINE, `m4_divert(1)const struct f_inst *f$1;
m4_divert(-1)')
m4_define(LINEP, `m4_divert(1)const struct f_line *fl$1;
m4_divert(-1)')
m4_define(SYMBOL, `m4_divert(1)const struct symbol *sym;
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)struct f_val vali;
m4_divert(-1)')
m4_define(VALP, `m4_divert(1)const struct f_val *valp;
m4_divert(-1)')
m4_define(VAR, `VALP()SYMBOL()')
m4_define(FRET, `m4_divert(1)enum filter_return fret;
m4_divert(-1)')
m4_define(ECS, `m4_divert(1)enum ec_subtype ecs;
m4_divert(-1)')
m4_define(RTC, `m4_divert(1)const struct rtable_config *rtc;
m4_divert(-1)')
m4_define(STATIC_ATTR, `m4_divert(1)struct f_static_attr sa;
m4_divert(-1)')
m4_define(DYNAMIC_ATTR, `m4_divert(1)struct f_dynamic_attr da;
m4_divert(-1)')
m4_define(COUNT, `m4_divert(1)uint count;
m4_divert(-1)')
m4_define(TREE, `m4_divert(1)const struct f_tree *tree;
m4_divert(-1)')
m4_define(STRING, `m4_divert(1)const char *s;
m4_divert(-1)')
m4_define(STRUCT, `m4_divert(1)$1
m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
struct f_inst_FI_NOP {
m4_undivert(1)
};

struct f_inst {
  const struct f_inst *next;		/* Next instruction */
  enum f_instruction_code fi_code;	/* Instruction code */
  int lineno;				/* Line number */
  union {
    m4_undivert(2)
  };
};
')

m4_changequote([[,]])

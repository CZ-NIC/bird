m4_divert(-1)m4_dnl
#
#	BIRD -- Line size counting
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#

# Common aliases
m4_define(DNL, `m4_dnl')

m4_define(INST, `m4_divert(1)
#undef what
break; case $1: cnt += 1;
#define what ((const struct f_inst_$1 *) &(what_->i_$1))
m4_divert(-1)')
m4_define(ARG, `m4_divert(1)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(ARG_T, `m4_divert(1)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(1)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(LINE_SIZE, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
#undef what
break; default: bug( "Unknown instruction %d (%c)", what_->fi_code, what_->fi_code & 0xff);
')

m4_changequote([[,]])

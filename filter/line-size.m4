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

m4_define(INST, `m4_divert(1)break; case $1: cnt += 1;
m4_divert(-1)')
m4_define(ARG_T, `m4_divert(1)cnt += inst_line_size(what->a[$1-1].p);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(1)cnt += inst_line_size(what->a[$1-1].p);
m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
break; default: bug( "Unknown instruction %d (%c)", what->fi_code, what->fi_code & 0xff);
')

m4_changequote([[,]])

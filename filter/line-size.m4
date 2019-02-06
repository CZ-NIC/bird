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

m4_define(INST_FLUSH, `m4_ifdef([[INST_NAME]], [[
m4_divert(1)
case INST_NAME():
cnt += 1;
#define what ((const struct f_inst_]]INST_NAME()[[ *) &(what_->i_]]INST_NAME()[[))
m4_undivert(2)
#undef what
break;
m4_divert(-1)
]])')
m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])')

m4_define(ARG, `m4_divert(2)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(ARG_T, `m4_divert(2)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(2)cnt += inst_line_size(what->f$1);
m4_divert(-1)')
m4_define(LINE_SIZE, `m4_divert(2)$1m4_divert(-1)')

m4_m4wrap(`
INST_FLUSH()
m4_divert(0)DNL
m4_undivert(1)

default: bug( "Unknown instruction %d (%c)", what_->fi_code, what_->fi_code & 0xff);
')

m4_changequote([[,]])

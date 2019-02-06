m4_divert(-1)m4_dnl
#
#	BIRD -- Converting instructions trees to instruction lines
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
#define what ((const struct f_inst_]]INST_NAME()[[ *) &(what_->i_]]INST_NAME()[[))
m4_undivert(2)
#undef what
dest->items[pos].fi_code = what_->fi_code;
dest->items[pos].lineno = what_->lineno;
break;
m4_divert(-1)
]])')
m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])')

m4_define(ARG, `m4_divert(2)pos = postfixify(dest, what->f$1, pos);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(2)pos = postfixify(dest, what->f$1, pos);
m4_divert(-1)')
m4_define(LINE, `m4_divert(2)dest->items[pos].lines[$2] = f_postfixify(what->f$1);
m4_divert(-1)')
m4_define(LINEP, `m4_divert(2)dest->items[pos].lines[$2] = what->fl$1;
m4_divert(-1)')
m4_define(SYMBOL, `m4_divert(2)dest->items[pos].sym = what->sym;
m4_divert(-1)')
m4_define(VALI, `m4_divert(2)dest->items[pos].val = what->vali;
m4_divert(-1)')
m4_define(VALP, `m4_divert(2)dest->items[pos].val = *(what->valp);
m4_divert(-1)')
m4_define(VAR, `m4_divert(2)dest->items[pos].vp = (dest->items[pos].sym = what->sym)->def;
m4_divert(-1)')
m4_define(FRET, `m4_divert(2)dest->items[pos].fret = what->fret;
m4_divert(-1)')
m4_define(ECS, `m4_divert(2)dest->items[pos].ecs = what->ecs;
m4_divert(-1)')
m4_define(RTC, `m4_divert(2)dest->items[pos].rtc = what->rtc;
m4_divert(-1)')
m4_define(STATIC_ATTR, `m4_divert(2)dest->items[pos].sa = what->sa;
m4_divert(-1)')
m4_define(DYNAMIC_ATTR, `m4_divert(2)dest->items[pos].da = what->da;
m4_divert(-1)')
m4_define(COUNT, `m4_divert(2)dest->items[pos].count = what->count;
m4_divert(-1)')
m4_define(TREE, `m4_divert(2)dest->items[pos].tree = what->tree;
m4_divert(-1)')
m4_define(STRING, `m4_divert(2)dest->items[pos].s = what->s;
m4_divert(-1)')
m4_define(POSTFIXIFY, `m4_divert(2)$1m4_divert(-1)')

m4_m4wrap(`
INST_FLUSH()
m4_divert(0)DNL
m4_undivert(1)

default: bug( "Unknown instruction %d (%c)", what_->fi_code, what_->fi_code & 0xff);
')

m4_changequote([[,]])

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

m4_define(POSTFIXIFY_TRAILER, `dest->items[pos].fi_code = what_->fi_code;
dest->items[pos].lineno = what_->lineno;')

m4_define(INST, `m4_divert(1)POSTFIXIFY_TRAILER
#undef what
break; case $1: 
#define what ((const struct f_inst_$1 *) &(what_->i_$1))
m4_divert(-1)'))
m4_define(ARG, `m4_divert(1)pos = postfixify(dest, what->f$1, pos);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(1)pos = postfixify(dest, what->f$1, pos);
m4_divert(-1)')
m4_define(LINE, `m4_divert(1)dest->items[pos].lines[$2] = f_postfixify(what->f$1);
m4_divert(-1)')
m4_define(LINEP, `m4_divert(1)dest->items[pos].lines[$2] = what->fl$1;
m4_divert(-1)')
m4_define(SYMBOL, `m4_divert(1)dest->items[pos].sym = what->sym;
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)dest->items[pos].val = what->vali;
m4_divert(-1)')
m4_define(VALP, `m4_divert(1)dest->items[pos].val = *(what->valp);
m4_divert(-1)')
m4_define(VAR, `m4_divert(1)dest->items[pos].vp = (dest->items[pos].sym = what->sym)->def;
m4_divert(-1)')
m4_define(FRET, `m4_divert(1)dest->items[pos].fret = what->fret;
m4_divert(-1)')
m4_define(ECS, `m4_divert(1)dest->items[pos].ecs = what->ecs;
m4_divert(-1)')
m4_define(RTC, `m4_divert(1)dest->items[pos].rtc = what->rtc;
m4_divert(-1)')
m4_define(STATIC_ATTR, `m4_divert(1)dest->items[pos].sa = what->sa;
m4_divert(-1)')
m4_define(DYNAMIC_ATTR, `m4_divert(1)dest->items[pos].da = what->da;
m4_divert(-1)')
m4_define(COUNT, `m4_divert(1)dest->items[pos].count = what->count;
m4_divert(-1)')
m4_define(TREE, `m4_divert(1)dest->items[pos].tree = what->tree;
m4_divert(-1)')
m4_define(STRING, `m4_divert(1)dest->items[pos].s = what->s;
m4_divert(-1)')
m4_define(POSTFIXIFY, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
POSTFIXIFY_TRAILER
#undef what
break; default: bug( "Unknown instruction %d (%c)", what_->fi_code, what_->fi_code & 0xff);
')

m4_changequote([[,]])

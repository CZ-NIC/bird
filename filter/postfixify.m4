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

m4_define(INST, `m4_divert(1)dest->items[pos].fi_code = what->fi_code;
dest->items[pos].lineno = what->lineno;
break; case $1:
m4_divert(-1)'))
m4_define(ARG, `m4_divert(1)pos = postfixify(dest, what->a[$1-1].p, pos);
m4_divert(-1)')
m4_define(ARG_ANY, `m4_divert(1)pos = postfixify(dest, what->a[$1-1].p, pos);
m4_divert(-1)')
m4_define(LINE, `m4_divert(1)dest->items[pos].lines[$2] = f_postfixify(what->a[$1-1].p);
m4_divert(-1)')
m4_define(SYMBOL, `m4_divert(1)dest->items[pos].sym = what->a[$1-1].p;
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)dest->items[pos].vp = &(what->val);
m4_divert(-1)')
m4_define(VALP, `m4_divert(1)dest->items[pos].vp = (dest->items[pos].sym = what->a[$1-1].p)->def;
m4_divert(-1)')
m4_define(FRET, `m4_divert(1)dest->items[pos].fret = what->a[$1-1].i;
m4_divert(-1)')
m4_define(POSTFIXIFY, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
break; default: bug( "Unknown instruction %d (%c)", what->fi_code, what->fi_code & 0xff);
')

m4_changequote([[,]])

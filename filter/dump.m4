m4_divert(-1)m4_dnl
#
#	BIRD -- Dumping instruction lines
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#

# Common aliases
m4_define(DNL, `m4_dnl')

m4_define(INST, `m4_divert(1)break; case $1:
m4_divert(-1)'))
m4_define(LINE, `m4_divert(1)f_dump_line(item->lines[$2], indent + 1);
m4_divert(-1)')
m4_define(SYMBOL, `m4_divert(1)debug("%ssymbol %s\n", INDENT, item->sym->name);
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)debug("%svalue %s\n", INDENT, val_dump(item->vp));
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)debug("%svalue %s\n", INDENT, val_dump(item->vp));
m4_divert(-1)')
m4_define(FRET, `m4_divert(1)debug("%sfilter return value %d\n", INDENT, item->fret);
m4_divert(-1)')
m4_define(DUMP, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
break; default: bug( "Unknown instruction %d (%c)", item->fi_code, item->fi_code & 0xff);
')

m4_changequote([[,]])

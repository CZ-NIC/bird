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
m4_define(LINEP, `LINE($@)')
m4_define(SYMBOL, `m4_divert(1)debug("%ssymbol %s\n", INDENT, item->sym->name);
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)debug("%svalue %s\n", INDENT, val_dump(item->vp));
m4_divert(-1)')
m4_define(VALI, `m4_divert(1)debug("%svalue %s\n", INDENT, val_dump(item->vp));
m4_divert(-1)')
m4_define(FRET, `m4_divert(1)debug("%sfilter return value %d\n", INDENT, item->fret);
m4_divert(-1)')
m4_define(ECS, `m4_divert(1)debug("%sec subtype %d\n", INDENT, item->ecs);
m4_divert(-1)')
m4_define(RTC, `m4_divert(1)debug("%sroute table %s\n", INDENT, item->rtc->name);
m4_divert(-1)')
m4_define(STATIC_ATTR, `m4_divert(1)debug("%sstatic attribute %u/%u/%u\n", INDENT, item->sa.f_type, item->sa.sa_code, item->sa.readonly);
m4_divert(-1)')
m4_define(DYNAMIC_ATTR, `m4_divert(1)debug("%sdynamic attribute %u/%u/%u/%u\n", INDENT, item->da.type, item->da.bit, item->da.f_type, item->da.ea_code);
m4_divert(-1)')
m4_define(DUMP, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
break; default: bug( "Unknown instruction %d (%c)", item->fi_code, item->fi_code & 0xff);
')

m4_changequote([[,]])

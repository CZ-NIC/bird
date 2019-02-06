m4_divert(-1)m4_dnl
#
#	BIRD -- Filter Comparator Generator
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
m4_undivert(2)
break;
m4_divert(-1)
]])')
m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])')

m4_define(ARG, `')
m4_define(ARG_ANY, `')

m4_define(LINE, `m4_divert(2)if (!f_same(f1->lines[$2], f2->lines[$2])) return 0;
m4_divert(-1)')
m4_define(LINEP, LINE)

m4_define(SYMBOL, `m4_divert(2){
  const struct symbol *s1 = f1->sym, *s2 = f2->sym;
  if (strcmp(s1->name, s2->name)) return 0;
  if (s1->class != s2->class) return 0;
}
m4_divert(-1)')

m4_define(VALI, `m4_divert(2)if (!val_same(f1->vp, f2->vp)) return 0;
m4_divert(-1)')
m4_define(VALP, `m4_divert(2)if (!val_same(f1->vp, f2->vp)) return 0;
m4_divert(-1)')
m4_define(VAR, `SYMBOL()VALP()')

m4_define(FRET, `m4_divert(2)if (f1->fret != f2->fret) return 0;
m4_divert(-1)')
m4_define(ECS, `m4_divert(2)if (f1->ecs != f2->ecs) return 0;
m4_divert(-1)')
m4_define(RTC, `m4_divert(2)if (strcmp(f1->rtc->name, f2->rtc->name)) return 0;
m4_divert(-1)')
m4_define(STATIC_ATTR, `m4_divert(2)if (f1->sa.sa_code != f2->sa.sa_code) return 0;
m4_divert(-1)')
m4_define(DYNAMIC_ATTR, `m4_divert(2)if (f1->da.ea_code != f2->da.ea_code) return 0;
m4_divert(-1)')

m4_define(SAME, `m4_divert(2)$1m4_divert(-1)')

m4_m4wrap(`
INST_FLUSH()
m4_divert(0)DNL
m4_undivert(1)
default: bug( "Unknown instruction %d (%c)", f1->fi_code, f1->fi_code & 0xff);
')

m4_changequote([[,]])


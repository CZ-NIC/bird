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

m4_define(INST, `m4_divert(1)break; case $1:
m4_divert(-1)')

m4_define(ARG, `')
m4_define(ARG_ANY, `')

m4_define(LINE, `m4_divert(1)if (!f_same(f1->lines[$2], f2->lines[$2])) return 0;
m4_divert(-1)')

m4_define(SYMBOL, `m4_divert(1){
  const struct symbol *s1 = f1->sym, *s2 = f2->sym;
  if (strcmp(s1->name, s2->name)) return 0;
  if (s1->class != s2->class) return 0;
}
m4_divert(-1)')

m4_define(VALI, `m4_divert(1)if (!val_same(f1->vp, f2->vp)) return 0;
m4_divert(-1)')
m4_define(VALP, `')

m4_define(FRET, `m4_divert(1)if (f1->fret != f2->fret) return 0;
m4_divert(-1)')

m4_define(SAME, `m4_divert(1)$1m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)DNL
case FI_NOP: bug("This shall not happen");
m4_undivert(1)
break; default: bug( "Unknown instruction %d (%c)", f1->fi_code, f1->fi_code & 0xff);
')

m4_divert(1)
m4_changequote([[,]])


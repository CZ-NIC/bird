m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Filter Instructions
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
m4_ifelse(m4_eval(INST_INVAL() > 0), 1, [[if (vstk.cnt < INST_INVAL()) runtime("Stack underflow"); vstk.cnt -= INST_INVAL(); ]])
m4_undivert(2)
break;
m4_divert(-1)
]])')

m4_define(INST, `INST_FLUSH()m4_define([[INST_NAME]], [[$1]])m4_define([[INST_INVAL]], [[$2]])m4_divert(2)')

m4_define(ARG, `if (v$1.type != $2) runtime("Argument $1 of instruction %s must be of type $2, got 0x%02x", f_instruction_name(what->fi_code), v$1.type)')

m4_define(RESULT_OK, `vstk.cnt++')
m4_define(RESULT, `RESULT_VAL([[ (struct f_val) { .type = $1, .val.$2 = $3 } ]])')
m4_define(RESULT_VAL, `do { res = $1; RESULT_OK; } while (0)')

m4_define(LINEX, `do {
  estk.item[estk.cnt].pos = 0;
  estk.item[estk.cnt].line = $1;
  estk.item[estk.cnt].ventry = vstk.cnt;
  estk.item[estk.cnt].emask = 0;
  estk.cnt++;
} while (0)')

m4_define(LINE, `do {
  if (what->lines[$2]) {
    estk.item[estk.cnt].pos = 0;
    estk.item[estk.cnt].line = what->lines[$2];
    estk.item[estk.cnt].ventry = vstk.cnt;
    estk.item[estk.cnt].emask = 0;
    estk.cnt++;
  }
} while (0)')

m4_define(LINEP, LINE($1, $2))

m4_define(ARG_ANY, `')

m4_define(SYMBOL, `const struct symbol *sym = what->sym')

m4_define(VALI, `res = what->val')
m4_define(VALP, `res = what->val')
m4_define(VAR, `res = *what->vp')
m4_define(FRET, `enum filter_return fret = what->fret')
m4_define(ECS, `enum ec_subtype ecs = what->ecs')
m4_define(RTC, `struct rtable *table = what->rtc->table')
m4_define(STATIC_ATTR, `struct f_static_attr sa = what->sa')
m4_define(DYNAMIC_ATTR, `struct f_dynamic_attr da = what->da')
m4_define(TREE, `')
m4_define(STRING, `')
m4_define(COUNT, `')
m4_define(SAME, `')
m4_define(FID_STRUCT_IN, `m4_divert(-1)')
m4_define(FID_NEW_ARGS, `m4_divert(-1)')
m4_define(FID_NEW_BODY, `m4_divert(-1)')
m4_define(FID_POSTFIXIFY_BODY, `m4_divert(-1)')
m4_define(FID_END, `m4_divert(2)')

m4_m4wrap(`
INST_FLUSH()
m4_divert(0)DNL
m4_undivert(1)
default: bug( "Unknown instruction %d (%c)", what->fi_code, what->fi_code & 0xff);
')

m4_changequote([[,]])


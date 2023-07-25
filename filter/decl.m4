m4_divert(-1)m4_dnl
#
#	BIRD -- Construction of per-instruction structures
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#
#	THIS IS A M4 MACRO FILE GENERATING 3 FILES ALTOGETHER.
#	KEEP YOUR HANDS OFF UNLESS YOU KNOW WHAT YOU'RE DOING.
#	EDITING AND DEBUGGING THIS FILE MAY DAMAGE YOUR BRAIN SERIOUSLY.
#
#	But you're welcome to read and edit and debug if you aren't scared.
#
#	Uncomment the following line to get exhaustive debug output.
#	m4_debugmode(aceflqtx)
#
#	How it works:
#	1) Instruction to code conversion (uses diversions 100..199)
#	2) Code wrapping (uses diversions 1..99)
#	3) Final preparation (uses diversions 200..299)
#	4) Shipout
#
#	See below for detailed description.
#
#
#	1) Instruction to code conversion
#	The code provided in f-inst.c between consecutive INST() calls
#	is interleaved for many different places. It is here processed
#	and split into separate instances where split-by-instruction
#	happens. These parts are stored in temporary diversions listed:
#
#	101	content of per-inst struct
#	102	constructor arguments
#	110	constructor attributes
#	103	constructor body
#	111	method constructor body
#	112	instruction constructor call from method constructor
#	113	method constructor symbol registrator
#	104	dump line item content
#		(there may be nothing in dump-line content and
#		 it must be handled specially in phase 2)
#	105	linearize body
#	106	comparator body
#	107	struct f_line_item content
#	108	interpreter body
#	109	iterator body
#
#	Here are macros to allow you to _divert to the right directions.
m4_define(FID_STRUCT_IN, `m4_divert(101)')
m4_define(FID_NEW_ARGS, `m4_divert(102)')
m4_define(FID_NEW_ATTRIBUTES, `m4_divert(110)')
m4_define(FID_NEW_BODY, `m4_divert(103)')
m4_define(FID_NEW_METHOD, `m4_divert(111)')
m4_define(FID_METHOD_CALL, `m4_divert(112)')
m4_define(FID_TYPE_SIGNATURE, `m4_divert(113)')
m4_define(FID_DUMP_BODY, `m4_divert(104)m4_define([[FID_DUMP_BODY_EXISTS]])')
m4_define(FID_LINEARIZE_BODY, `m4_divert(105)')
m4_define(FID_SAME_BODY, `m4_divert(106)')
m4_define(FID_LINE_IN, `m4_divert(107)')
m4_define(FID_INTERPRET_BODY, `m4_divert(108)')
m4_define(FID_ITERATE_BODY, `m4_divert(109)')

#	Sometimes you want slightly different code versions in different
#	outputs.
#	Use FID_HIC(code for inst-gen.h, code for inst-gen.c, code for inst-interpret.c)
#	and put it into [[ ]] quotes if it shall contain commas.
m4_define(FID_HIC, `m4_ifelse(TARGET, [[H]], [[$1]], TARGET, [[I]], [[$2]], TARGET, [[C]], [[$3]])')

#	In interpreter code, this is quite common.
m4_define(FID_INTERPRET_EXEC, `FID_HIC(,[[FID_INTERPRET_BODY()]],[[m4_divert(-1)]])')
m4_define(FID_INTERPRET_NEW,  `FID_HIC(,[[m4_divert(-1)]],[[FID_INTERPRET_BODY()]])')

#	If the instruction is never converted to constant, the interpret
#	code is not produced at all for constructor
m4_define(NEVER_CONSTANT, `m4_define([[INST_NEVER_CONSTANT]])')
m4_define(FID_IFCONST, `m4_ifdef([[INST_NEVER_CONSTANT]],[[$2]],[[$1]])')

#	If the instruction has some attributes (here called members),
#	these are typically carried with the instruction from constructor
#	to interpreter. This yields a line of code everywhere on the path.
#	FID_MEMBER is a macro to help with this task.
m4_define(FID_MEMBER, `m4_dnl
FID_LINE_IN()m4_dnl
      $1 $2;
FID_STRUCT_IN()m4_dnl
      $1 $2;
FID_NEW_ARGS()m4_dnl
  , $1 $2
FID_NEW_BODY()m4_dnl
whati->$2 = $2;
FID_LINEARIZE_BODY()m4_dnl
item->$2 = whati->$2;
m4_ifelse($3,,,[[
FID_SAME_BODY()m4_dnl
if ($3) return 0;
]])
m4_ifelse($4,,,[[
FID_DUMP_BODY()m4_dnl
debug("%s" $4 "\n", INDENT, $5);
]])
FID_INTERPRET_EXEC()m4_dnl
const $1 $2 = whati->$2
FID_INTERPRET_BODY')

#	Instruction arguments are needed only until linearization is done.
#	This puts the arguments into the filter line to be executed before
#	the instruction itself.
#
#	To achieve this, ARG_ANY must be called before anything writes into
#	the instruction line as it moves the instruction pointer forward.
m4_define(ARG_ANY, `
FID_STRUCT_IN()m4_dnl
      struct f_inst * f$1;
FID_NEW_ARGS()m4_dnl
  , struct f_inst * f$1
FID_NEW_ATTRIBUTES()m4_dnl
NONNULL(m4_eval($1+1))
FID_NEW_BODY()m4_dnl
whati->f$1 = f$1;
const struct f_inst *child$1 = f$1;
do {
  what->size += child$1->size;
FID_IFCONST([[
  if (child$1->fi_code != FI_CONSTANT)
    constargs = 0;
]])
} while (child$1 = child$1->next);
m4_define([[INST_METHOD_NUM_ARGS]],$1)m4_dnl
m4_ifelse($1,1,,[[FID_NEW_METHOD()m4_dnl
  struct f_inst *arg$1 = args;
  if (args == NULL) cf_error("Not enough arguments"); /* INST_NAME */
  args = args->next;
FID_METHOD_CALL()    , arg$1]])
FID_LINEARIZE_BODY()m4_dnl
pos = linearize(dest, whati->f$1, pos);
FID_INTERPRET_BODY()')

#	Some instructions accept variable number of arguments.
m4_define(VARARG, `
FID_NEW_ARGS()m4_dnl
  , struct f_inst * fvar
FID_STRUCT_IN()m4_dnl
      struct f_inst * fvar;
      uint varcount;
FID_LINE_IN()m4_dnl
      uint varcount;
FID_NEW_BODY()m4_dnl
whati->varcount = 0;
whati->fvar = fvar;
for (const struct f_inst *child = fvar; child; child = child->next, whati->varcount++) {
  what->size += child->size;
FID_IFCONST([[
  if (child->fi_code != FI_CONSTANT)
    constargs = 0;
]])
}
FID_IFCONST([[
  const struct f_inst **items = NULL;
  if (constargs && whati->varcount) {
    items = alloca(whati->varcount * sizeof(struct f_inst *));
    const struct f_inst *child = fvar;
    for (uint i=0; child; i++)
      child = (items[i] = child)->next;
  }
]])
FID_LINEARIZE_BODY()m4_dnl
  pos = linearize(dest, whati->fvar, pos);
  item->varcount = whati->varcount;
FID_DUMP_BODY()m4_dnl
  debug("%snumber of varargs %u\n", INDENT, item->varcount);
FID_SAME_BODY()m4_dnl
  if (f1->varcount != f2->varcount) return 0;
FID_INTERPRET_BODY()
FID_HIC(,[[
  if (fstk->vcnt < whati->varcount) runtime("Stack underflow");
  fstk->vcnt -= whati->varcount;
]],)
')

#	Some arguments need to check their type. After that, ARG_ANY is called.
m4_define(ARG, `ARG_ANY($1) ARG_TYPE($1,$2)')
m4_define(ARG_TYPE, `ARG_TYPE_STATIC($1,$2) ARG_TYPE_DYNAMIC($1,$2)')

m4_define(ARG_TYPE_STATIC, `m4_dnl
m4_ifelse($1,1,[[m4_define([[INST_METHOD_OBJECT_TYPE]],$2)]],)m4_dnl
FID_TYPE_SIGNATURE()m4_dnl
  method->args_type[m4_eval($1-1)] = $2;
FID_NEW_BODY()m4_dnl
if (f$1->type && (f$1->type != ($2)) && !f_const_promotion(f$1, ($2)))
  cf_error("Argument $1 of %s must be of type %s, got type %s",
	   f_instruction_name(what->fi_code), f_type_name($2), f_type_name(f$1->type));
FID_INTERPRET_BODY()')

m4_define(ARG_TYPE_DYNAMIC, `m4_dnl
FID_INTERPRET_EXEC()m4_dnl
if (v$1.type != ($2))
  runtime("Argument $1 of %s must be of type %s, got type %s",
	   f_instruction_name(what->fi_code), f_type_name($2), f_type_name(v$1.type));
FID_INTERPRET_BODY()')

m4_define(ARG_SAME_TYPE, `m4_dnl
FID_NEW_BODY()m4_dnl
if (f$1->type && f$2->type && (f$1->type != f$2->type) &&
   !f_const_promotion(f$2, f$1->type) && !f_const_promotion(f$1, f$2->type))
  cf_error("Arguments $1 and $2 of %s must be of the same type", f_instruction_name(what->fi_code));
FID_INTERPRET_BODY()')

m4_define(ARG_PREFER_SAME_TYPE, `m4_dnl
FID_NEW_BODY()m4_dnl
if (f$1->type && f$2->type && (f$1->type != f$2->type))
   (void) (f_const_promotion(f$2, f$1->type) || f_const_promotion(f$1, f$2->type));
FID_INTERPRET_BODY()')

#	Executing another filter line. This replaces the recursion
#	that was needed in the former implementation.
m4_define(LINEX, `FID_INTERPRET_EXEC()LINEX_($1)FID_INTERPRET_NEW()return $1 FID_INTERPRET_BODY()')
m4_define(LINEX_, `do if ($1) {
  fstk->estk[fstk->ecnt].pos = 0;
  fstk->estk[fstk->ecnt].line = $1;
  fstk->estk[fstk->ecnt].ventry = fstk->vcnt;
  fstk->estk[fstk->ecnt].vbase = fstk->estk[fstk->ecnt-1].vbase;
  fstk->estk[fstk->ecnt].emask = 0;
  fstk->ecnt++;
} while (0)')

m4_define(LINE, `
FID_LINE_IN()m4_dnl
      const struct f_line * fl$1;
FID_STRUCT_IN()m4_dnl
      struct f_inst * f$1;
FID_NEW_ARGS()m4_dnl
  , struct f_inst * f$1
FID_NEW_BODY()m4_dnl
whati->f$1 = f$1;
m4_define([[INST_METHOD_NUM_ARGS]],$1)m4_dnl
FID_NEW_METHOD()m4_dnl
  struct f_inst *arg$1 = args;
  if (args == NULL) cf_error("Not enough arguments"); /* INST_NAME */
  args = NULL; /* The rest is the line itself */
FID_METHOD_CALL()    , arg$1
FID_DUMP_BODY()m4_dnl
f_dump_line(item->fl$1, indent + 1);
FID_LINEARIZE_BODY()m4_dnl
item->fl$1 = f_linearize(whati->f$1, $2);
FID_SAME_BODY()m4_dnl
if (!f_same(f1->fl$1, f2->fl$1)) return 0;
FID_ITERATE_BODY()m4_dnl
if (whati->fl$1) BUFFER_PUSH(fit->lines) = whati->fl$1;
FID_INTERPRET_EXEC()m4_dnl
LINEX_(whati->fl$1)
FID_INTERPRET_NEW()m4_dnl
return whati->f$1
FID_INTERPRET_BODY()')

#	Some of the instructions have a result. These constructions
#	state the result and put it to the right place.
m4_define(RESULT, `RESULT_TYPE([[$1]]) RESULT_([[$1]],[[$2]],[[$3]])')
m4_define(RESULT_, `RESULT_VAL([[ (struct f_val) { .type = $1, .val.$2 = $3 } ]])')
m4_define(RESULT_VAL, `FID_HIC(, [[do { res = $1; fstk->vcnt++; } while (0)]],
[[return fi_constant(what, $1)]])')
m4_define(RESULT_VOID, `RESULT_VAL([[ (struct f_val) { .type = T_VOID } ]])')

m4_define(ERROR,
       `m4_errprint(m4___file__:m4___line__: $*
       )m4_m4exit(1)')

#	This macro specifies result type and makes there are no conflicting definitions
m4_define(RESULT_TYPE,
	`m4_ifdef([[INST_RESULT_TYPE]],
		  [[m4_ifelse(INST_RESULT_TYPE,$1,,[[ERROR([[Multiple type definitions in]] INST_NAME)]])]],
		  [[m4_define(INST_RESULT_TYPE,$1) RESULT_TYPE_($1)]])')

m4_define(RESULT_TYPE_CHECK,
	`m4_ifelse(INST_OUTVAL,0,,
		   [[m4_ifdef([[INST_RESULT_TYPE]],,[[ERROR([[Missing type definition in]] INST_NAME)]])]])')

m4_define(RESULT_TYPE_, `
FID_NEW_BODY()m4_dnl
what->type = $1;
FID_INTERPRET_BODY()')

#	Some common filter instruction members
m4_define(SYMBOL, `FID_MEMBER(struct symbol *, sym, [[strcmp(f1->sym->name, f2->sym->name) || (f1->sym->class != f2->sym->class)]], "symbol %s", item->sym->name)')
m4_define(RTC, `FID_MEMBER(struct rtable_config *, rtc, [[strcmp(f1->rtc->name, f2->rtc->name)]], "route table %s", item->rtc->name)')
m4_define(STATIC_ATTR, `FID_MEMBER(struct f_static_attr, sa, f1->sa.sa_code != f2->sa.sa_code,,)')
m4_define(DYNAMIC_ATTR, `FID_MEMBER(struct f_dynamic_attr, da, f1->da.ea_code != f2->da.ea_code,,)')
m4_define(ACCESS_RTE, `FID_HIC(,[[do { if (!fs->rte) runtime("No route to access"); } while (0)]],NEVER_CONSTANT())')

#	Method constructor block
m4_define(METHOD_CONSTRUCTOR, `m4_dnl
FID_NEW_METHOD()m4_dnl
    if (args) cf_error("Too many arguments");
m4_define([[INST_IS_METHOD]])
m4_define([[INST_METHOD_NAME]],$1)
FID_INTERPRET_BODY()')

#	Short method constructor
#	$1 = type
#	$2 = name
#	$3 = method inputs
#	method outputs are always 1
#	$4 = code
m4_define(METHOD, `m4_dnl
INST([[FI_METHOD__]]$1[[__]]$2, m4_eval($3 + 1), 1) {
  ARG(1, $1);
  $4
  METHOD_CONSTRUCTOR("$2");
}')

m4_define(METHOD_R, `METHOD($1, $2, 0, [[ RESULT($3, $4, $5) ]])')

#	2) Code wrapping
#	The code produced in 1xx temporary diversions is a raw code without
#	any auxiliary commands and syntactical structures around. When the
#	instruction is done, INST_FLUSH is called. More precisely, it is called
#	at the beginning of INST() call and at the end of file.
#
#	INST_FLUSH picks all the temporary diversions, wraps their content
#	into appropriate headers and structures and saves them into global
#	diversions listed:
#
#	4	enum fi_code
#	5	enum fi_code to string
#	6	dump line item
#	7	dump line item callers
#	8	linearize
#	9	same (filter comparator)
#	10	iterate
#	1	union in struct f_inst
#	3	constructors + interpreter
#	11	method constructors
#
#	These global diversions contain blocks of code that can be directly
#	put into the final file, yet it still can't be written out now as
#	every instruction writes to all of these diversions.

#	Code wrapping diversion names. Here we want an explicit newline
#	after the C comment.
m4_define(FID_ZONE, `m4_divert($1) /* $2 for INST_NAME() */
')
m4_define(FID_INST, `FID_ZONE(1, Instruction structure for config)')
m4_define(FID_LINE, `FID_ZONE(2, Instruction structure for interpreter)')
m4_define(FID_NEW, `FID_ZONE(3, Constructor)')
m4_define(FID_ENUM, `FID_ZONE(4, Code enum)')
m4_define(FID_ENUM_STR, `FID_ZONE(5, Code enum to string)')
m4_define(FID_DUMP, `FID_ZONE(6, Dump line)')
m4_define(FID_DUMP_CALLER, `FID_ZONE(7, Dump line caller)')
m4_define(FID_LINEARIZE, `FID_ZONE(8, Linearize)')
m4_define(FID_SAME, `FID_ZONE(9, Comparison)')
m4_define(FID_ITERATE, `FID_ZONE(10, Iteration)')
m4_define(FID_METHOD, `FID_ZONE(11, Method constructor)')
m4_define(FID_METHOD_SCOPE_INIT, `FID_ZONE(12, Method scope initializator)')
m4_define(FID_METHOD_REGISTER, `FID_ZONE(13, Method registrator)')

#	This macro does all the code wrapping. See inline comments.
m4_define(INST_FLUSH, `m4_ifdef([[INST_NAME]], [[
RESULT_TYPE_CHECK()m4_dnl		 Check for defined RESULT_TYPE()
FID_ENUM()m4_dnl			 Contents of enum fi_code { ... }
  INST_NAME(),
FID_ENUM_STR()m4_dnl			 Contents of const char * indexed by enum fi_code
  [INST_NAME()] = "INST_NAME()",
FID_INST()m4_dnl			 Anonymous structure inside struct f_inst
    struct {
m4_undivert(101)m4_dnl
    } i_[[]]INST_NAME();
FID_LINE()m4_dnl			 Anonymous structure inside struct f_line_item
    struct {
m4_undivert(107)m4_dnl
    } i_[[]]INST_NAME();
FID_NEW()m4_dnl				 Constructor and interpreter code together
FID_HIC(
[[m4_dnl				 Public declaration of constructor in H file
struct f_inst *
m4_undivert(110)m4_dnl
f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)m4_dnl
);]],
[[m4_dnl				 The one case in The Big Switch inside interpreter
  case INST_NAME():
  #define whati (&(what->i_]]INST_NAME()[[))
  m4_ifelse(m4_eval(INST_INVAL() > 0), 1, [[if (fstk->vcnt < INST_INVAL()) runtime("Stack underflow");
  fstk->vcnt -= INST_INVAL();]])
  m4_undivert(108)m4_dnl
  #undef whati
  break;
]],
[[m4_dnl				 Constructor itself
struct f_inst *
m4_undivert(110)m4_dnl
f_new_inst_]]INST_NAME()[[(enum f_instruction_code fi_code
m4_undivert(102)m4_dnl
)
  {
    /* Allocate the structure */
    struct f_inst *what = fi_new(fi_code);
    FID_IFCONST([[uint constargs = 1;]])

    /* Initialize all the members */
  #define whati (&(what->i_]]INST_NAME()[[))
  m4_undivert(103)m4_dnl

    /* If not constant, return the instruction itself */
    FID_IFCONST([[if (!constargs)]])
      return what;

    /* Try to pre-calculate the result */
    FID_IFCONST([[m4_undivert(108)]])m4_dnl
  #undef whati
  }
]])

m4_ifdef([[INST_IS_METHOD]],m4_dnl
FID_METHOD()m4_dnl
[[struct f_inst * NONNULL(1)
f_new_method_]]INST_NAME()[[(struct f_inst *obj, struct f_inst *args)
  {
    /* Unwind the arguments (INST_METHOD_NUM_ARGS) */
    m4_undivert(111)m4_dnl
    return f_new_inst(INST_NAME, obj
m4_undivert(112)
    );
  }

FID_METHOD_SCOPE_INIT()m4_dnl
  [INST_METHOD_OBJECT_TYPE] = {},
FID_METHOD_REGISTER()m4_dnl
  method = lp_allocz(global_root_scope_linpool, sizeof(struct f_method) + INST_METHOD_NUM_ARGS * sizeof(enum f_type));
  method->new_inst = f_new_method_]]INST_NAME()[[;
  method->arg_num = INST_METHOD_NUM_ARGS;
m4_undivert(113)
  f_register_method(INST_METHOD_OBJECT_TYPE, INST_METHOD_NAME, method);

]])m4_dnl

FID_DUMP_CALLER()m4_dnl			 Case in another big switch used in instruction dumping (debug)
case INST_NAME(): f_dump_line_item_]]INST_NAME()[[(item, indent + 1); break;

FID_DUMP()m4_dnl			 The dumper itself
m4_ifdef([[FID_DUMP_BODY_EXISTS]],
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item_, const int indent)]],
[[static inline void f_dump_line_item_]]INST_NAME()[[(const struct f_line_item *item UNUSED, const int indent UNUSED)]])
m4_undefine([[FID_DUMP_BODY_EXISTS]])
{
#define item (&(item_->i_]]INST_NAME()[[))
m4_undivert(104)m4_dnl
#undef item
}

FID_LINEARIZE()m4_dnl			 The linearizer
case INST_NAME(): {
#define whati (&(what->i_]]INST_NAME()[[))
#define item (&(dest->items[pos].i_]]INST_NAME()[[))
  m4_undivert(105)m4_dnl
#undef whati
#undef item
  dest->items[pos].fi_code = what->fi_code;
  dest->items[pos].flags = what->flags;
  dest->items[pos].lineno = what->lineno;
  break;
}

FID_SAME()m4_dnl			 This code compares two f_line"s while reconfiguring
case INST_NAME():
#define f1 (&(f1_->i_]]INST_NAME()[[))
#define f2 (&(f2_->i_]]INST_NAME()[[))
m4_undivert(106)m4_dnl
#undef f1
#undef f2
break;

FID_ITERATE()m4_dnl			The iterator
case INST_NAME():
#define whati (&(what->i_]]INST_NAME()[[))
m4_undivert(109)m4_dnl
#undef whati
break;

m4_divert(-1)FID_FLUSH(101,200)m4_dnl  And finally this flushes all the unused diversions
]])')

m4_define(INST, `m4_dnl				This macro is called on beginning of each instruction.
INST_FLUSH()m4_dnl				First, old data is flushed
m4_define([[INST_NAME]], [[$1]])m4_dnl		Then we store instruction name,
m4_define([[INST_INVAL]], [[$2]])m4_dnl		instruction input value count,
m4_define([[INST_OUTVAL]], [[$3]])m4_dnl	instruction output value count,
m4_undefine([[INST_NEVER_CONSTANT]])m4_dnl	reset NEVER_CONSTANT trigger,
m4_undefine([[INST_RESULT_TYPE]])m4_dnl		and reset RESULT_TYPE value.
m4_undefine([[INST_IS_METHOD]])m4_dnl		and reset method constructor request.
m4_undefine([[INST_METHOD_OBJECT_TYPE]],)m4_dnl	reset method object type,
FID_INTERPRET_BODY()m4_dnl 			By default, every code is interpreter code.
')

#	3) Final preparation
#
#	Now we prepare all the code around the global diversions.
#	It must be here, not in m4wrap, as we want M4 to mark the code
#	by #line directives correctly, not to claim that every single line
#	is at the beginning of the m4wrap directive.
#
#	This part is split by the final file.
#	H for inst-gen.h
#	I for inst-interpret.c
#	C for inst-gen.c
#
#	So we in cycle:
#	  A. open a diversion
#	  B. send there some code
#	  C. close that diversion
#	  D. flush a global diversion
#	  E. open another diversion and goto B.
#
#	Final diversions
#	200+	completed text before it is flushed to output

#	This is a list of output diversions
m4_define(FID_WR_PUT_LIST)

#	This macro does the steps C to E, see before.
m4_define(FID_WR_PUT_ALSO, `m4_define([[FID_WR_PUT_LIST]],FID_WR_PUT_LIST()[[FID_WR_DPUT(]]FID_WR_DIDX[[)FID_WR_DPUT(]]$1[[)]])m4_define([[FID_WR_DIDX]],m4_eval(FID_WR_DIDX+1))m4_divert(FID_WR_DIDX)')

#	These macros do the splitting between H/I/C
m4_define(FID_WR_DIRECT, `m4_ifelse(TARGET,[[$1]],[[FID_WR_INIT()]],[[FID_WR_STOP()]])')
m4_define(FID_WR_INIT, `m4_define([[FID_WR_DIDX]],200)m4_define([[FID_WR_PUT]],[[FID_WR_PUT_ALSO($]][[@)]])m4_divert(200)')
m4_define(FID_WR_STOP, `m4_define([[FID_WR_PUT]])m4_divert(-1)')

#	Here is the direct code to be put into the output files
#	together with the undiversions, being hidden under FID_WR_PUT()

m4_changequote([[,]])
FID_WR_DIRECT(I)
FID_WR_PUT(3)
FID_WR_DIRECT(C)

#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#endif

#include "nest/bird.h"
#include "filter/filter.h"
#include "filter/f-inst.h"

/* Instruction codes to string */
static const char * const f_instruction_name_str[] = {
FID_WR_PUT(5)
};

const char *
f_instruction_name_(enum f_instruction_code fi)
{
  if (fi < (sizeof(f_instruction_name_str) / sizeof(f_instruction_name_str[0])))
    return f_instruction_name_str[fi];
  else
    bug("Got unknown instruction code: %d", fi);
}

static inline struct f_inst *
fi_new(enum f_instruction_code fi_code)
{
  struct f_inst *what = tmp_allocz(sizeof(struct f_inst));
  what->lineno = ifs->lino;
  what->size = 1;
  what->fi_code = fi_code;
  return what;
}

static inline struct f_inst *
fi_constant(struct f_inst *what, struct f_val val)
{
  what->fi_code = FI_CONSTANT;
  what->i_FI_CONSTANT.val = val;
  return what;
}

int
f_const_promotion_(struct f_inst *arg, enum f_type want, int update)
{
  if (arg->fi_code != FI_CONSTANT)
    return 0;

  struct f_val *c = &arg->i_FI_CONSTANT.val;

  if ((c->type == T_IP) && ipa_is_ip4(c->val.ip) && (want == T_QUAD)) {
    if (update)
      *c = (struct f_val) {
        .type = T_QUAD,
        .val.i = ipa_to_u32(c->val.ip),
      };
    return 1;
  }

  else if ((c->type == T_SET) && (!c->val.t) && (want == T_PREFIX_SET)) {
    if (update)
      *c = f_const_empty_prefix_set;
    return 1;
  }

  return 0;
}

#define v1 whati->f1->i_FI_CONSTANT.val
#define v2 whati->f2->i_FI_CONSTANT.val
#define v3 whati->f3->i_FI_CONSTANT.val
#define vv(i) items[i]->i_FI_CONSTANT.val
#define runtime(fmt, ...) cf_error("filter preevaluation, line %d: " fmt, ifs->lino, ##__VA_ARGS__)
#define fpool cfg_mem
#define falloc(size) cfg_alloc(size)
/* Instruction constructors */
FID_WR_PUT(3)
#undef v1
#undef v2
#undef v3
#undef vv

/* Method constructor wrappers */
FID_WR_PUT(11)

#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Woverride-init"
#endif

static struct sym_scope f_type_method_scopes[] = {
FID_WR_PUT(12)
};

#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic pop
#endif

struct sym_scope *f_type_method_scope(enum f_type t)
{
  return (t < ARRAY_SIZE(f_type_method_scopes)) ? &f_type_method_scopes[t] : NULL;
}

static void
f_register_method(enum f_type t, const byte *name, struct f_method *dsc)
{
  struct sym_scope *scope = &f_type_method_scopes[t];
  struct symbol *sym = cf_find_symbol_scope(scope, name);

  if (!sym)
  {
    sym = cf_new_symbol(scope, global_root_scope_pool, global_root_scope_linpool, name);
    sym->class = SYM_METHOD;
  }

  dsc->sym = sym;
  dsc->next = sym->method;
  sym->method = dsc;
}

void f_type_methods_register(void)
{
  struct f_method *method;

FID_WR_PUT(13)

  for (uint i = 0; i < ARRAY_SIZE(f_type_method_scopes); i++)
    f_type_method_scopes[i].readonly = 1;
}

/* Line dumpers */
#define INDENT (((const char *) f_dump_line_indent_str) + sizeof(f_dump_line_indent_str) - (indent) - 1)
static const char f_dump_line_indent_str[] = "                                ";

FID_WR_PUT(6)

void f_dump_line(const struct f_line *dest, uint indent)
{
  if (!dest) {
    debug("%sNo filter line (NULL)\n", INDENT);
    return;
  }
  debug("%sFilter line %p (len=%u)\n", INDENT, dest, dest->len);
  for (uint i=0; i<dest->len; i++) {
    const struct f_line_item *item = &dest->items[i];
    debug("%sInstruction %s at line %u\n", INDENT, f_instruction_name_(item->fi_code), item->lineno);
    switch (item->fi_code) {
FID_WR_PUT(7)
      default: bug("Unknown instruction %x in f_dump_line", item->fi_code);
    }
  }
  debug("%sFilter line %p dump done\n", INDENT, dest);
}

/* Linearize */
static uint
linearize(struct f_line *dest, const struct f_inst *what, uint pos)
{
  for ( ; what; what = what->next) {
    switch (what->fi_code) {
FID_WR_PUT(8)
    }
    pos++;
  }
  return pos;
}

struct f_line *
f_linearize_concat(const struct f_inst * const inst[], uint count, uint results)
{
  uint len = 0;
  for (uint i=0; i<count; i++)
    for (const struct f_inst *what = inst[i]; what; what = what->next)
      len += what->size;

  struct f_line *out = cfg_allocz(sizeof(struct f_line) + sizeof(struct f_line_item)*len);

  for (uint i=0; i<count; i++)
    out->len = linearize(out, inst[i], out->len);

  out->results = results;

#ifdef LOCAL_DEBUG
  f_dump_line(out, 0);
#endif
  return out;
}

/* Filter line comparison */
int
f_same(const struct f_line *fl1, const struct f_line *fl2)
{
  if ((!fl1) && (!fl2))
    return 1;
  if ((!fl1) || (!fl2))
    return 0;
  if (fl1->len != fl2->len)
    return 0;
  for (uint i=0; i<fl1->len; i++) {
#define f1_ (&(fl1->items[i]))
#define f2_ (&(fl2->items[i]))
    if (f1_->fi_code != f2_->fi_code)
      return 0;
    if (f1_->flags != f2_->flags)
      return 0;

    switch(f1_->fi_code) {
FID_WR_PUT(9)
    }
  }
#undef f1_
#undef f2_
  return 1;
}


/* Part of FI_SWITCH filter iterator */
static void
f_add_tree_lines(const struct f_tree *t, void *fit_)
{
  struct filter_iterator * fit = fit_;

  if (t->data)
    BUFFER_PUSH(fit->lines) = t->data;
}

/* Filter line iterator */
void
f_add_lines(const struct f_line_item *what, struct filter_iterator *fit)
{
  switch(what->fi_code) {
FID_WR_PUT(10)
  }
}


#if defined(__GNUC__) && __GNUC__ >= 6
#pragma GCC diagnostic pop
#endif

FID_WR_DIRECT(H)
/* Filter instruction codes */
enum f_instruction_code {
FID_WR_PUT(4)m4_dnl
} PACKED;

/* Filter instruction structure for config */
struct f_inst {
  struct f_inst *next;			/* Next instruction */
  enum f_instruction_code fi_code;	/* Instruction code */
  enum f_instruction_flags flags;	/* Flags, instruction-specific */
  enum f_type type;			/* Type of returned value, if known */
  int size;				/* How many instructions are underneath */
  int lineno;				/* Line number */
  union {
FID_WR_PUT(1)m4_dnl
  };
};

/* Filter line item */
struct f_line_item {
  enum f_instruction_code fi_code;	/* What to do */
  enum f_instruction_flags flags;	/* Flags, instruction-specific */
  uint lineno;				/* Where */
  union {
FID_WR_PUT(2)m4_dnl
  };
};

/* Instruction constructors */
FID_WR_PUT(3)
m4_divert(-1)

#	4) Shipout
#
#	Everything is prepared in FID_WR_PUT_LIST now. Let's go!

m4_changequote(`,')

#	Flusher auxiliary macro
m4_define(FID_FLUSH, `m4_ifelse($1,$2,,[[m4_undivert($1)FID_FLUSH(m4_eval($1+1),$2)]])')

#	Defining the macro used in FID_WR_PUT_LIST
m4_define(FID_WR_DPUT, `m4_undivert($1)')

#	After the code is read and parsed, we:
m4_m4wrap(`INST_FLUSH()m4_divert(0)FID_WR_PUT_LIST()m4_divert(-1)FID_FLUSH(1,200)')

m4_changequote([[,]])
#	And now M4 is going to parse f-inst.c, fill the diversions
#	and after the file is done, the content of m4_m4wrap (see before)
#	is executed.

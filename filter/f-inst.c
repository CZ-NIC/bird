/*
 *	Filters: Instructions themselves
 *
 *	Copyright 1998 Pavel Machek <pavel@ucw.cz>
 *	Copyright 2018 Maria Matejka <mq@jmq.cz>
 *	Copyright 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	The filter code goes through several phases:
 *
 *	1  Parsing
 *	Flex- and Bison-generated parser decodes the human-readable data into
 *	a struct f_inst tree. This is an infix tree that was interpreted by
 *	depth-first search execution in previous versions of the interpreter.
 *	All instructions have their constructor: f_new_inst(FI_EXAMPLE, ...)
 *	translates into f_new_inst_FI_EXAMPLE(...) and the types are checked in
 *	compile time. If the result of the instruction is always the same,
 *	it's reduced to FI_CONSTANT directly in constructor. This phase also
 *	counts how many instructions are underlying in means of f_line_item
 *	fields to know how much we have to allocate in the next phase.
 *
 *	2  Linearize before interpreting
 *	The infix tree is always interpreted in the same order. Therefore we
 *	sort the instructions one after another into struct f_line. Results
 *	and arguments of these instructions are implicitly put on a value
 *	stack; e.g. the + operation just takes two arguments from the value
 *	stack and puts the result on there.
 *
 *	3  Interpret
 *	The given line is put on a custom execution stack. If needed (FI_CALL,
 *	FI_SWITCH, FI_AND, FI_OR, FI_CONDITION, ...), another line is put on top
 *	of the stack; when that line finishes, the execution continues on the
 *	older lines on the stack where it stopped before.
 *
 *	4  Same
 *	On config reload, the filters have to be compared whether channel
 *	reload is needed or not. The comparison is done by comparing the
 *	struct f_line's recursively.
 *
 *	The main purpose of this rework was to improve filter performance
 *	by making the interpreter non-recursive.
 *
 *	The other outcome is concentration of instruction definitions to
 *	one place -- right here. You shall define your instruction only here
 *	and nowhere else.
 *
 *	Beware. This file is interpreted by M4 macros. These macros
 *	may be more stupid than you could imagine. If something strange
 *	happens after changing this file, compare the results before and
 *	after your change (see the Makefile to find out where the results are)
 *	and see what really happened.
 *
 *	This file is not directly a C source code -> it is a generator input
 *	for several C sources; every instruction block gets expanded into many
 *	different places.
 *
 *	All the arguments are processed literally; if you need an argument including comma,
 *	you have to quote it by [[ ... ]]
 *
 *	What is the syntax here?
 *	m4_dnl	INST(FI_NOP, in, out) {			enum value, input args, output args
 *	m4_dnl	  ARG(num, type);			argument, its id (in data fields) and type accessible by v1, v2, v3
 *	m4_dnl	  ARG_ANY(num);				argument with no type check accessible by v1, v2, v3
 *	m4_dnl	  ARG_TYPE(num, type);			just declare the type of argument
 *	m4_dnl	  VARARG;				variable-length argument list; accessible by vv(i) and whati->varcount
 *	m4_dnl	  LINE(num, out);			this argument has to be converted to its own f_line
 *	m4_dnl	  SYMBOL;				symbol handed from config
 *	m4_dnl	  STATIC_ATTR;				static attribute definition
 *	m4_dnl	  DYNAMIC_ATTR;				dynamic attribute definition
 *	m4_dnl	  RTC;					route table config
 *	m4_dnl	  ACCESS_RTE;				this instruction needs route
 *	m4_dnl	  ACCESS_EATTRS;			this instruction needs extended attributes
 *
 *	m4_dnl	  METHOD_CONSTRUCTOR(name);		this instruction is in fact a method of the first argument's type; register it with the given name for that type
 *
 *	m4_dnl	  FID_MEMBER(				custom instruction member
 *	m4_dnl	    C type,				for storage in structs
 *	m4_dnl	    name,				how the member is named
 *	m4_dnl	    comparator for same(),		if different, this should be TRUE (CAVEAT)
 *	m4_dnl	    dump format string			debug -> format string for bvsnprintf
 *	m4_dnl	    dump format args			appropriate args
 *	m4_dnl	  )
 *
 *	m4_dnl	  RESULT(type, union-field, value);	putting this on value stack
 *	m4_dnl	  RESULT_(type, union-field, value);	like RESULT(), but do not declare the type
 *	m4_dnl	  RESULT_VAL(value-struct);		pass the struct f_val directly
 *	m4_dnl	  RESULT_TYPE(type);			just declare the type of result value
 *	m4_dnl	  RESULT_VOID;				return undef
 *	m4_dnl	}
 *
 *	Note that runtime arguments m4_dnl (ARG*, VARARG) must be defined before
 *	parse-time arguments m4_dnl (LINE, SYMBOL, ...). During linearization,
 *	first ones move position in f_line by linearizing arguments first, while
 *	second ones store data to the current position.
 *
 *	Also note that the { ... } blocks are not respected by M4 at all.
 *	If you get weird unmatched-brace-pair errors, check what it generated and why.
 *	What is really considered as one instruction is not the { ... } block
 *	after m4_dnl INST() but all the code between them.
 *
 *	Other code is just copied into the interpreter part.
 *
 *	It's also possible to declare type methods in a short way:
 *
 *	m4_dnl	METHOD(type, method name, argument count, code)
 *	m4_dnl	METHOD_R(type, method name, argument count, result type, union-field, value)
 *
 *	The filter language uses a simple type system, where values have types
 *	(constants T_*) and also terms (instructions) are statically typed. Our
 *	static typing is partial (some terms do not declare types of arguments
 *	or results), therefore it can detect most but not all type errors and
 *	therefore we still have runtime type checks.
 *
 *	m4_dnl  Types of arguments are declared by macros ARG() and ARG_TYPE(),
 *	m4_dnl  types of results are declared by RESULT() and RESULT_TYPE().
 *	m4_dnl  Macros ARG_ANY(), RESULT_() and RESULT_VAL() do not declare types
 *	m4_dnl  themselves, but can be combined with ARG_TYPE() / RESULT_TYPE().
 *
 *	m4_dnl  Note that types should be declared only once. If there are
 *	m4_dnl  multiple RESULT() macros in an instruction definition, they must
 *	m4_dnl  use the exact same expression for type, or they should be replaced
 *	m4_dnl  by multiple RESULT_() macros and a common RESULT_TYPE() macro.
 *	m4_dnl  See e.g. FI_EA_GET or FI_MIN instructions.
 *
 *
 *	If you are satisfied with this, you don't need to read the following
 *	detailed description of what is really done with the instruction definitions.
 *
 *	m4_dnl	Now let's look under the cover. The code between each INST()
 *	m4_dnl	is copied to several places, namely these (numbered by the M4 diversions
 *	m4_dnl	used in filter/decl.m4):
 *
 *	m4_dnl	(102)	struct f_inst *f_new_inst(FI_EXAMPLE [[ put it here ]])
 *	m4_dnl		{
 *	m4_dnl		  ... (common code)
 *	m4_dnl	(103)	  [[ put it here ]]
 *	m4_dnl		  ...
 *	m4_dnl		  if (all arguments are constant)
 *	m4_dnl	(108)	    [[ put it here ]]
 *	m4_dnl		}
 *	m4_dnl	For writing directly to constructor argument list, use FID_NEW_ARGS.
 *	m4_dnl	For computing something in constructor (103), use FID_NEW_BODY.
 *	m4_dnl	For constant pre-interpretation (108), see below at FID_INTERPRET_BODY.
 *
 *	m4_dnl		struct f_inst {
 *	m4_dnl		  ... (common fields)
 *	m4_dnl		  union {
 *	m4_dnl		    struct {
 *	m4_dnl	(101)	      [[ put it here ]]
 *	m4_dnl		    } i_FI_EXAMPLE;
 *	m4_dnl		    ...
 *	m4_dnl		  };
 *	m4_dnl		};
 *	m4_dnl	This structure is returned from constructor.
 *	m4_dnl	For writing directly to this structure, use FID_STRUCT_IN.
 *
 *	m4_dnl		linearize(struct f_line *dest, const struct f_inst *what, uint pos) {
 *	m4_dnl		  ...
 *	m4_dnl		    switch (what->fi_code) {
 *	m4_dnl		      case FI_EXAMPLE:
 *	m4_dnl	(105)		[[ put it here ]]
 *	m4_dnl			break;
 *	m4_dnl		    }
 *	m4_dnl		}
 *	m4_dnl	This is called when translating from struct f_inst to struct f_line_item.
 *	m4_dnl	For accessing your custom instruction data, use following macros:
 *	m4_dnl	  whati	-> for accessing (struct f_inst).i_FI_EXAMPLE
 *	m4_dnl	  item	-> for accessing (struct f_line)[pos].i_FI_EXAMPLE
 *	m4_dnl	For writing directly here, use FID_LINEARIZE_BODY.
 *
 *	m4_dnl	(107)	struct f_line_item {
 *	m4_dnl		  ... (common fields)
 *	m4_dnl		  union {
 *	m4_dnl		    struct {
 *	m4_dnl	(101)	      [[ put it here ]]
 *	m4_dnl		    } i_FI_EXAMPLE;
 *	m4_dnl		    ...
 *	m4_dnl		  };
 *	m4_dnl		};
 *	m4_dnl	The same as FID_STRUCT_IN (101) but for the other structure.
 *	m4_dnl	This structure is returned from the linearizer (105).
 *	m4_dnl	For writing directly to this structure, use FID_LINE_IN.
 *
 *	m4_dnl		f_dump_line_item_FI_EXAMPLE(const struct f_line_item *item, const int indent)
 *	m4_dnl		{
 *	m4_dnl	(104)	  [[ put it here ]]
 *	m4_dnl		}
 *	m4_dnl	This code dumps the instruction on debug. Note that the argument
 *	m4_dnl	is the linearized instruction; if the instruction has arguments,
 *	m4_dnl	their code has already been linearized and their value is taken
 *	m4_dnl	from the value stack.
 *	m4_dnl	For writing directly here, use FID_DUMP_BODY.
 *
 *	m4_dnl		f_same(...)
 *	m4_dnl		{
 *	m4_dnl		  switch (f1_->fi_code) {
 *	m4_dnl		    case FI_EXAMPLE:
 *	m4_dnl	(106)	      [[ put it here ]]
 *	m4_dnl		      break;
 *	m4_dnl		  }
 *	m4_dnl		}
 *	m4_dnl	This code compares the two given instrucions (f1_ and f2_)
 *	m4_dnl	on reconfigure. For accessing your custom instruction data,
 *	m4_dnl	use macros f1 and f2.
 *	m4_dnl	For writing directly here, use FID_SAME_BODY.
 *
 *	m4_dnl		f_add_lines(...)
 *	m4_dnl		{
 *	m4_dnl		  switch (what_->fi_code) {
 *	m4_dnl		    case FI_EXAMPLE:
 *	m4_dnl	(109)	      [[ put it here ]]
 *	m4_dnl		      break;
 *	m4_dnl		  }
 *	m4_dnl		}
 *	m4_dnl	This code adds new filter lines reachable from the instruction
 *	m4_dnl	to the filter iterator line buffer. This is for instructions
 *	m4_dnl  that changes conrol flow, like FI_CONDITION or FI_CALL, most
 *	m4_dnl  instructions do not need to update it. It is used in generic
 *	m4_dnl  filter iteration code (FILTER_ITERATE*). For accessing your
 *	m4_dnl  custom instruction data, use macros f1 and f2. For writing
 *	m4_dnl	directly here, use FID_ITERATE_BODY.
 *
 *	m4_dnl		interpret(...)
 *	m4_dnl		{
 *	m4_dnl		  switch (what->fi_code) {
 *	m4_dnl		    case FI_EXAMPLE:
 *	m4_dnl	(108)	      [[ put it here ]]
 *	m4_dnl		      break;
 *	m4_dnl		  }
 *	m4_dnl		}
 *	m4_dnl	This code executes the instruction. Every pre-defined macro
 *	m4_dnl	resets the output here. For setting it explicitly,
 *	m4_dnl	use FID_INTERPRET_BODY.
 *	m4_dnl	This code is put on two places; one is the interpreter, the other
 *	m4_dnl	is instruction constructor. If you need to distinguish between
 *	m4_dnl	these two, use FID_INTERPRET_EXEC or FID_INTERPRET_NEW respectively.
 *	m4_dnl	To address the difference between interpreter and constructor
 *	m4_dnl	environments, there are several convenience macros defined:
 *	m4_dnl	  runtime()	-> for spitting out runtime error like division by zero
 *	m4_dnl	  RESULT(...)	-> declare result; may overwrite arguments
 *	m4_dnl	  v1, v2, v3	-> positional arguments, may be overwritten by RESULT()
 *	m4_dnl	  falloc(size)	-> allocate memory from the appropriate linpool
 *	m4_dnl	  fpool		-> the current linpool
 *	m4_dnl	  NEVER_CONSTANT-> don't generate pre-interpretation code at all
 *	m4_dnl	  ACCESS_RTE	-> check that route is available, also NEVER_CONSTANT
 *	m4_dnl	  ACCESS_EATTRS	-> pre-cache the eattrs; use only with ACCESS_RTE
 *	m4_dnl	  f_rta_cow(fs)	-> function to call before any change to route should be done
 *
 *	m4_dnl	If you are stymied, see FI_CALL or FI_CONSTANT or just search for
 *	m4_dnl	the mentioned macros in this file to see what is happening there in wild.
 *
 *
 *	A note about soundness of the type system:
 *
 *	A type system is sound when types of expressions are consistent with
 *	types of values resulting from evaluation of such expressions. Untyped
 *	expressions are ok, but badly typed expressions are not sound. So is
 *	the type system of BIRD filtering code sound? There are some points:
 *
 *	All cases of (one) m4_dnl RESULT() macro are obviously ok, as the macro
 *	both declares a type and returns a value. One have to check instructions
 *	that use m4_dnl RESULT_TYPE() macro. There are two issues:
 *
 *	FI_AND, FI_OR - second argument is statically checked to be T_BOOL and
 *	passed as result without dynamic typecheck, declared to be T_BOOL. If
 *	an untyped non-bool expression is used as a second argument, then
 *	the mismatched type is returned.
 *
 *	FI_VAR_GET - soundness depends on consistency of declared symbol types
 *	and stored values. This is maintained when values are stored by
 *	FI_VAR_SET, but when they are stored by FI_CALL, only static checking is
 *	used, so when an untyped expression returning mismatched value is used
 *	as a function argument, then inconsistent value is stored and subsequent
 *	FI_VAR_GET would be unsound.
 *
 *	Both of these issues are inconsequential, as mismatched values from
 *	unsound expressions will be caught by dynamic typechecks like mismatched
 *	values from untyped expressions.
 *
 *	Also note that FI_CALL is the only expression without properly declared
 *	result type.
 */

/* Binary operators */
  INST(FI_ADD, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    RESULT(T_INT, i, v1.val.i + v2.val.i);
  }
  INST(FI_SUBTRACT, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    RESULT(T_INT, i, v1.val.i - v2.val.i);
  }
  INST(FI_MULTIPLY, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    RESULT(T_INT, i, v1.val.i * v2.val.i);
  }
  INST(FI_DIVIDE, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    if (v2.val.i == 0) runtime( "Mother told me not to divide by 0" );
    RESULT(T_INT, i, v1.val.i / v2.val.i);
  }
  INST(FI_AND, 1, 1) {
    ARG(1,T_BOOL);
    ARG_TYPE_STATIC(2,T_BOOL);
    RESULT_TYPE(T_BOOL);

    if (v1.val.i)
      LINE(2,1);
    else
      RESULT_VAL(v1);
  }
  INST(FI_OR, 1, 1) {
    ARG(1,T_BOOL);
    ARG_TYPE_STATIC(2,T_BOOL);
    RESULT_TYPE(T_BOOL);

    if (!v1.val.i)
      LINE(2,1);
    else
      RESULT_VAL(v1);
  }

  INST(FI_PAIR_CONSTRUCT, 2, 1) {
    ARG(1,T_INT);
    ARG(2,T_INT);
    uint u1 = v1.val.i;
    uint u2 = v2.val.i;
    if ((u1 > 0xFFFF) || (u2 > 0xFFFF))
      runtime( "Can't operate with value out of bounds in pair constructor" );
    RESULT(T_PAIR, i, (u1 << 16) | u2);
  }

  INST(FI_EC_CONSTRUCT, 2, 1) {
    ARG_ANY(1);
    ARG(2, T_INT);

    FID_MEMBER(enum ec_subtype, ecs, f1->ecs != f2->ecs, "ec subtype %s", ec_subtype_str(item->ecs));

    int ipv4_used;
    u32 key, val;

    if (v1.type == T_INT) {
      ipv4_used = 0; key = v1.val.i;
    }
    else if (v1.type == T_QUAD) {
      ipv4_used = 1; key = v1.val.i;
    }
    /* IP->Quad implicit conversion */
    else if (val_is_ip4(&v1)) {
      ipv4_used = 1; key = ipa_to_u32(v1.val.ip);
    }
    else
      runtime("Argument 1 of EC constructor must be integer or IPv4 address, got 0x%02x", v1.type);

    val = v2.val.i;

    if (ecs == EC_GENERIC)
      RESULT(T_EC, ec, ec_generic(key, val));
    else if (ipv4_used)
      if (val <= 0xFFFF)
	RESULT(T_EC, ec, ec_ip4(ecs, key, val));
      else
	runtime("4-byte value %u can't be used with IP-address key in extended community", val);
    else if (key < 0x10000)
      RESULT(T_EC, ec, ec_as2(ecs, key, val));
    else
      if (val <= 0xFFFF)
	RESULT(T_EC, ec, ec_as4(ecs, key, val));
      else
	runtime("4-byte value %u can't be used with 4-byte ASN in extended community", val);
  }

  INST(FI_LC_CONSTRUCT, 3, 1) {
    ARG(1, T_INT);
    ARG(2, T_INT);
    ARG(3, T_INT);
    RESULT(T_LC, lc, [[(lcomm) { v1.val.i, v2.val.i, v3.val.i }]]);
  }

  INST(FI_PATHMASK_CONSTRUCT, 0, 1) {
    VARARG;

    struct f_path_mask *pm = falloc(sizeof(struct f_path_mask) + whati->varcount * sizeof(struct f_path_mask_item));
    pm->len = whati->varcount;

    for (uint i=0; i<whati->varcount; i++) {
      switch (vv(i).type) {
	case T_PATH_MASK_ITEM:
	  if (vv(i).val.pmi.kind == PM_LOOP)
	  {
	    if (i == 0)
	      runtime("Path mask iterator '+' cannot be first");

	    /* We want PM_LOOP as prefix operator */
	    pm->item[i] = pm->item[i - 1];
	    pm->item[i - 1] = vv(i).val.pmi;
	    break;
	  }

	  pm->item[i] = vv(i).val.pmi;
	  break;

	case T_INT:
	  pm->item[i] = (struct f_path_mask_item) {
	    .asn = vv(i).val.i,
	    .kind = PM_ASN,
	  };
	  break;

	case T_SET:
	  if (!path_set_type(vv(i).val.t))
	    runtime("Only integer sets allowed in path mask");

	  pm->item[i] = (struct f_path_mask_item) {
	    .set = vv(i).val.t,
	    .kind = PM_ASN_SET,
	  };
	  break;

	default:
	  runtime( "Error resolving path mask template: value not an integer" );
      }
    }

    RESULT(T_PATH_MASK, path_mask, pm);
  }

/* Relational operators */

  INST(FI_NEQ, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    ARG_PREFER_SAME_TYPE(1, 2);
    RESULT(T_BOOL, i, !val_same(&v1, &v2));
  }

  INST(FI_EQ, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    ARG_PREFER_SAME_TYPE(1, 2);
    RESULT(T_BOOL, i, val_same(&v1, &v2));
  }

  INST(FI_LT, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    ARG_SAME_TYPE(1, 2);

    int i = val_compare(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "Can't compare values of incompatible types" );
    RESULT(T_BOOL, i, (i == -1));
  }

  INST(FI_LTE, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    ARG_SAME_TYPE(1, 2);

    int i = val_compare(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "Can't compare values of incompatible types" );
    RESULT(T_BOOL, i, (i != 1));
  }

  INST(FI_NOT, 1, 1) {
    ARG(1,T_BOOL);
    RESULT(T_BOOL, i, !v1.val.i);
  }

  INST(FI_MATCH, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_in_range(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "~ applied on unknown type pair" );
    RESULT(T_BOOL, i, !!i);
  }

  INST(FI_NOT_MATCH, 2, 1) {
    ARG_ANY(1);
    ARG_ANY(2);
    int i = val_in_range(&v1, &v2);
    if (i == F_CMP_ERROR)
      runtime( "!~ applied on unknown type pair" );
    RESULT(T_BOOL, i, !i);
  }

  INST(FI_DEFINED, 1, 1) {
    ARG_ANY(1);
    RESULT(T_BOOL, i, (v1.type != T_VOID) && !val_is_undefined(v1));
  }

  METHOD_R(T_NET, type, T_ENUM_NETTYPE, i, v1.val.net->type);
  METHOD_R(T_IP, is_v4, T_BOOL, i, ipa_is_ip4(v1.val.ip));

  /* Add initialized variable */
  INST(FI_VAR_INIT, 1, 0) {
    NEVER_CONSTANT;
    ARG_ANY(1);
    SYMBOL;
    ARG_TYPE(1, sym->class & 0xff);

    /* New variable is always the last on stack */
    uint pos = curline.vbase + sym->offset;
    fstk->vstk[pos] = v1;
    fstk->vcnt = pos + 1;
  }

  /* Add uninitialized variable */
  INST(FI_VAR_INIT0, 0, 0) {
    NEVER_CONSTANT;
    SYMBOL;

    /* New variable is always the last on stack */
    uint pos = curline.vbase + sym->offset;
    fstk->vstk[pos] = val_empty(sym->class & 0xff);
    fstk->vcnt = pos + 1;
  }

  /* Set to indirect value prepared in v1 */
  INST(FI_VAR_SET, 1, 0) {
    NEVER_CONSTANT;
    ARG_ANY(1);
    SYMBOL;
    ARG_TYPE(1, sym->class & 0xff);

    fstk->vstk[curline.vbase + sym->offset] = v1;
  }

  INST(FI_VAR_GET, 0, 1) {
    SYMBOL;
    NEVER_CONSTANT;
    RESULT_TYPE(sym->class & 0xff);
    RESULT_VAL(fstk->vstk[curline.vbase + sym->offset]);
  }

  INST(FI_CONSTANT, 0, 1) {
    FID_MEMBER(
      struct f_val,
      val,
      [[ !val_same(&(f1->val), &(f2->val)) ]],
      "value %s",
      val_dump(&(item->val))
    );

    RESULT_TYPE(val.type);
    RESULT_VAL(val);
  }

  METHOD_R(T_PATH, empty, T_PATH, ad, &null_adata);
  METHOD_R(T_CLIST, empty, T_CLIST, ad, &null_adata);
  METHOD_R(T_ECLIST, empty, T_ECLIST, ad, &null_adata);
  METHOD_R(T_LCLIST, empty, T_LCLIST, ad, &null_adata);

  /* Common loop begin instruction, always created by f_for_cycle() */
  INST(FI_FOR_LOOP_START, 0, 3) {
    NEVER_CONSTANT;
    SYMBOL;

    /* Repeat the instruction which called us */
    ASSERT_DIE(fstk->ecnt > 1);
    prevline.pos--;

    /* There should be exactly three items on the value stack to be taken care of */
    fstk->vcnt += 3;

    /* And these should also stay there after we finish for the caller instruction */
    curline.ventry += 3;

    /* Assert the iterator variable positioning */
    ASSERT_DIE(curline.vbase + sym->offset == fstk->vcnt - 1);

    /* The result type declaration makes no sense here but is needed */
    RESULT_TYPE(T_VOID);
  }

  /* Type-specific for_next iterators */
  INST(FI_PATH_FOR_NEXT, 3, 0) {
    NEVER_CONSTANT;
    ARG(1, T_PATH);
    if (as_path_walk(v1.val.ad, &v2.val.i, &v3.val.i))
      LINE(2,0);

    METHOD_CONSTRUCTOR("!for_next");
  }

  INST(FI_CLIST_FOR_NEXT, 3, 0) {
    NEVER_CONSTANT;
    ARG(1, T_CLIST);
    if (int_set_walk(v1.val.ad, &v2.val.i, &v3.val.i))
      LINE(2,0);

    METHOD_CONSTRUCTOR("!for_next");
  }

  INST(FI_ECLIST_FOR_NEXT, 3, 0) {
    NEVER_CONSTANT;
    ARG(1, T_ECLIST);
    if (ec_set_walk(v1.val.ad, &v2.val.i, &v3.val.ec))
      LINE(2,0);

    METHOD_CONSTRUCTOR("!for_next");
  }

  INST(FI_LCLIST_FOR_NEXT, 3, 0) {
    NEVER_CONSTANT;
    ARG(1, T_LCLIST);
    if (lc_set_walk(v1.val.ad, &v2.val.i, &v3.val.lc))
      LINE(2,0);

    METHOD_CONSTRUCTOR("!for_next");
  }

  INST(FI_ROUTES_BLOCK_FOR_NEXT, 3, 0) {
    NEVER_CONSTANT;
    ARG(1, T_ROUTES_BLOCK);
    if (!v2.type)
      v2 = v1;

    if (v2.val.rte)
    {
      v3.val.rte = v2.val.rte;
      v2.val.rte = v2.val.rte->next;
      LINE(2,0);
    }

    METHOD_CONSTRUCTOR("!for_next");
  }

  INST(FI_CONDITION, 1, 0) {
    ARG(1, T_BOOL);
    if (v1.val.i)
      LINE(2,0);
    else
      LINE(3,0);
  }

  INST(FI_PRINT, 1, 0) {
    NEVER_CONSTANT;
    ARG_ANY(1);

    if (!(fs->flags & FF_SILENT))
      val_format(&v1, &fs->buf);
  }

  INST(FI_FLUSH, 0, 0) {
    NEVER_CONSTANT;
    if (!(fs->flags & FF_SILENT))
      /* After log_commit, the buffer is reset */
      log_commit(*L_INFO, &fs->buf);
  }

  INST(FI_DIE, 0, 0) {
    NEVER_CONSTANT;
    FID_MEMBER(enum filter_return, fret, f1->fret != f2->fret, "%s", filter_return_str(item->fret));

    switch (whati->fret) {
    case F_ACCEPT:	/* Should take care about turning ACCEPT into MODIFY */
    case F_ERROR:
    case F_REJECT:	/* Maybe print complete route along with reason to reject route? */
      return fret;	/* We have to return now, no more processing. */
    default:
      bug( "unknown return type: Can't happen");
    }
  }

  INST(FI_RTA_GET, 1, 1) {
    {
      ACCESS_RTE;
      ARG(1, T_ROUTE);
      STATIC_ATTR;

      struct rta *rta = v1.val.rte ? v1.val.rte->attrs : (*fs->rte)->attrs;

      switch (sa.sa_code)
      {
      case SA_FROM:	RESULT(sa.f_type, ip, rta->from); break;
      case SA_GW:	RESULT(sa.f_type, ip, rta->nh.gw); break;
      case SA_NET:	RESULT(sa.f_type, net, (*fs->rte)->net->n.addr); break;
      case SA_PROTO:	RESULT(sa.f_type, s, (*fs->rte)->src->proto->name); break;
      case SA_SOURCE:	RESULT(sa.f_type, i, rta->source); break;
      case SA_SCOPE:	RESULT(sa.f_type, i, rta->scope); break;
      case SA_DEST:	RESULT(sa.f_type, i, rta->dest); break;
      case SA_IFNAME:	RESULT(sa.f_type, s, rta->nh.iface ? rta->nh.iface->name : ""); break;
      case SA_IFINDEX:	RESULT(sa.f_type, i, rta->nh.iface ? rta->nh.iface->index : 0); break;
      case SA_WEIGHT:	RESULT(sa.f_type, i, rta->nh.weight + 1); break;
      case SA_PREF:	RESULT(sa.f_type, i, rta->pref); break;
      case SA_GW_MPLS:	RESULT(sa.f_type, i, rta->nh.labels ? rta->nh.label[0] : MPLS_NULL); break;
      case SA_ONLINK:	RESULT(sa.f_type, i, rta->nh.flags & RNF_ONLINK ? 1 : 0); break;

      default:
	bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
      }
    }
  }

  INST(FI_RTA_SET, 1, 0) {
    ACCESS_RTE;
    ARG_ANY(1);
    STATIC_ATTR;
    ARG_TYPE(1, sa.f_type);

    f_rta_cow(fs);
    {
      struct rta *rta = (*fs->rte)->attrs;

      switch (sa.sa_code)
      {
      case SA_FROM:
	rta->from = v1.val.ip;
	break;

      case SA_GW:
	{
	  ip_addr ip = v1.val.ip;
	  struct iface *ifa = ipa_is_link_local(ip) || (rta->nh.flags & RNF_ONLINK) ? rta->nh.iface : NULL;
	  neighbor *n = neigh_find((*fs->rte)->src->proto, ip, ifa, (rta->nh.flags & RNF_ONLINK) ? NEF_ONLINK : 0);
	  if (!n || (n->scope == SCOPE_HOST))
	    runtime( "Invalid gw address" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = ip;
	  rta->nh.iface = n->iface;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	  rta->nh.labels = 0;
	}
	break;

      case SA_SCOPE:
	rta->scope = v1.val.i;
	break;

      case SA_DEST:
	{
	  int i = v1.val.i;
	  if ((i != RTD_BLACKHOLE) && (i != RTD_UNREACHABLE) && (i != RTD_PROHIBIT))
	    runtime( "Destination can be changed only to blackhole, unreachable or prohibit" );

	  rta->dest = i;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = NULL;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	  rta->nh.labels = 0;
	}
	break;

      case SA_IFNAME:
	{
	  struct iface *ifa = if_find_by_name(v1.val.s);
	  if (!ifa)
	    runtime( "Invalid iface name" );

	  rta->dest = RTD_UNICAST;
	  rta->nh.gw = IPA_NONE;
	  rta->nh.iface = ifa;
	  rta->nh.next = NULL;
	  rta->hostentry = NULL;
	  rta->nh.labels = 0;
	}
	break;

      case SA_GW_MPLS:
	{
	  if (v1.val.i >= 0x100000)
	    runtime( "Invalid MPLS label" );

	  if (v1.val.i != MPLS_NULL)
	  {
	    rta->nh.label[0] = v1.val.i;
	    rta->nh.labels = 1;
	  }
	  else
	    rta->nh.labels = 0;
	}
	break;

      case SA_WEIGHT:
        {
	  int i = v1.val.i;
	  if (i < 1 || i > 256)
	    runtime( "Setting weight value out of bounds" );
	  if (rta->dest != RTD_UNICAST)
	    runtime( "Setting weight needs regular nexthop " );

	  /* Set weight on all next hops */
	  for (struct nexthop *nh = &rta->nh; nh; nh = nh->next)
	    nh->weight = i - 1;
        }
	break;

      case SA_PREF:
	rta->pref = v1.val.i;
	break;

      case SA_ONLINK:
	{
	  if (v1.val.i)
	    rta->nh.flags |= RNF_ONLINK;
	  else
	    rta->nh.flags &= ~RNF_ONLINK;
	}
	break;

      default:
	bug("Invalid static attribute access (%u/%u)", sa.f_type, sa.sa_code);
      }
    }
  }

  INST(FI_EA_GET, 1, 1) {	/* Access to extended attributes */
    ACCESS_RTE;
    ACCESS_EATTRS;
    ARG(1, T_ROUTE);
    DYNAMIC_ATTR;
    RESULT_TYPE(da.f_type);
    {
      struct ea_list *eal = v1.val.rte ? v1.val.rte->attrs->eattrs : *fs->eattrs;
      eattr *e = ea_find(eal, da.ea_code);

      if (!e) {
	RESULT_VAL(val_empty(da.f_type));
	break;
      }

      switch (e->type & EAF_TYPE_MASK) {
      case EAF_TYPE_INT:
	RESULT_(da.f_type, i, e->u.data);
	break;
      case EAF_TYPE_ROUTER_ID:
	RESULT_(T_QUAD, i, e->u.data);
	break;
      case EAF_TYPE_OPAQUE:
	if (da.f_type == T_ENUM_EMPTY)
	  RESULT_(T_ENUM_EMPTY, i, 0);
	else
	  RESULT_(T_BYTESTRING, ad, e->u.ptr);
	break;
      case EAF_TYPE_IP_ADDRESS:
	RESULT_(T_IP, ip, *((ip_addr *) e->u.ptr->data));
	break;
      case EAF_TYPE_AS_PATH:
	RESULT_(T_PATH, ad, e->u.ptr);
	break;
      case EAF_TYPE_BITFIELD:
	RESULT_(T_BOOL, i, !!(e->u.data & (1u << da.bit)));
	break;
      case EAF_TYPE_INT_SET:
	RESULT_(T_CLIST, ad, e->u.ptr);
	break;
      case EAF_TYPE_EC_SET:
	RESULT_(T_ECLIST, ad, e->u.ptr);
	break;
      case EAF_TYPE_LC_SET:
	RESULT_(T_LCLIST, ad, e->u.ptr);
	break;
      default:
	bug("Unknown dynamic attribute type");
      }
    }
  }

  INST(FI_EA_SET, 1, 0) {
    ACCESS_RTE;
    ACCESS_EATTRS;
    ARG_ANY(1);
    DYNAMIC_ATTR;
    ARG_TYPE(1, da.f_type);

    FID_NEW_BODY;
      if (da.f_type == T_ENUM_EMPTY)
	cf_error("Setting opaque attribute is not allowed");

    FID_INTERPRET_BODY;
    {
      struct ea_list *l = lp_alloc(fs->pool, sizeof(struct ea_list) + sizeof(eattr));

      l->next = NULL;
      l->flags = EALF_SORTED;
      l->count = 1;
      l->attrs[0].id = da.ea_code;
      l->attrs[0].flags = da.flags;
      l->attrs[0].type = da.type;
      l->attrs[0].originated = 1;
      l->attrs[0].fresh = 1;
      l->attrs[0].undef = 0;

      switch (da.type) {
      case EAF_TYPE_INT:
      case EAF_TYPE_ROUTER_ID:
	l->attrs[0].u.data = v1.val.i;
	break;

      case EAF_TYPE_IP_ADDRESS:;
	int len = sizeof(ip_addr);
	struct adata *ad = lp_alloc(fs->pool, sizeof(struct adata) + len);
	ad->length = len;
	(* (ip_addr *) ad->data) = v1.val.ip;
	l->attrs[0].u.ptr = ad;
	break;

      case EAF_TYPE_OPAQUE:
      case EAF_TYPE_AS_PATH:
      case EAF_TYPE_INT_SET:
      case EAF_TYPE_EC_SET:
      case EAF_TYPE_LC_SET:
	l->attrs[0].u.ptr = v1.val.ad;
	break;

      case EAF_TYPE_BITFIELD:
	{
	  /* First, we have to find the old value */
	  eattr *e = ea_find(*fs->eattrs, da.ea_code);
	  u32 data = e ? e->u.data : 0;

	  if (v1.val.i)
	    l->attrs[0].u.data = data | (1u << da.bit);
	  else
	    l->attrs[0].u.data = data & ~(1u << da.bit);
	}
	break;

      default:
	bug("Unknown dynamic attribute type");
      }

      f_rta_cow(fs);
      l->next = *fs->eattrs;
      *fs->eattrs = l;
    }
  }

  INST(FI_EA_UNSET, 0, 0) {
    DYNAMIC_ATTR;
    ACCESS_RTE;
    ACCESS_EATTRS;

    f_rta_cow(fs);
    ea_unset_attr(fs->eattrs, fs->pool, 1, da.ea_code);
  }

  /* Get length of */
  METHOD_R(T_NET, len, T_INT, i, net_pxlen(v1.val.net));
  METHOD_R(T_PATH, len, T_INT, i, as_path_getlen(v1.val.ad));
  METHOD_R(T_CLIST, len, T_INT, i, int_set_get_size(v1.val.ad));
  METHOD_R(T_ECLIST, len, T_INT, i, ec_set_get_size(v1.val.ad));
  METHOD_R(T_LCLIST, len, T_INT, i, lc_set_get_size(v1.val.ad));

  INST(FI_NET_SRC, 1, 1) { 	/* Get src prefix */
    ARG(1, T_NET);
    METHOD_CONSTRUCTOR("src");

    net_addr_union *net = (void *) v1.val.net;
    net_addr *src = falloc(sizeof(net_addr_ip6));
    const byte *part;

    switch(v1.val.net->type) {
    case NET_FLOW4:
      part = flow4_get_part(&net->flow4, FLOW_TYPE_SRC_PREFIX);
      if (part)
	net_fill_ip4(src, flow_read_ip4_part(part), flow_read_pxlen(part));
      else
	net_fill_ip4(src, IP4_NONE, 0);
      break;

    case NET_FLOW6:
      part = flow6_get_part(&net->flow6, FLOW_TYPE_SRC_PREFIX);
      if (part)
	net_fill_ip6(src, flow_read_ip6_part(part), flow_read_pxlen(part));
      else
	net_fill_ip6(src, IP6_NONE, 0);
      break;

    case NET_IP6_SADR:
      net_fill_ip6(src, net->ip6_sadr.src_prefix, net->ip6_sadr.src_pxlen);
      break;

    default:
      runtime( "Flow or SADR expected" );
    }

    RESULT(T_NET, net, src);
  }

  INST(FI_NET_DST, 1, 1) { 	/* Get dst prefix */
    ARG(1, T_NET);
    METHOD_CONSTRUCTOR("dst");

    net_addr_union *net = (void *) v1.val.net;
    net_addr *dst = falloc(sizeof(net_addr_ip6));
    const byte *part;

    switch(v1.val.net->type) {
    case NET_FLOW4:
      part = flow4_get_part(&net->flow4, FLOW_TYPE_DST_PREFIX);
      if (part)
	net_fill_ip4(dst, flow_read_ip4_part(part), flow_read_pxlen(part));
      else
	net_fill_ip4(dst, IP4_NONE, 0);
      break;

    case NET_FLOW6:
      part = flow6_get_part(&net->flow6, FLOW_TYPE_DST_PREFIX);
      if (part)
	net_fill_ip6(dst, flow_read_ip6_part(part), flow_read_pxlen(part));
      else
	net_fill_ip6(dst, IP6_NONE, 0);
      break;

    case NET_IP6_SADR:
      net_fill_ip6(dst, net->ip6_sadr.dst_prefix, net->ip6_sadr.dst_pxlen);
      break;

    default:
      runtime( "Flow or SADR expected" );
    }

    RESULT(T_NET, net, dst);
  }

  /* Get ROA max prefix length */
  METHOD(T_NET, maxlen, 0, [[
    if (!net_is_roa(v1.val.net))
      runtime( "ROA expected" );

    RESULT(T_INT, i, (v1.val.net->type == NET_ROA4) ?
      ((net_addr_roa4 *) v1.val.net)->max_pxlen :
      ((net_addr_roa6 *) v1.val.net)->max_pxlen);
  ]]);

  /* Get ROA ASN */
  METHOD(T_NET, asn, 0, [[
        if (!net_is_roa(v1.val.net))
          runtime( "ROA expected" );

        RESULT(T_INT, i, (v1.val.net->type == NET_ROA4) ?
          ((net_addr_roa4 *) v1.val.net)->asn :
          ((net_addr_roa6 *) v1.val.net)->asn);
  ]]);

  /* Convert prefix to IP */
  METHOD_R(T_NET, ip, T_IP, ip, net_prefix(v1.val.net));

  INST(FI_ROUTE_DISTINGUISHER, 1, 1) {
    ARG(1, T_NET);
    METHOD_CONSTRUCTOR("rd");
    if (!net_is_vpn(v1.val.net))
      runtime( "VPN address expected" );
    RESULT(T_RD, ec, net_rd(v1.val.net));
  }

  /* Get first ASN from AS PATH */
  METHOD_R(T_PATH, first, T_INT, i, ({ u32 as = 0; as_path_get_first(v1.val.ad, &as); as; }));

  /* Get last ASN from AS PATH */
  METHOD_R(T_PATH, last, T_INT, i, ({ u32 as = 0; as_path_get_last(v1.val.ad, &as); as; }));

  /* Get last ASN from non-aggregated part of AS PATH */
  METHOD_R(T_PATH, last_nonaggregated, T_INT, i, as_path_get_last_nonaggregated(v1.val.ad));

  /* Get ASN part from the standard community ASN */
  METHOD_R(T_PAIR, asn, T_INT, i, v1.val.i >> 16);

  /* Get data part from the standard community */
  METHOD_R(T_PAIR, data, T_INT, i, v1.val.i & 0xFFFF);

  /* Get ASN part from the large community */
  METHOD_R(T_LC, asn, T_INT, i, v1.val.lc.asn);

  /* Get data1 part from the large community */
  METHOD_R(T_LC, data1, T_INT, i, v1.val.lc.ldp1);

  /* Get data2 part from the large community */
  METHOD_R(T_LC, data2, T_INT, i, v1.val.lc.ldp2);

  /* Get minimum element from clist */
  METHOD_R(T_CLIST, min, T_PAIR, i, ({ u32 val = 0; int_set_min(v1.val.ad, &val); val; }));

  /* Get maximum element from clist */
  METHOD_R(T_CLIST, max, T_PAIR, i, ({ u32 val = 0; int_set_max(v1.val.ad, &val); val; }));

  /* Get minimum element from eclist */
  METHOD_R(T_ECLIST, min, T_EC, ec, ({ u64 val = 0; ec_set_min(v1.val.ad, &val); val; }));

  /* Get maximum element from eclist */
  METHOD_R(T_ECLIST, max, T_EC, ec, ({ u64 val = 0; ec_set_max(v1.val.ad, &val); val; }));

  /* Get minimum element from lclist */
  METHOD_R(T_LCLIST, min, T_LC, lc, ({ lcomm val = {}; lc_set_min(v1.val.ad, &val); val; }));

  /* Get maximum element from lclist */
  METHOD_R(T_LCLIST, max, T_LC, lc, ({ lcomm val = {}; lc_set_max(v1.val.ad, &val); val; }));

  INST(FI_RETURN, 1, 0) {
    NEVER_CONSTANT;
    /* Acquire the return value */
    ARG_ANY(1);
    uint retpos = fstk->vcnt;

    /* Drop every sub-block including ourselves */
    do fstk->ecnt--;
    while ((fstk->ecnt > 0) && !(fstk->estk[fstk->ecnt].emask & FE_RETURN));

    /* Now we are at the caller frame; if no such, try to convert to accept/reject. */
    if (!fstk->ecnt)
    {
      if (fstk->vstk[retpos].type == T_BOOL)
	return (fstk->vstk[retpos].val.i) ? F_ACCEPT :  F_REJECT;
      else
	runtime("Can't return non-bool from non-function");
    }

    /* Set the value stack position, overwriting the former implicit void */
    fstk->vcnt = fstk->estk[fstk->ecnt].ventry - 1;

    /* Copy the return value */
    RESULT_VAL(fstk->vstk[retpos]);
  }

  INST(FI_CALL, 0, 1) {
    NEVER_CONSTANT;
    VARARG;
    SYMBOL;
    RESULT_TYPE(sym->function->return_type);

    FID_NEW_BODY()
    ASSERT(sym->class == SYM_FUNCTION);

    if (whati->varcount != sym->function->args)
      cf_error("Function '%s' expects %u arguments, got %u arguments",
	       sym->name, sym->function->args, whati->varcount);

    /* Typecheck individual arguments */
    struct f_inst *a = fvar;
    struct f_arg *b = sym->function->arg_list;
    for (uint i = 1; a && b; a = a->next, b = b->next, i++)
    {
      enum f_type b_type = b->arg->class & 0xff;

      if (a->type && (a->type != b_type) && !f_const_promotion(a, b_type))
	cf_error("Argument %u of '%s' must be %s, got %s",
		 i, sym->name, f_type_name(b_type), f_type_name(a->type));
    }
    ASSERT(!a && !b);

    /* Add implicit void slot for the return value */
    struct f_inst *tmp = f_new_inst(FI_CONSTANT, (struct f_val) { .type = T_VOID });
    tmp->next = whati->fvar;
    whati->fvar = tmp;
    what->size += tmp->size;

    /* Mark recursive calls, they have dummy f_line */
    if (!sym->function->len)
      what->flags |= FIF_RECURSIVE;

    FID_SAME_BODY()
    if (!(f1->sym->flags & SYM_FLAG_SAME) && !(f1_->flags & FIF_RECURSIVE))
      return 0;

    FID_ITERATE_BODY()
    if (!(what->flags & FIF_RECURSIVE))
      BUFFER_PUSH(fit->lines) = whati->sym->function;

    FID_INTERPRET_BODY()

    /* Push the body on stack */
    LINEX(sym->function);
    curline.vbase = curline.ventry;
    curline.emask |= FE_RETURN;

    /* Arguments on stack */
    fstk->vcnt += sym->function->args;

    /* Storage for local variables */
    memset(&(fstk->vstk[fstk->vcnt]), 0, sizeof(struct f_val) * sym->function->vars);
    fstk->vcnt += sym->function->vars;
  }

  INST(FI_DROP_RESULT, 1, 0) {
    NEVER_CONSTANT;
    ARG_ANY(1);
  }

  INST(FI_SWITCH, 1, 0) {
    ARG_ANY(1);

    FID_MEMBER(struct f_tree *, tree, [[!same_tree(f1->tree, f2->tree)]], "tree %p", item->tree);

    FID_LINEARIZE_BODY()
    /* Linearize all branches in switch */
    struct f_inst *last_inst = NULL;
    struct f_line *last_line = NULL;
    for (struct f_tree *t = whati->tree; t; t = t->left)
    {
      if (t->data != last_inst)
      {
	last_inst = t->data;
	last_line = f_linearize(t->data, 0);
      }

      t->data = last_line;
    }

    /* Balance the tree */
    item->tree = build_tree(whati->tree);

    FID_ITERATE_BODY()
    tree_walk(whati->tree, f_add_tree_lines, fit);

    FID_INTERPRET_BODY()
    /* In parse-time use find_tree_linear(), in runtime use find_tree() */
    const struct f_tree *t = FID_HIC(,find_tree,find_tree_linear)(tree, &v1);
    if (!t) {
      v1.type = T_VOID;
      t = FID_HIC(,find_tree,find_tree_linear)(tree, &v1);
      if (!t) {
	debug( "No else statement?\n");
	FID_HIC(,break,return NULL);
      }
    }

    LINEX(t->data);
  }

  INST(FI_IP_MASK, 2, 1) { /* IP.MASK(val) */
    ARG(1, T_IP);
    ARG(2, T_INT);
    METHOD_CONSTRUCTOR("mask");
    RESULT(T_IP, ip, [[ ipa_is_ip4(v1.val.ip) ?
      ipa_from_ip4(ip4_and(ipa_to_ip4(v1.val.ip), ip4_mkmask(v2.val.i))) :
      ipa_from_ip6(ip6_and(ipa_to_ip6(v1.val.ip), ip6_mkmask(v2.val.i))) ]]);
  }

  INST(FI_PATH_PREPEND, 2, 1) {	/* Path prepend */
    ARG(1, T_PATH);
    ARG(2, T_INT);
    METHOD_CONSTRUCTOR("prepend");
    RESULT(T_PATH, ad, [[ as_path_prepend(fpool, v1.val.ad, v2.val.i) ]]);
  }

  /* Community list add */
  INST(FI_CLIST_ADD_PAIR, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_PAIR);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_CLIST, ad, [[ int_set_add(fpool, v1.val.ad, v2.val.i) ]]);
  }

  INST(FI_CLIST_ADD_IP, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_IP);
    METHOD_CONSTRUCTOR("add");

    FID_NEW_BODY();
    /* IP->Quad implicit conversion, must be before FI_CLIST_ADD_QUAD */
    cf_warn("Method add(clist, ip) is deprecated, please use add(clist, quad)");

    FID_INTERPRET_BODY();
    if (!val_is_ip4(&v2)) runtime("Mismatched IP type");
    RESULT(T_CLIST, ad, [[ int_set_add(fpool, v1.val.ad, ipa_to_u32(v2.val.ip)) ]]);
  }

  INST(FI_CLIST_ADD_QUAD, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_QUAD);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_CLIST, ad, [[ int_set_add(fpool, v1.val.ad, v2.val.i) ]]);
  }

  INST(FI_CLIST_ADD_CLIST, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_CLIST);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_CLIST, ad, [[ int_set_union(fpool, v1.val.ad, v2.val.ad) ]]);
  }

  INST(FI_ECLIST_ADD_EC, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_EC);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_ECLIST, ad, [[ ec_set_add(fpool, v1.val.ad, v2.val.ec) ]]);
  }

  INST(FI_ECLIST_ADD_ECLIST, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_ECLIST);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_ECLIST, ad, [[ ec_set_union(fpool, v1.val.ad, v2.val.ad) ]]);
  }

  INST(FI_LCLIST_ADD_LC, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_LC);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_LCLIST, ad, [[ lc_set_add(fpool, v1.val.ad, v2.val.lc) ]]);
  }

  INST(FI_LCLIST_ADD_LCLIST, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_LCLIST);
    METHOD_CONSTRUCTOR("add");
    RESULT(T_LCLIST, ad, [[ lc_set_union(fpool, v1.val.ad, v2.val.ad) ]]);
  }

  INST(FI_PATH_DELETE_INT, 2, 1) {
    ARG(1, T_PATH);
    ARG(2, T_INT);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_PATH, ad, [[ as_path_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_PATH_DELETE_SET, 2, 1) {
    ARG(1, T_PATH);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("delete");

    if (!path_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_PATH, ad, [[ as_path_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  /* Community list delete */
  INST(FI_CLIST_DELETE_PAIR, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_PAIR);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_CLIST, ad, [[ int_set_del(fpool, v1.val.ad, v2.val.i) ]]);
  }

  INST(FI_CLIST_DELETE_IP, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_IP);
    METHOD_CONSTRUCTOR("delete");

    FID_NEW_BODY();
    /* IP->Quad implicit conversion, must be before FI_CLIST_DELETE_QUAD */
    cf_warn("Method delete(clist, ip) is deprecated, please use delete(clist, quad)");

    FID_INTERPRET_BODY();
    if (!val_is_ip4(&v2)) runtime("Mismatched IP type");
    RESULT(T_CLIST, ad, [[ int_set_del(fpool, v1.val.ad, ipa_to_u32(v2.val.ip)) ]]);
  }

  INST(FI_CLIST_DELETE_QUAD, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_QUAD);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_CLIST, ad, [[ int_set_del(fpool, v1.val.ad, v2.val.i) ]]);
  }

  INST(FI_CLIST_DELETE_CLIST, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_CLIST);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_CLIST, ad, [[ clist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_CLIST_DELETE_SET, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("delete");

    if (!clist_set_type(v2.val.t, &(struct f_val){}))
      runtime("Mismatched set type");

    RESULT(T_CLIST, ad, [[ clist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_ECLIST_DELETE_EC, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_EC);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_ECLIST, ad, [[ ec_set_del(fpool, v1.val.ad, v2.val.ec) ]]);
  }

  INST(FI_ECLIST_DELETE_ECLIST, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_ECLIST);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_ECLIST, ad, [[ eclist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_ECLIST_DELETE_SET, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("delete");

    if (!eclist_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_ECLIST, ad, [[ eclist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_LCLIST_DELETE_LC, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_LC);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_LCLIST, ad, [[ lc_set_del(fpool, v1.val.ad, v2.val.lc) ]]);
  }

  INST(FI_LCLIST_DELETE_LCLIST, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_LCLIST);
    METHOD_CONSTRUCTOR("delete");
    RESULT(T_LCLIST, ad, [[ lclist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_LCLIST_DELETE_SET, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("delete");

    if (!lclist_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_LCLIST, ad, [[ lclist_filter(fpool, v1.val.ad, &v2, 0) ]]);
  }

  INST(FI_PATH_FILTER_SET, 2, 1) {
    ARG(1, T_PATH);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("filter");

    if (!path_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_PATH, ad, [[ as_path_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_CLIST_FILTER_CLIST, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_CLIST);
    METHOD_CONSTRUCTOR("filter");
    RESULT(T_CLIST, ad, [[ clist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_CLIST_FILTER_SET, 2, 1) {
    ARG(1, T_CLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("filter");

    if (!clist_set_type(v2.val.t, &(struct f_val){}))
      runtime("Mismatched set type");

    RESULT(T_CLIST, ad, [[ clist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_ECLIST_FILTER_ECLIST, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_ECLIST);
    METHOD_CONSTRUCTOR("filter");
    RESULT(T_ECLIST, ad, [[ eclist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_ECLIST_FILTER_SET, 2, 1) {
    ARG(1, T_ECLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("filter");

    if (!eclist_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_ECLIST, ad, [[ eclist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_LCLIST_FILTER_LCLIST, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_LCLIST);
    METHOD_CONSTRUCTOR("filter");
    RESULT(T_LCLIST, ad, [[ lclist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_LCLIST_FILTER_SET, 2, 1) {
    ARG(1, T_LCLIST);
    ARG(2, T_SET);
    METHOD_CONSTRUCTOR("filter");

    if (!lclist_set_type(v2.val.t))
      runtime("Mismatched set type");

    RESULT(T_LCLIST, ad, [[ lclist_filter(fpool, v1.val.ad, &v2, 1) ]]);
  }

  INST(FI_ROA_CHECK_IMPLICIT, 0, 1) {	/* ROA Check */
    NEVER_CONSTANT;
    RTC(1);
    struct rtable *table = rtc->table;
    ACCESS_RTE;
    ACCESS_EATTRS;
    const net_addr *net = (*fs->rte)->net->n.addr;

    /* We ignore temporary attributes, probably not a problem here */
    /* 0x02 is a value of BA_AS_PATH, we don't want to include BGP headers */
    eattr *e = ea_find(*fs->eattrs, EA_CODE(PROTOCOL_BGP, 0x02));

    if (!e || ((e->type & EAF_TYPE_MASK) != EAF_TYPE_AS_PATH))
      runtime("Missing AS_PATH attribute");

    u32 as = 0;
    as_path_get_last(e->u.ptr, &as);

    if (!table)
      runtime("Missing ROA table");

    if (table->addr_type != NET_ROA4 && table->addr_type != NET_ROA6)
      runtime("Table type must be either ROA4 or ROA6");

    if (table->addr_type != (net->type == NET_IP4 ? NET_ROA4 : NET_ROA6))
      RESULT(T_ENUM_ROA, i, ROA_UNKNOWN); /* Prefix and table type mismatch */
    else
      RESULT(T_ENUM_ROA, i, [[ net_roa_check(table, net, as) ]]);
  }

  INST(FI_ROA_CHECK_EXPLICIT, 2, 1) {	/* ROA Check */
    NEVER_CONSTANT;
    ARG(1, T_NET);
    ARG(2, T_INT);
    RTC(3);
    struct rtable *table = rtc->table;

    u32 as = v2.val.i;

    if (!table)
      runtime("Missing ROA table");

    if (table->addr_type != NET_ROA4 && table->addr_type != NET_ROA6)
      runtime("Table type must be either ROA4 or ROA6");

    if (table->addr_type != (v1.val.net->type == NET_IP4 ? NET_ROA4 : NET_ROA6))
      RESULT(T_ENUM_ROA, i, ROA_UNKNOWN); /* Prefix and table type mismatch */
    else
      RESULT(T_ENUM_ROA, i, [[ net_roa_check(table, v1.val.net, as) ]]);

  }

  INST(FI_FROM_HEX, 1, 1) {	/* Convert hex text to bytestring */
    ARG(1, T_STRING);

    int len = bstrhextobin(v1.val.s, NULL);
    if (len < 0)
      runtime("Invalid hex string");

    struct adata *bs;
    bs = falloc(sizeof(struct adata) + len);
    bs->length = bstrhextobin(v1.val.s, bs->data);
    ASSERT(bs->length == (size_t) len);

    RESULT(T_BYTESTRING, bs, bs);
  }

  INST(FI_FORMAT, 1, 1) {	/* Format */
    ARG_ANY(1);
    RESULT(T_STRING, s, val_format_str(fpool, &v1));
  }

  INST(FI_ASSERT, 1, 0) {	/* Birdtest Assert */
    NEVER_CONSTANT;
    ARG(1, T_BOOL);

    FID_MEMBER(char *, s, [[strcmp(f1->s, f2->s)]], "string %s", item->s);

    ASSERT(s);

    if (!bt_assert_hook)
      runtime("No bt_assert hook registered, can't assert");

    bt_assert_hook(v1.val.i, what);
  }

/*
 *	BIRD Internet Routing Daemon -- Filter instructions
 *
 *	(c) 2018--2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/* Filter instruction words */
#define FI__TWOCHAR(a,b)	((a<<8) | b)
#define FI__LIST \
  F(FI_NOP,			  0, '0') \
  F(FI_ADD,			  0, '+') \
  F(FI_SUBTRACT,		  0, '-') \
  F(FI_MULTIPLY,		  0, '*') \
  F(FI_DIVIDE,			  0, '/') \
  F(FI_AND,			  0, '&') \
  F(FI_OR,			  0, '|') \
  F(FI_PAIR_CONSTRUCT,		'm', 'p') \
  F(FI_EC_CONSTRUCT,		'm', 'c') \
  F(FI_LC_CONSTRUCT,		'm', 'l') \
  F(FI_PATHMASK_CONSTRUCT,	'm', 'P') \
  F(FI_NEQ,			'!', '=') \
  F(FI_EQ,			'=', '=') \
  F(FI_LT,			  0, '<') \
  F(FI_LTE,			'<', '=') \
  F(FI_NOT,			  0, '!') \
  F(FI_MATCH,			  0, '~') \
  F(FI_NOT_MATCH,		'!', '~') \
  F(FI_DEFINED,			'd', 'e') \
  F(FI_TYPE,			  0, 'T') \
  F(FI_IS_V4,			'I', 'i') \
  F(FI_SET,			  0, 's') \
  F(FI_CONSTANT,		  0, 'c') \
  F(FI_VARIABLE,		  0, 'V') \
  F(FI_CONSTANT_INDIRECT,	  0, 'C') \
  F(FI_PRINT,			  0, 'p') \
  F(FI_CONDITION,		  0, '?') \
  F(FI_PRINT_AND_DIE,		'p', ',') \
  F(FI_RTA_GET,			  0, 'a') \
  F(FI_RTA_SET,			'a', 'S') \
  F(FI_EA_GET,			'e', 'a') \
  F(FI_EA_SET,			'e', 'S') \
  F(FI_PREF_GET,		  0, 'P') \
  F(FI_PREF_SET,		'P', 'S') \
  F(FI_LENGTH,			  0, 'L') \
  F(FI_ROA_MAXLEN,		'R', 'M') \
  F(FI_ROA_ASN,			'R', 'A') \
  F(FI_SADR_SRC,		'n', 's') \
  F(FI_IP,			'c', 'p') \
  F(FI_ROUTE_DISTINGUISHER,	'R', 'D') \
  F(FI_AS_PATH_FIRST,		'a', 'f') \
  F(FI_AS_PATH_LAST,		'a', 'l') \
  F(FI_AS_PATH_LAST_NAG,	'a', 'L') \
  F(FI_RETURN,			  0, 'r') \
  F(FI_CALL,			'c', 'a') \
  F(FI_DROP_RESULT,		'd', 'r') \
  F(FI_CLEAR_LOCAL_VARS,	'c', 'V') \
  F(FI_SWITCH,			'S', 'W') \
  F(FI_IP_MASK,			'i', 'M') \
  F(FI_PATH_PREPEND,		'A', 'p') \
  F(FI_CLIST_ADD,		'C', 'a') \
  F(FI_CLIST_DEL,		'C', 'd') \
  F(FI_CLIST_FILTER,		'C', 'f') \
  F(FI_ROA_CHECK_IMPLICIT,	'R', 'i') \
  F(FI_ROA_CHECK_EXPLICIT,	'R', 'e') \
  F(FI_FORMAT,			  0, 'F') \
  F(FI_ASSERT,			'a', 's')

/* The enum itself */
enum f_instruction_code {
#define F(c,a,b) \
  c,
FI__LIST
#undef F
  FI__MAX,
} PACKED;

/* Convert the instruction back to the enum name */
const char *f_instruction_name(enum f_instruction_code fi);



/* Instruction structure for config */
struct f_inst {
  const struct f_inst *next;		/* Next instruction to be executed */
  union {				/* Instruction content */
    struct {				/* Instruction code for dispatching purposes */
      enum f_instruction_code fi_code;
    };

    struct {
      enum f_instruction_code fi_code_a;
      const struct f_inst *p[3];	/* Three arguments at most */
    };

    struct {



    struct {
      enum f_instruction_code 




    enum f_iknst
  u16 aux;		/* Extension to instruction code, T_*, EA_*, EAF_*  */
  union {

    union f_inst_attr a[3];		/* The three arguments */
    struct f_val val;	/* The value if FI_CONSTANT */
    struct {
      union f_inst_attr sa_a[1];
      struct f_static_attr sa;	/* Static attribute def for FI_RTA_* */
    };
    struct {
      union f_inst_attr da_a[1];
      struct f_dynamic_attr da; /* Dynamic attribute def for FI_EA_* */
    };
  };
  int lineno;
};


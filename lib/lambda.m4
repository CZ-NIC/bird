#	Lambda functions for C code
#
#	(c) 2026 Maria Matejka <mq@jmq.cz>
#	(c) 2026 CZ.NIC, z.s.p.o.
#
#	Can be freely distributed and used under the terms of the GNU GPL
#
#	m4_debugmode(aceflqtx)
#
#	Check lib/auto-in-h.m4 for general usage.
#
#	LAMBDA(return type, arguments ...)(value to return)
#	-> create an "unnamed" function locally
#
#	SUBLAMBDA(token, return type, arguments)
#	-> token(value to return)
#	-> define the token to stand for the first part of LAMBDA

AUX_SECTION(PREC,LAMBDA_SECTION,[[
/* Expanded lambda functions */
#define LAMBDA(...)	MACRO_CONCAT_AFTER(_bird_m4_lambda_, __LINE__) MACRO_DROP
#define SUBLAMBDA(...)
]],[[/* End of expanded lambda functions */]])

AUQ_STD()

m4_define(SUBLAMBDA, `LAMBDA_SECTION()
#define $1 LAMBDA()
AUX_MUTE
m4_define($1, [[LAMBDA_HEAD(m4_shift($@))
LAMBDA_BODY($]][[@)]])
')

m4_define(LAMBDA_HEAD, `LAMBDA_SECTION()static $1 _bird_m4_lambda_[[]]m4___line__[[]](m4_shift($@))')

m4_define(LAMBDA, `LAMBDA_HEAD
LAMBDA_BODY')

m4_define(LAMBDA_BODY, `m4_dnl
{
  return $@;
}
AUX_MUTE')

AUQ_ALT()

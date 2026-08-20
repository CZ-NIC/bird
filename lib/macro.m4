m4_divert(-1)
#	Auxiliary macros for C code preprocessing
#
#	(c) 2026 Maria Matejka <mq@jmq.cz>
#	(c) 2026 CZ.NIC, z.s.p.o.
#
#	Can be freely distributed and used under the terms of the GNU GPL
#
#	m4_debugmode(aceflqtx)
#
#	Usage of these macros needs:
#
#	- #include "...-m4-auto.h" as the last local include
#	- $(call m4_auto,...) in the Makefile
#
#	Lambda function usage:
#	
#	LAMBDA(return type, arguments ...)(value to return)
#	-> create an "unnamed" function locally
#
#	SUBLAMBDA(token, return type, arguments)
#	-> token(value to return)
#	-> define the token to stand for the first part of LAMBDA

m4_divert(0)
#define LAMBDA(...)	MACRO_CONCAT_AFTER(_bird_m4_lambda_, __LINE__) MACRO_DROP
#define SUBLAMBDA(...)

m4_divert(-1)
m4_define(SUBLAMBDA, `m4_divert(0)
#define $1 LAMBDA()
m4_divert(-1)
m4_define($1, `LAMBDA_HEAD(m4_shift($@))
LAMBDA_BODY($'`@)')
')

m4_define(LAMBDA_HEAD, `m4_divert(0)static $1 _bird_m4_lambda_`'m4___line__`'(m4_shift($@))')

m4_define(LAMBDA, `LAMBDA_HEAD
LAMBDA_BODY')

m4_define(LAMBDA_BODY, `m4_dnl
{
  return $@;
}
m4_divert(-1)')

m4_m4wrap()
m4_divert(-1)


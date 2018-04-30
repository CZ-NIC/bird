/* 
 *	BIRD Macro Tricks
 *
 *	(c) 2018 Jan Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *	Contains useful but dirty macro tricks:
 *		MACRO_CONCAT(a, b)	-> concatenates a##b
 *		MACRO_BOOL(x)		-> convert 0 to 0, anything else to 1
 *		MACRO_IFELSE(b)(true-branch)(false-branch)
 *					-> b shall be 0 or 1; expands to the appropriate branch
 *		MACRO_ISEMPTY(...)	-> 1 for empty argument list, 0 otherwise
 *		MACRO_FOREACH(func, ...)
 *					-> calling FOREACH(func, a, b, c, d) expands to
 *						func(a) func(b) func(c) func(d)
 *		MACRO_RPACK(func, terminator, ...)
 *					-> packs the list into recursive calls:
 *						func(func(func(func(terminator, a), b), c), d)
 */

#ifndef _BIRD_MACRO_H_
#define _BIRD_MACRO_H_

/* What to do with args */
#define MACRO_DROP(...)
#define MACRO_UNPAREN(...) __VA_ARGS__
#define MACRO_SEP(a, b, sep)  a sep b

/* Aliases for some special chars */
#define MACRO_COMMA ,
#define MACRO_LPAREN (
#define MACRO_RPAREN )
#define MACRO_LPAREN_() (
#define MACRO_RPAREN_() )

/* Multiple expansion trick */
#define MACRO_EXPAND0(...) __VA_ARGS__
#define MACRO_EXPAND1(...) MACRO_EXPAND0(MACRO_EXPAND0(__VA_ARGS__))
#define MACRO_EXPAND2(...) MACRO_EXPAND1(MACRO_EXPAND1(__VA_ARGS__))
#define MACRO_EXPAND3(...) MACRO_EXPAND2(MACRO_EXPAND2(__VA_ARGS__))
#define MACRO_EXPAND(...) MACRO_EXPAND3(MACRO_EXPAND3(__VA_ARGS__))

/* Deferring expansion in the expansion trick */
#define MACRO_EMPTY()
#define MACRO_DEFER(t) t MACRO_EMPTY()
#define MACRO_DEFER2(t) t MACRO_EMPTY MACRO_EMPTY()()
#define MACRO_DEFER3(t) t MACRO_EMPTY MACRO_EMPTY MACRO_EMPTY()()()

/* Token concatenation */
#define MACRO_CONCAT(prefix, ...) prefix##__VA_ARGS__
#define MACRO_CONCAT_AFTER(...) MACRO_CONCAT(__VA_ARGS__)

/* Get first or second argument only */
#define MACRO_FIRST(a, ...) a
#define MACRO_SECOND(a, b, ...) b
#define MACRO_SECOND_OR_ZERO(...) MACRO_SECOND(__VA_ARGS__, 0,)

/* Macro Boolean auxiliary macros */
#define MACRO_BOOL_CHECK_0 ~, 1
#define MACRO_BOOL_NEG(x) MACRO_SECOND_OR_ZERO(MACRO_CONCAT(MACRO_BOOL_CHECK_, x))

#define MACRO_BOOL_NOT_0  1
#define MACRO_BOOL_NOT_1  0

/* Macro Boolean negation */
#define MACRO_NOT(x) MACRO_CONCAT(MACRO_BOOL_NOT_, x)

/* Convert anything to bool (anything -> 1, 0 -> 0) */
#define MACRO_BOOL(x) MACRO_NOT(MACRO_BOOL_NEG(x))

/*
 * Macro If/Else condition
 * Usage: MACRO_IFELSE(condition)(true-branch)(false-branch)
 * Expands to true-branch if condition is true, otherwise to false-branch.
 */
#define MACRO_IFELSE(b) MACRO_CONCAT(MACRO_IFELSE_, b)
#define MACRO_IFELSE_0(...) MACRO_UNPAREN
#define MACRO_IFELSE_1(...) __VA_ARGS__ MACRO_DROP

/* Auxiliary macros for MACRO_FOREACH */
#define MACRO_ISLAST(...) MACRO_BOOL_NEG(MACRO_FIRST(MACRO_ISLAST_CHECK __VA_ARGS__)())
#define MACRO_ISLAST_CHECK() 0

#define MACRO_FOREACH_EXPAND(call, a, ...) MACRO_IFELSE(MACRO_ISLAST(__VA_ARGS__))(call(a))(call(a) MACRO_DEFER2(MACRO_FOREACH_PAREN)()(call, __VA_ARGS__))
#define MACRO_FOREACH_PAREN() MACRO_FOREACH_EXPAND

#define MACRO_RPACK_EXPAND(call, terminator, a, ...) MACRO_IFELSE(MACRO_ISLAST(__VA_ARGS__))(call(terminator, a))(call(MACRO_DEFER2(MACRO_RPACK_PAREN)()(call, terminator, __VA_ARGS__), a))
#define MACRO_RPACK_PAREN() MACRO_RPACK_EXPAND
/*
 * Call the first argument for each following:
 * MACRO_FOREACH(func, a, b, c, d) expands to func(a) func(b) func(c) func(d).
 * It supports also macros as func.
 */
#define MACRO_FOREACH(call, ...) MACRO_EXPAND(MACRO_FOREACH_EXPAND(call, __VA_ARGS__))
#define MACRO_RPACK(call, terminator, ...) MACRO_EXPAND(MACRO_RPACK_EXPAND(call, terminator, __VA_ARGS__))

#endif

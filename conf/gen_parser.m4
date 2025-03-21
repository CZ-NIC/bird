m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Configuration Grammar
#
#	(c) 1998--1999 Martin Mares <mj@atrey.karlin.mff.cuni.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#

# Diversions used:
#	1	includes
#	2	types etc.
#	3	rules
#	4	C code

# Common aliases
m4_define(DNL, `m4_dnl')

# Define macros for defining sections
m4_define(CF_ZONE, `m4_divert($1)/* $2 from m4___file__ */')
m4_define(CF_HDR, `CF_ZONE(1, Headers)')
m4_define(CF_DEFINES, `CF_ZONE(1, Defines)')
m4_define(CF_DECLS, `CF_ZONE(2, Declarations)')
m4_define(CF_GRAMMAR, `CF_ZONE(3, Grammar)')
m4_define(CF_CODE, `CF_ZONE(4, C Code)')
m4_define(CF_END, `m4_divert(-1)')

# Simple iterator
m4_define(CF_itera, `m4_ifelse($#, 1, [[CF_iter($1)]], [[CF_iter($1)[[]]CF_itera(m4_shift($@))]])')
m4_define(CF_iterate, `m4_define([[CF_iter]], m4_defn([[$1]]))CF_itera($2)')

m4_define(CF_append, `m4_define([[$1]], m4_ifdef([[$1]], m4_defn([[$1]])[[$3]])[[$2]])')

# Keywords act as %token<s>
m4_define(CF_keywd, `m4_ifdef([[CF_tok_$1]],,[[m4_define([[CF_tok_$1]],1)CF_append([[CF_kw_rule]],$1,[[ | ]])m4_define([[CF_toks]],CF_toks $1)]])')
m4_define(CF_KEYWORDS, `m4_define([[CF_toks]],[[]])CF_iterate([[CF_keywd]], [[$@]])m4_ifelse(CF_toks,,,%token<s>[[]]CF_toks
)DNL')
m4_define(CF_METHODS, `m4_define([[CF_toks]],[[]])CF_iterate([[CF_keywd]], [[$@]])m4_ifelse(CF_toks,,,%token<s>[[]]CF_toks
)DNL')

m4_define(CF_keywd2, `m4_ifdef([[CF_tok_$1]],,[[m4_define([[CF_tok_$1]],1)m4_define([[CF_toks]],CF_toks $1)]])')
m4_define(CF_KEYWORDS_EXCLUSIVE, `m4_define([[CF_toks]],[[]])CF_iterate([[CF_keywd2]], [[$@]])m4_ifelse(CF_toks,,,%token<s>[[]]CF_toks
)DNL')

# CLI commands
m4_define(CF_CLI, `m4_define([[CF_cmd]], cmd_[[]]m4_translit($1, [[ ]], _))DNL
m4_divert(2)CF_KEYWORDS(m4_translit($1, [[ ]], [[,]]))
m4_divert(3)cli_cmd: CF_cmd
CF_cmd: $1 $2 END')
m4_define(CF_CLI_CMD, `')
m4_define(CF_CLI_OPT, `')
m4_define(CF_CLI_HELP, `')

# ENUM declarations are ignored
m4_define(CF_token, `m4_ifdef([[CF_tok_$1]],,[[m4_define([[CF_tok_$1]],1)%token<s> $1]])')
m4_define(CF_enum, `CF_append([[CF_enum_type]],[[$1 { $$ = $2; }]],[[ | ]])CF_token($1)')
m4_define(CF_ENUM,    `CF_enum(m4_substr($1, 7), $1)')
m4_define(CF_ENUM_PX, `CF_enum(m4_substr($1, 7), $1)')

# After all configuration templates end, we finally generate the grammar file.
m4_m4wrap(`
m4_divert(0)DNL
%{
m4_undivert(1)DNL
%}

m4_undivert(2)DNL

%type <s> KEYWORD
%type <i> enum_type

%%
KEYWORD: CF_kw_rule;
enum_type: CF_enum_type;

m4_undivert(3)DNL

%%
m4_undivert(4)DNL
')

# As we are processing C source, we must access all M4 primitives via
# m4_* and also set different quoting convention: `[[' and ']]'
m4_changequote([[,]])

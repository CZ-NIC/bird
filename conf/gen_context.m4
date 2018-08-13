m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Configuration Context
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#

# Common aliases
m4_define(DNL, `m4_dnl')

# Diversions used:
#	2	context

# We include all the headers
m4_define(CF_HDR, `m4_divert(0)')
m4_define(CF_CTX, `m4_divert(2)')
m4_define(CF_DECLS, `m4_divert(-1)')
m4_define(CF_DEFINES, `m4_divert(-1)')

# After all configuration templates end, we generate the 
m4_m4wrap(`
m4_divert(0)
struct cf_context {
m4_undivert(2)
};
')

# As we are processing C source, we must access all M4 primitives via
# m4_* and also set different quoting convention: `[[' and ']]'
m4_changequote([[,]])


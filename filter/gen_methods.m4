m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Object Method List
#
#	(c) 2018 Maria Matejka <mq@jmq.cz>
#
#	Can be freely distributed and used under the terms of the GNU GPL.
#
# Common aliases
m4_define(DNL, `m4_dnl')

# Diversions used:
#	1	methods

# We don't need headers
m4_define(CF_HDR, `m4_divert(-1)')

m4_define(CF_OBJM, `m4_divert(1)FM_$1,
m4_divert(-1)')

m4_m4wrap(`
m4_divert(0)
#ifndef _BIRD_FILTER_METHOD_H_
#define _BIRD_FILTER_METHOD_H_
enum f_method {
m4_undivert(1)
};
#endif
')

# As we are processing C source, we must access all M4 primitives via
# m4_* and also set different quoting convention: `[[' and ']]'
m4_changequote([[,]])

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

m4_define(INST, `break; case $1:')

m4_changequote([[,]])
m4_divert(0)

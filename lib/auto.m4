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
#	- #include "...-m4-auto-in.h" from wherever you need to have exported headers
#	- #include "...-m4-auto-pre.c" as the last local include
#	- $(call m4_auto,...) in the Makefile
#
####################### Auxiliary technical tools #######################

# Write nowhere
m4_define(AUX_MUTE,`m4_divert(-1)')

# Quoting weirdness
m4_define(AUQ_ALT,`m4_changequote([[,]])')
AUQ_ALT()
m4_define(AUQ_STD,[[m4_changequote(`,')]])
AUQ_STD()

# Self
m4_define(AUX_MACROSET,m4_builtin(__file__))

# Collection of all sections to be undiverted at the end
m4_define(AUX_REGULAR_SECTIONS,)
m4_define(AUX_END_SECTIONS,)

# Collection of things to be done just before undiverting
m4_define(AUX_FINALIZE,`m4_divert(0)')

# Request to do something just before undiverting. Executed
# in reverse order of definition. If something needs to be written out,
# declare a section deferred.
m4_define(AUX_DEFER,`m4_dnl
m4_define([[AUX_FINALIZE]],m4_dnl
$@
m4_defn([[AUX_FINALIZE]]))')

##################### Section definition definitions ####################

# We collect data to output into sections which are then consolidated at the end.
#
#     AUX_SECTION(<target>, <name>, <initial content>, <end content>)
#     Create a regular section <name> containing <initial content> and ended by <end content>.
#
#     AUX_END_SECTION(<target>, <name>, <initial content>, <end content>)
#     Create an end section <name> containing <initial content>.
#     These sections are exported in reverse order after all the regular sections.
#
#
m4_define(AUX_SECTION,`m4_ifelse(TARGET,$1,[[AUX_SECTION_DEF(REGULAR,m4_shift($@))]],[[AUX_SECTION_DROP($@)]])')
m4_define(AUX_END_SECTION,`m4_ifelse(TARGET,$1,[[AUX_SECTION_DEF(END,m4_shift($@))]],[[AUX_SECTION_DROP($@)]])')

# Definition of a section included in the output
# <section_kind>, <name>, <initial content>
m4_define(AUX_SECTION_DEF, `
  # Assign the section $2 number and define the diversion
  m4_define($2,[[m4_divert(]]AUX_SECTION_NUMBER[[)]])
  m4_define(SN_$2,AUX_SECTION_NUMBER)

  # Increment the section number
  m4_define([[AUX_SECTION_NUMBER]], m4_eval(AUX_SECTION_NUMBER+1))

  # Concatentate this section into the All Sections undiverter
  m4_ifelse($1,[[REGULAR]],[[
    m4_define([[AUX_REGULAR_SECTIONS]],
      m4_defn([[AUX_REGULAR_SECTIONS]])[[m4_undivert(SN_$2)]])
    ]],
    [[m4_ifelse($1,[[END]],[[
      m4_define([[AUX_END_SECTIONS]],
	[[m4_undivert(SN_$2)]]m4_defn([[AUX_END_SECTIONS]]))
      ]])
    ]]
  )

  # Divert to that section to make a prefix
$2
[[$3]]
AUX_DEFER([[$2]]
[[$4]]
AUX_MUTE)
AUX_MUTE
')

# Section not intended for this target
m4_define(AUX_SECTION_DROP, `
  m4_define($2,[[m4_divert(-1)]])
  m4_define(SN_$2,666)
')

# Start with the sections at a reasonably high number
m4_define(`AUX_SECTION_NUMBER', 1000)

############################# Final output ##############################

m4_m4wrap(`
AUX_FINALIZE()m4_dnl		Run all deferred macros
AUX_REGULAR_SECTIONS()m4_dnl	Put all regular sections
AUX_END_SECTIONS()m4_dnl	Put all the end sections
')

########################### Default sections ############################
AUQ_ALT()

AUX_END_SECTION(PREC,AUX_HIDE_M4,[[
#define AUX_SECTION(...)
#define AUX_END_SECTION(...)
#define AUX_MUTE(...)
]],)

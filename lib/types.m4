m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Filter Types
#

#m4_debugmode(aceflqtx)

m4_define(MUTE,`m4_divert(-1)')

# Quoting weirdness
m4_define(TDX_ALTQUOTES, `m4_changequote([[,]])')
TDX_ALTQUOTES()
m4_define(TDX_STDQUOTES, [[m4_changequote(`,')]])
TDX_STDQUOTES()

# Finalization defer macros
m4_define(TDX_ALL_SECTIONS,)	# This collects all the sections to undivert
m4_define(TDX_FINALIZE,`m4_divert(0)')			# This collects everything which should be done before that
m4_define(TDX_DEFER,`m4_dnl
m4_define([[TDX_FINALIZE]],m4_dnl
$@
m4_defn([[TDX_FINALIZE]]))')

# Section definition definitions
# ##############################

# Different behavior for sections going to Y and to H
m4_define(TDX_SECTION,`m4_ifelse(TARGET,$1,[[TDX_SECTION_DEF($@)]],[[TDX_SECTION_DROP($@)]])')
m4_define(TDX_SECTION_DEF, `
  # Assign the section $2 number and define the diversion
  m4_define($2,[[m4_divert(]]TDX_SECTION_NUMBER[[)]])
  m4_define(SN_$2,TDX_SECTION_NUMBER)

  # Increment the section number
  m4_define([[TDX_SECTION_NUMBER]], m4_eval(TDX_SECTION_NUMBER+1))

  # Concatentate this section into the All Sections undiverter
  m4_define([[TDX_ALL_SECTIONS]], m4_defn([[TDX_ALL_SECTIONS]])[[m4_undivert(SN_$2)]])

  # Divert to that section to make a prefix
$2
[[$3]]
TDX_DEFER([[$2]]
$4
MUTE)
MUTE
')

# Section not intended for this target
m4_define(TDX_SECTION_DROP, `
  m4_define($2,[[m4_divert(-1)]])
  m4_define(SN_$2,6666)
')

# Using the metadefinitions needs the other set of quotes
TDX_ALTQUOTES()

# Sections for Y target
m4_define([[TDX_SECTION_NUMBER]], 100)
TDX_SECTION(Y, TDY_KEYWORDS, [[CF_DECLS]])
TDX_SECTION(Y, TDY_TYPE, [[CF_GRAMMAR]])

# Sections for ENUMS target, required arguments
TDX_SECTION(ENUMS, __TDH_BEGIN,[[
#ifndef _BIRD_LIB_TYPES_ENUMS_H_
#define _BIRD_LIB_TYPES_ENUMS_H_
]])
TDX_DEFER([[MUTE()TDX_SECTION(ENUMS, __TDH_END, [[
#endif
]])]])

TDX_SECTION(ENUMS, TDH_TYPE_ENUM, [[
enum f_type {]],
[[} PACKED;
]])

TDX_SECTION(ENUMS, TDH_TYPE_FUNCS)

# Section for UNION target, required arguments
m4_define([[TDX_SECTION_NUMBER]], 300)
TDX_SECTION(UNION, TDH_UNION)

# Sections for C target, optional arguments
m4_define([[TDX_SECTION_NUMBER]], 400)

TDX_SECTION(C, __TDC_BEGIN, [[
#include "sysdep/config.h"
#include "lib/types-enums.h"
#include "nest/route.h"
]])

TDX_SECTION(C, TDC_TYPE_INCLUDES)

TDX_SECTION(C, TDC_TYPE_STR, [[
const char *
f_type_name(enum f_type t)
{
  switch (t) {]],
[[    default: return "?";
  }
}]])

TDH_TYPE_FUNCS()
const char *f_type_name(enum f_type);
MUTE

TDX_SECTION(C, TDC_TYPE_CF_NAME, [[

#include "conf/conf.h"

const char *
cf_type_name(enum f_type t)
{
  switch (t) {]],
[[    default: cf_warn("Bug: Unknown type %u in config error message");
	     return "???";
  }
}]])

TDH_TYPE_FUNCS()
const char *cf_type_name(enum f_type);
MUTE

TDX_SECTION(C, TDC_TYPE_VALID_SET_TYPE, [[
bool
f_valid_set_type(enum f_type t)
{
  switch (t) {]],
[[    default: return false;
  }
}]])

TDH_TYPE_FUNCS()
bool f_valid_set_type(enum f_type);
MUTE

TDX_SECTION(C, TDC_TO_EA_TYPE, [[
int
f_type_attr(enum f_type t)
{
  switch (t) {]],
[[    default: cf_error("Custom route attribute of unsupported type");
  }
}]])

TDH_TYPE_FUNCS()
int f_type_attr(enum f_type);
MUTE


# Dynamic section numbers for later
m4_define([[TDX_SECTION_NUMBER]],10000)

# Macros to be used in the user data need the standard quote set
# so that the users can use [[]]
TDX_STDQUOTES

# Type definition header
m4_define(`TYPEDEF',`m4_dnl
m4_define([[TDL_TYPE_ENUM]],[[$1]])m4_dnl		T_xyz enum token
m4_define([[TDL_TYPE_CTYPE]],[[$2]])m4_dnl		C type for storage
m4_define([[TDL_TYPE_BTYPE]],[[$3]])m4_dnl		BIRD filter type
m4_define([[TDL_TYPE_UNAME]],[[val_]][[$1]])m4_dnl	Union name for storage
TDH_TYPE_ENUM  TDL_TYPE_ENUM, /* Filter type TDL_TYPE_BTYPE, stored as TDL_TYPE_CTYPE */
TDH_UNION    m4_ifelse([[$2]],[[void]],/* No storage for void type TDL_TYPE_ENUM */,TDL_TYPE_CTYPE TDL_TYPE_UNAME;)
TDC_TYPE_STR    case TDL_TYPE_ENUM: return "TDL_TYPE_BTYPE";
TDY_KEYWORDS()CF_KEYWORDS(m4_translit(TDL_TYPE_BTYPE,[[a-z ]],[[A-Z,]]))
MUTE')

# Type additional options
# Header file defining the underlying C type
m4_define(`TD_INCLUDE',`m4_dnl
TDC_TYPE_INCLUDES
#include "$1"
MUTE')

# Name to be used in non-filter configuration error messages
m4_define(`TD_CF_NAME',`m4_dnl
TDC_TYPE_CF_NAME    case TDL_TYPE_ENUM: return "$1";
MUTE')

# This type might be used as a set member
m4_define(`TD_SET_MEMBER',`m4_dnl
TDC_TYPE_VALID_SET_TYPE    case TDL_TYPE_ENUM: return true;
MUTE')

# Storage type for eattrs
m4_define(`TD_EA',`m4_dnl
TDC_TO_EA_TYPE    case TDL_TYPE_ENUM: return $1;
MUTE')

# Enum definition
m4_define(`ENUMDEF',`m4_dnl
m4_define([[TDL_ENUM_LC]],[[t_enum_]]$1)m4_dnl			Prefixed enum name
m4_define([[TDL_ENUM_UC]],m4_translit(TDL_ENUM_LC,a-z,A-Z))m4_dnl	Uppercase version of the name
m4_define([[TDL_ENUM_CTYPE]],enum $1)m4_dnl		Declare this enum type for usage in C

# Contents of the enum itself
TDX_SECTION(ENUMS, [[TDH_ENUM_ENUM_]]$1,
TDL_ENUM_CTYPE [[{]],
[[};

const char *f_str_]]TDL_ENUM_LC[[(TDL_ENUM_CTYPE);
]])

# Enum to string function
TDX_SECTION(C, [[TDC_ENUM_STR_]]$1, [[
const char *
f_str_]]TDL_ENUM_LC[[(]]TDL_ENUM_CTYPE[[ val)
{
  switch (val) {]],
[[  }
  bug("Unknown value %d for ]]TDH_ENUM_CTYPE[[", val);
}]])

TYPEDEF(TDL_ENUM_UC, TDL_ENUM_CTYPE, TDL_ENUM_CTYPE) m4_dnl	Declare this enum type as a config/filter type
TD_SET_MEMBER[[]]m4_dnl						Enums may be in sets
TD_ENUM_ITEMS($@)m4_dnl						Process the enum items if declared
TDY_TYPE()type: ENUM m4_translit($1,a-z,A-Z) { $$ = TDL_ENUM_UC; } ;
MUTE')

# Add more enum items
m4_define(`TD_ENUM_ITEMS',`m4_dnl
m4_ifelse($2,,,[[
TD_ENUM_SINGLE_ITEM($1,$2)
TD_ENUM_ITEMS($1,m4_shift(m4_shift($@)))
]])
MUTE')

# Add a single item
m4_define(`TD_ENUM_SINGLE_ITEM',`m4_dnl
# It may have an explicit value, split out the name only.
# We find the = sign and chomp out also the whitespace before it.
m4_define([[TDL_ENUM_EQINDEX]],m4_index([[$2]],=))
m4_ifelse(TDL_ENUM_EQINDEX,[[-1]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],[[$2]])]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],m4_patsubst(m4_substr([[$2]],0,TDL_ENUM_EQINDEX),[[\s+$]]))]]
)
m4_dnl Enum definition, including the value
m4_indir([[TDH_ENUM_ENUM_]]$1)m4_dnl
  $2,
m4_dnl Enum to string function
m4_indir([[TDC_ENUM_STR_]]$1)m4_dnl
  case TDL_ENUM_ITEM_NAME: return "TDL_ENUM_ITEM_NAME";
m4_dnl Config keyword definition
TDY_KEYWORDS()CF_PUT_KW(TDL_ENUM_ITEM_NAME, [[CFT_]]TDL_ENUM_ITEM_NAME)
m4_dnl Allowed usage: As a standalone constant or inside a set atom 
TDY_TYPE()m4_dnl
constant: TDL_ENUM_ITEM_NAME { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = TDL_ENUM_UC, .val.i = TDL_ENUM_ITEM_NAME, }); } ;
set_atom0: TDL_ENUM_ITEM_NAME { $$.type = TDL_ENUM_UC; $$.val.i = TDL_ENUM_ITEM_NAME; } ;
MUTE')

# The same but an item for use not visible by the user
m4_define(`TD_ENUM_INTERNAL_ITEM',`m4_dnl
# It may have an explicit value, split out the name only
m4_define([[TDL_ENUM_EQINDEX]],m4_index([[$2]],=))
m4_ifelse(TDL_ENUM_EQINDEX,[[-1]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],[[$2]])]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],m4_substr([[$2]],0,TDL_ENUM_EQINDEX))]]
)
m4_dnl Enum definition, including the value
m4_indir([[TDH_ENUM_ENUM_]]$1)m4_dnl
  $2,
m4_dnl Enum to string function
m4_indir([[TDC_ENUM_STR_]]$1)m4_dnl
  case TDL_ENUM_ITEM_NAME: break; /* No string representation, fail instead */
MUTE')

# Output wrapper
m4_m4wrap(`
TDX_FINALIZE
m4_ifelse(TARGET,[[H]],[[#if 0]])
TDX_ALL_SECTIONS
m4_ifelse(TARGET,[[H]],[[#endif]])
')

m4_changequote([[,]])
MUTE

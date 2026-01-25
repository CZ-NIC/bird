m4_divert(-1)m4_dnl
#
#	BIRD -- Generator of Filter Types
#
#
# Notes from the meeting:
#
# We want the type system reworked to match what we actually need from it.
#
#
### Types
#
# First, there are basic types of several kinds:
#
# - A generic integer (ideally of unlimited length)
# - Bit-limited integers (int1 up to int128), auto-converted to generic integer every time it exits storage, and range-checked when storing back
# - Various other types, like bool, ec, lc, ip addr
# - Some weird types like net (which is kinda compound but not exactly)
#
# Then, there are compound types:
#
# - an ordered list of items of the same type
# - a set of unique items of the same type
# - a structure type with unique keys and assigned typed values
#
# List and set is identified by setting a specific bit in the type.
# Structure types have their own range.
#
# We will allow explicit typecasting wherever reasonable.
#
### Representations
#
# Every type may have multiple storage representations and there are bits
# reserved to store information on how the data is stored. One of these
# representations (all zeros) is a canonical one.
#
# Canonical representations:
# - for basic types, either an integer or a pointer to bird-native struct
# - for structure types, cached ea_list pointer
# - for lists, adata containing basic types one after another
# - for sets, adata containing basic types one after another, sorted
#
# Alternative representations:
# - for lists and sets, adata containing type ranges
# - for lists and sets, adata containing an operation and original adata pointer
# - for structure types, uncached ea_list pointer, possibly even multilayered
#
### Storage
#
# There are multiple places where typed values can be stored:
#
# - Filter on-stack
#   - any representation is allowed, apart from bit-limited integers
#   - we want to reduce the f_val size ideally to 16 bytes (8+8) to gain speed a bit
# - Filter in-variable, func argument or return value
#   - bit-limited integers range-checked
#   - everything else as if on-stack
# - Storage in ea_list, uncached
#   - everything as if on-stack, we don't care
#   - extending the current eattr structure to accommodate 8B integers (there are pointers to adata already anyway)
#   - store single pointers directly there
# - Storage in ea_list, cached
#   - converting everything strictly to the canonical representation
#   - the conversion must be done from bottom to top, as ea_lists change their pointers
#   - size-checking all adata so that they don't eat up all memory?
#	- probably a global attribute size limit knob, by default at 64k, with no reload on reconf?
#
### Writeout
#
# - Special value formatting needs a different type
# - Enums have two value formats, one is the exact token,
#   the other is a semantic nice representation, used in different places differently (as fits purpose)
#
### Specific attributes
#
# BGP encap attribute and other complex data structures may become a multi-level EA list:
#
# - type e.g. BGP encap, stored as ea_list
# - keys e.g. GRE or VxLAN
# - GRE is of type BGP encap GRE, stored as ea_list
# - VxLAN is of type BGP encap VxLAN, stored as ea_list
#
# BGP next hop attribute becomes a structure, and if `bgp_next_hop = bgp_next_hop` is ever encountered,
# the user is warned that it should be now `bgp_next_hop = { global bgp_next_hop.global }`
#
### Literals
#
# List and set are using the same literal representation with [ and ];
# the actual type is inferred from the contents and from destination.
#
# Structs use the representation of { meow 1; nya 2; } as if regular config.
# This might be later used to rework the protocol parsers but we are not doing it now.
#
# If the parser fails to infer the literal type, it requires prefixing the
# literal by an explicit typecast, as if C: (nexthop) -> with that, both
# these constructions are equivalent:
#
#     (nexthop list) [ { ... }, { ... }, ... ]
#     [ (nexthop) { ... }, { ... }, ... ]
#
### For-cycles
#
## over lists and sets
# for nexthop nh in nexthops do {
#   ...
# }
#
## over structs?
# for string key, auto val in bgp_encap do {
#   ...
# }
#
## over numbers?
# for int i = 0 upto 1407 step 67 do {
#   ...
# }
#
### Structure definitions in code
#
#    STRUCTDEF(T_NEXTHOP, nexthop,
#        T_IP gw,
#        T_INT weight,
#        ...
#        )
#      ....
#    }
#
### Structure definitions in config
#
#   struct meow {
#	ip nya;
#	int whiskers;
#   };
#
### Method definitions in config
#
#   method meow.purr(int volume) {
#     ...
#   }
#
# If the return type is the same as the original, allow call as standalone command.
#
### Default methods
#
# - lists: prepend, append, delete, filter
# - sets: add, delete, filter
#
### Indexing
#
# List[index]
# Struct.key

#m4_debugmode(aceflqtx)

m4_define(MUTE,`m4_divert(-1)')

####################### Auxiliary technical tools #######################

# Quoting weirdness
m4_define(TDQ_ALT, `m4_changequote([[,]])')
TDQ_ALT()
m4_define(TDQ_STD, [[m4_changequote(`,')]])
TDQ_STD()

# Collection of all sections to be undiverted at the end
m4_define(TDX_REGULAR_SECTIONS,)
m4_define(TDX_END_SECTIONS,)

# Collection of things to be done just before undiverting
m4_define(TDX_FINALIZE,`m4_divert(0)')

# Request to do something just before undiverting. Executed
# in reverse order of definition. If something needs to be written out,
# declare a section deferred.
m4_define(TDX_DEFER,`m4_dnl
m4_define([[TDX_FINALIZE]],m4_dnl
$@
m4_defn([[TDX_FINALIZE]]))')

##################### Section definition definitions ####################

# We run the M4 with different targets and each time we give out only
# some of the sections.
#
#     TDX_SECTION(<target>, <name>, <initial content>, <end content>)
#     Create a regular section <name> exported to <target> containing <initial content>.
#
#     TDX_END_SECTION(<target>, <name>, <initial content>, <end content>)
#     Create an end section <name> exported to <target> containing <initial content>.
#     These sections are exported in reverse order after all the
#     regular sections.
#
#
m4_define(TDX_SECTION,`m4_ifelse(TARGET,$1,[[TDX_SECTION_DEF(REGULAR,m4_shift($@))]],[[TDX_SECTION_DROP($@)]])')
m4_define(TDX_END_SECTION,`m4_ifelse(TARGET,$1,[[TDX_SECTION_DEF(END,m4_shift($@))]],[[TDX_SECTION_DROP($@)]])')

# Definition of a section included in the output
# <section_kind>, <name>, <initial content>
m4_define(TDX_SECTION_DEF, `
  # Assign the section $2 number and define the diversion
  m4_define($2,[[m4_divert(]]TDX_SECTION_NUMBER[[)]])
  m4_define(SN_$2,TDX_SECTION_NUMBER)

  # Increment the section number
  m4_define([[TDX_SECTION_NUMBER]], m4_eval(TDX_SECTION_NUMBER+1))

  # Concatentate this section into the All Sections undiverter
  m4_ifelse($1,[[REGULAR]],[[
    m4_define([[TDX_REGULAR_SECTIONS]],
      m4_defn([[TDX_REGULAR_SECTIONS]])[[m4_undivert(SN_$2)]])
    ]],
    [[m4_ifelse($1,[[END]],[[
      m4_define([[TDX_END_SECTIONS]],
	[[m4_undivert(SN_$2)]]m4_defn([[TDX_END_SECTIONS]]))
      ]])
    ]]
  )

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
  m4_define(SN_$2,666)
')

######################## Basic output sections ##########################

# Defining sections requires the other set of quotes, so that we can run
# these inside our macros.
TDQ_ALT()

# Start with the sections at a reasonably high number
m4_define([[TDX_SECTION_NUMBER]], 1000)

TDX_SECTION(Y, TDY_BEGIN,[[
/*
 *	BIRD Internet Routing Daemon -- Filter and config type definitions
 *
 *	Auto-generated by ]]m4_builtin(__file__)[[ with TARGET=]]TARGET[[
 */
]])

# Keyword declarations for the config parser
TDX_SECTION(Y, TDY_KEYWORDS, [[CF_DECLS]])

# Bison rule declarations
TDX_SECTION(Y, TDY_TYPE, [[CF_GRAMMAR]])


# The types-enums.h file needs an inclusion guard
# Declares one section here, and one section deferred to the very end,
# so that it is put last into the file.
TDX_SECTION(ENUMS, TDH_BEGIN,[[
/*
 *	BIRD Internet Routing Daemon -- Filter and config type definitions
 *
 *	Auto-generated by ]]m4_builtin(__file__)[[ with TARGET=]]TARGET[[
 */
#ifndef _BIRD_LIB_TYPES_ENUMS_H_
#define _BIRD_LIB_TYPES_ENUMS_H_
]])
TDX_END_SECTION(ENUMS, TDH_END, [[
#endif
]])

# The main type enum
TDX_SECTION(ENUMS, TDH_TYPE_ENUM, [[
enum f_type {]],
[[} PACKED;
]])

# Functions associated with the enums
TDX_SECTION(ENUMS, TDH_TYPE_FUNCS)


# The types-union.h file needs an inclusion guard
TDX_SECTION(UNION, TDU_BEGIN,[[
/*
 *	BIRD Internet Routing Daemon -- Filter and config value union
 *
 *	Auto-generated by ]]m4_builtin(__file__)[[ with TARGET=]]TARGET[[
 */
#ifndef _BIRD_LIB_TYPES_UNION_H_
#define _BIRD_LIB_TYPES_UNION_H_
]])
TDX_END_SECTION(UNION, TDU_END, [[
#endif
]])

# Contents of the filter value unions
TDX_SECTION(UNION, TDU_UNION_SHORT, [[
union f_val_short {
]],[[
};
]])

TDX_SECTION(UNION, TDU_UNION_LONG, [[
union f_val_long {
]],[[
    uint i;
    u64 ec;
    struct lcomm *lc;
    vpn_rd rd;
    ip_addr ip;
    const net_addr *net;
    const char *s;
    const struct adata *bs;
    const struct f_tree *t;
    const struct f_trie *ti;
    const struct adata *ad;
    const struct f_path_mask *path_mask;
    struct f_path_mask_item *pmi;
    struct rte *rte;
};

struct f_val {
  enum f_type type;
  union f_val_long val;
};
]])

TDX_SECTION(UNION, TDU_FUNCS)


# Header for the auxiliary function file
TDX_SECTION(C, TDC_BEGIN, [[
/*
 *	BIRD Internet Routing Daemon -- Filter and config type auxiliary functions
 *
 *	Auto-generated by ]]m4_builtin(__file__)[[ with TARGET=]]TARGET[[
 */
#include "sysdep/config.h"
#include "nest/bird.h"
#include "lib/types-enums.h"
#include "lib/types-union.h"
#include "nest/route.h"
]])

# Type name string
TDH_TYPE_FUNCS()m4_dnl
const char *f_type_name(enum f_type);
MUTE

TDX_SECTION(C, TDC_TYPE_STR, [[
const char *
f_type_name(enum f_type t)
{
  switch (t) {]],
[[    default: return "?";
  }
}]])

########################## Basic type definition #####################

# Macros to be used in the user data need the standard quote set
# so that the users can use [[]]
TDQ_STD()

# Type definition header
# TYPEDEF(T_xyz enum token, storage C type, filter type)
m4_define(`TYPEDEF',`m4_dnl
m4_define([[TDL_TYPE_ENUM]],[[$1]])m4_dnl		T_xyz enum token
m4_define([[TDL_TYPE_CTYPE]],[[$2]])m4_dnl		C type for storage
m4_define([[TDL_TYPE_BTYPE]],[[$3]])m4_dnl		BIRD filter type
m4_define([[TDL_TYPE_UNAME]],[[val_]][[$1]])m4_dnl	Union name for storage
TDH_TYPE_ENUM  TDL_TYPE_ENUM, /* Filter type TDL_TYPE_BTYPE, stored as TDL_TYPE_CTYPE */
TDU_UNION_LONG    m4_ifelse([[$2]],[[void]],/* No storage for void type TDL_TYPE_ENUM */,TDL_TYPE_CTYPE TDL_TYPE_UNAME;)
TDC_TYPE_STR    case TDL_TYPE_ENUM: return "TDL_TYPE_BTYPE";
TDY_KEYWORDS()CF_KEYWORDS(m4_translit(TDL_TYPE_BTYPE,[[a-z ]],[[A-Z,]]))
MUTE')

######################## Additional type options #######################

# Header file defining the underlying C type. Needed for the union and
# for the auxiliary functions.
#
#     TD_INCLUDE(filename)

m4_define(`TD_INCLUDE',`m4_dnl
TDC_BEGIN
#include "$1"
MUTE')

# Name to be used in non-filter configuration error messages.
#
#     TD_CF_NAME(unquoted string)

TDH_TYPE_FUNCS()m4_dnl
const char *cf_type_name(enum f_type);
MUTE

TDQ_ALT
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
TDQ_STD

m4_define(`TD_CF_NAME',`m4_dnl
TDC_TYPE_CF_NAME    case TDL_TYPE_ENUM: return "$1";
MUTE')

# Declaration that this specific type may be used as a set member.
#
#     TD_SET_MEMBER

TDH_TYPE_FUNCS()m4_dnl
bool f_valid_set_type(enum f_type);
MUTE

TDQ_ALT
TDX_SECTION(C, TDC_TYPE_VALID_SET_TYPE, [[
bool
f_valid_set_type(enum f_type t)
{
  switch (t) {]],
[[    default: return false;
  }
}]])
TDQ_STD

m4_define(`TD_SET_MEMBER',`m4_dnl
TDC_TYPE_VALID_SET_TYPE    case TDL_TYPE_ENUM: return true;
MUTE')

# Relationship between EA type and filter type. This should be temporary
# until we unify both type systems.
#
#     TD_EA(EAF_TYPE_*)

TDH_TYPE_FUNCS()m4_dnl
int f_type_attr(enum f_type);
MUTE

TDQ_ALT
TDX_SECTION(C, TDC_TO_EA_TYPE, [[
int
f_type_attr(enum f_type t)
{
  switch (t) {]],
[[    default: cf_error("Custom route attribute of unsupported type");
  }
}]])
TDQ_STD

m4_define(`TD_EA',`m4_dnl
TDC_TO_EA_TYPE    case TDL_TYPE_ENUM: return $1;
MUTE')

# Conversion of the type to its canonical back-parseable string representation.
#
#     TD_STR(arguments for buffer_print)
#     TD_STR_BUF(a command instead of buffer_print)
#
#     Available macros:
#	_t:   the type enum
#	_v:   the value
#	_aux: auxiliary on-stack buffer
#	_buf: the target buffer

TDU_FUNCS()m4_dnl
void f_val_str(const struct f_val *, buffer *buf);
MUTE

TDQ_ALT
TDX_SECTION(C, TDC_STR, [[
void
f_val_str(const struct f_val *val, buffer *_buf)
{
  enum f_type _t = val->type;
  char _aux[1024]; 
  switch (_t) {]],
[[    default: buffer_print(_buf, "[value of unknown type %x]", _t); return;
  }
}]])
TDQ_STD

m4_define(`TD_STR_BUF',`m4_dnl
TDC_STR()m4_dnl
[[#]]define _v (val->val.TDL_TYPE_UNAME)
    case TDL_TYPE_ENUM: $@; return;
#undef _v
MUTE')

m4_define(`TD_STR',`TD_STR_BUF(buffer_print(_buf, $@))')

# Enum definition.
#
#     ENUMDEF(enum name, items...)
#
#     Defines the enum type and its items. It's allowed to put
#     explicit enum values into this definition.
#     This also automatically generates f_str_t_enum_<name>()
#     for stringification.
#
#     TODO: add also "pretty type formatting" for semantically nice
#     user display, like what rtd and rts has.

m4_define(`ENUMDEF',`m4_dnl
m4_define([[TDL_ENUM_LC]],[[t_enum_]]$1)m4_dnl			Prefixed enum name
m4_define([[TDL_ENUM_UC]],m4_translit(TDL_ENUM_LC,a-z,A-Z))m4_dnl	Uppercase version of the name
m4_define([[TDL_ENUM_CTYPE]],enum $1)m4_dnl		Declare this enum type for usage in C

# Contents of the enum itself
TDX_SECTION(ENUMS, [[TDH_ENUM_ENUM_]]$1,
TDL_ENUM_CTYPE [[{]],
[[};

const char *f_str_]]TDL_ENUM_LC[[(TDL_ENUM_CTYPE);
const char *f_pretty_]]TDL_ENUM_LC[[(TDL_ENUM_CTYPE);
]])

# Enum to string function
TDX_SECTION(C, [[TDC_ENUM_STR_]]$1, [[
const char *
f_str_]]TDL_ENUM_LC[[(]]TDL_ENUM_CTYPE[[ val)
{
  switch (val) {]],
[[  }
m4_dnl  bug("Unknown value %d for ]]TDL_ENUM_CTYPE[[", val);
  return tmp_sprintf("(]]TDL_ENUM_CTYPE[[) %u", val);
}]])

# Enum to pretty function
TDX_SECTION(C, [[TDC_ENUM_PRETTY_]]$1, [[
const char *
f_pretty_]]TDL_ENUM_LC[[(]]TDL_ENUM_CTYPE[[ val)
{
  switch (val) {]],
[[  }
m4_dnl  log(L_BUG "Unknown value %d for ]]TDH_ENUM_CTYPE[[", val);
  return tmp_sprintf("Unknown value %u of ]]TDL_ENUM_CTYPE[[", val);
}]])

TYPEDEF(TDL_ENUM_UC, TDL_ENUM_CTYPE, TDL_ENUM_CTYPE) m4_dnl	Declare this enum type as a config/filter type
TD_SET_MEMBER[[]]m4_dnl						Enums may be in sets
TD_STR("%s", f_str_[[]]TDL_ENUM_LC[[(_v)]]);m4_dnl		Display the enum as string
TD_ENUM_ITEMS($@)m4_dnl						Process the enum items if declared
TDY_TYPE()type: ENUM m4_translit($1,a-z,A-Z) { $$ = TDL_ENUM_UC; } ;
MUTE')

# Add more enum items into an already defined enum.
#
#     TD_ENUM_ITEMS(enum name, items...)
#
#     The values may contain explicit enum values.

m4_define(`TD_ENUM_ITEMS',`m4_dnl
m4_ifelse($2,,,[[
TD_ENUM_SINGLE_ITEM($1,$2)
TD_ENUM_ITEMS($1,m4_shift(m4_shift($@)))
]])
MUTE')

# Add a single item into an already defined enum.
#
#     TD_ENUM_SINGLE_ITEM(enum name, pretty name: item)
#     TD_ENUM_SINGLE_ITEM(enum name, pretty name: item = value)
#
#     The item may contain explicit enum value. Pretty name must not contain colon.
#

m4_define(`TD_ENUM_SINGLE_ITEM',`m4_dnl
# First split off the pretty name.
m4_define([[TDL_ENUM_COLONINDEX]],m4_index([[$2]],:))
m4_ifelse(TDL_ENUM_COLONINDEX,[[-1]],
  [[m4_define([[TDL_ENUM_REST]],[[$2]])]],
  [[
    m4_define([[TDL_ENUM_PRETTY]],m4_substr([[$2]],0,TDL_ENUM_COLONINDEX))
    m4_define([[TDL_ENUM_REST]],m4_patsubst(m4_substr([[$2]],m4_eval(TDL_ENUM_COLONINDEX+1)),[[^\s+]]))
  ]]
)
# It may have an explicit value, split out the name only.
# We find the = sign and chomp out also the whitespace before it.
m4_define([[TDL_ENUM_EQINDEX]],m4_index(TDL_ENUM_REST,=))
m4_ifelse(TDL_ENUM_EQINDEX,[[-1]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],TDL_ENUM_REST)]],
  [[m4_define([[TDL_ENUM_ITEM_NAME]],m4_patsubst(m4_substr(TDL_ENUM_REST,0,TDL_ENUM_EQINDEX),[[\s+$]]))]]
)
m4_ifelse(TDL_ENUM_COLONINDEX,[[-1]],[[m4_define([[TDL_ENUM_PRETTY]],TDL_ENUM_ITEM_NAME)]])
m4_dnl Enum definition, including the value
m4_indir([[TDH_ENUM_ENUM_]]$1)m4_dnl
  TDL_ENUM_REST,
m4_dnl Enum to string function
m4_indir([[TDC_ENUM_STR_]]$1)m4_dnl
    case TDL_ENUM_ITEM_NAME: return "TDL_ENUM_ITEM_NAME";
m4_dnl Enum to pretty string function
m4_indir([[TDC_ENUM_PRETTY_]]$1)m4_dnl
    case TDL_ENUM_ITEM_NAME: return "TDL_ENUM_PRETTY";
m4_dnl Config keyword definition
TDY_KEYWORDS()CF_PUT_KW(TDL_ENUM_ITEM_NAME, [[CFT_]]TDL_ENUM_ITEM_NAME)
m4_dnl Allowed usage: As a standalone constant or inside a set atom
TDY_TYPE()m4_dnl
constant: TDL_ENUM_ITEM_NAME { $$ = f_new_inst(FI_CONSTANT, (struct f_val) { .type = TDL_ENUM_UC, .val.i = TDL_ENUM_ITEM_NAME, }); } ;
set_atom0: TDL_ENUM_ITEM_NAME { $$.type = TDL_ENUM_UC; $$.val.i = TDL_ENUM_ITEM_NAME; } ;
MUTE')

# Add a single item into an already defined enum but not visible
# to users, i.e. it's not available in the config parser.
#
#     TD_ENUM_INTERNAL_ITEM(enum name, item)
#
#     The item may contain explicit enum value.

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
m4_dnl Enum to pretty function
m4_indir([[TDC_ENUM_PRETTY_]]$1)m4_dnl
    case TDL_ENUM_ITEM_NAME: break; /* No string representation, fail instead */
MUTE')

############################# Final output ##############################

m4_m4wrap(`
TDX_FINALIZE()m4_dnl		Run all deferred macros
TDX_REGULAR_SECTIONS()m4_dnl	Put all regular sections
TDX_END_SECTIONS()m4_dnl	Put all the end sections
')

########################## Declaration cleanup ##########################
TDQ_ALT()

/*
 *	BIRD -- Flow specification (RFC 5575) grammar
 *
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#define PARSER 1

#include "nest/bird.h"
#include "lib/flowspec.h"


CF_DEFINES

struct flow_builder *this_flow;

/**
 * flow_check_cf_value_length - check value by flowspec component type
 * @fb: flow builder instance
 * @val: value
 *
 * This function checks if the value is in range of component's type support.
 * If some problem will appear, the function calls cf_error() function with
 * a textual description of reason to failing of validation.
 */
static void
flow_check_cf_value_length(struct flow_builder *fb, u32 val)
{
  enum flow_type t = fb->this_type;
  u8 max = flow_max_value_length(t, fb->ipv6);

  if (t == FLOW_TYPE_DSCP && val > 0x3f)
    cf_error("%s value %u out of range (0-63)", flow_type_str(t, fb->ipv6), val);

  if (max == 1 && (val > 0xff))
    cf_error("%s value %u out of range (0-255)", flow_type_str(t, fb->ipv6), val);

  if (max == 2 && (val > 0xffff))
    cf_error("%s value %u out of range (0-65535)", flow_type_str(t, fb->ipv6), val);
}

/**
 * flow_check_cf_bmk_values - check value/bitmask part of flowspec component
 * @fb: flow builder instance
 * @neg: negation operand
 * @val: value from value/mask pair
 * @mask: bitmap mask from value/mask pair
 *
 * This function checks value/bitmask pair. If some problem will appear, the
 * function calls cf_error() function with a textual description of reason
 * to failing of validation.
 */
static void
flow_check_cf_bmk_values(struct flow_builder *fb, u8 neg, u32 val, u32 mask)
{
  flow_check_cf_value_length(fb, val);
  flow_check_cf_value_length(fb, mask);

  if (neg && !(val == 0 || val == mask))
    cf_error("For negation, value must be zero or bitmask");

  if ((fb->this_type == FLOW_TYPE_TCP_FLAGS) && (mask & 0xf000))
    cf_error("Invalid mask 0x%x, must not exceed 0xfff", mask);

  if ((fb->this_type == FLOW_TYPE_FRAGMENT) && fb->ipv6 && (mask & 0x01))
    cf_error("Invalid mask 0x%x, bit 0 must be 0", mask);

  if (val & ~mask)
    cf_error("Value 0x%x outside bitmask 0x%x", val, mask);
}

/**
 * flow4_validate_cf - validate flowspec data structure &net_addr_flow4 in parsing time
 * @f: flowspec data structure &net_addr_flow4
 *
 * Check if @f is valid flowspec data structure. Can call cf_error() function
 * with a textual description of reason to failing of validation.
 */
static void
flow4_validate_cf(net_addr_flow4 *f)
{
  enum flow_validated_state r = flow4_validate(flow4_first_part(f), flow_read_length(f->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}

/**
 * flow6_validate_cf - validate flowspec data structure &net_addr_flow6 in parsing time
 * @f: flowspec data structure &net_addr_flow6
 *
 * Check if @f is valid flowspec data structure. Can call cf_error() function
 * with a textual description of reason to failing of validation.
 */
static void
flow6_validate_cf(net_addr_flow6 *f)
{
  enum flow_validated_state r = flow6_validate(flow6_first_part(f), flow_read_length(f->data));

  if (r != FLOW_ST_VALID)
    cf_error("Invalid flow route: %s", flow_validated_state_str(r));
}


CF_DECLS

%type <i32> flow_num_op flow_srcdst flow_logic_op flow_num_type_ flow_frag_val flow_neg
%type <net_ptr> net_flow4_ net_flow6_ net_flow_

CF_KEYWORDS(FLOW4, FLOW6, DST, SRC, PROTO, NEXT, HEADER, DPORT, SPORT, ICMP,
	    TYPE, CODE, TCP, FLAGS, LENGTH, DSCP, DONT_FRAGMENT, IS_FRAGMENT,
	    FIRST_FRAGMENT, LAST_FRAGMENT, FRAGMENT, LABEL, OFFSET)


CF_GRAMMAR

/* Network Flow Specification */

flow_num_op:
   TRUE		{ $$ = FLOW_OP_TRUE; }
 | '='		{ $$ = FLOW_OP_EQ;  }
 | NEQ		{ $$ = FLOW_OP_NEQ; }
 | '<'		{ $$ = FLOW_OP_LT;  }
 | LEQ		{ $$ = FLOW_OP_LEQ; }
 | '>'		{ $$ = FLOW_OP_GT;  }
 | GEQ		{ $$ = FLOW_OP_GEQ; }
 | FALSE	{ $$ = FLOW_OP_FALSE; }
 ;

flow_logic_op:
   OR		{ $$ = FLOW_OP_OR; }
 | AND		{ $$ = FLOW_OP_AND; }
 ;

flow_num_type_:
   PROTO	{ $$ = FLOW_TYPE_IP_PROTOCOL; }
 | NEXT HEADER  { $$ = FLOW_TYPE_NEXT_HEADER; }
 | PORT		{ $$ = FLOW_TYPE_PORT; }
 | DPORT	{ $$ = FLOW_TYPE_DST_PORT; }
 | SPORT	{ $$ = FLOW_TYPE_SRC_PORT; }
 | ICMP TYPE	{ $$ = FLOW_TYPE_ICMP_TYPE; }
 | ICMP CODE	{ $$ = FLOW_TYPE_ICMP_CODE; }
 | LENGTH	{ $$ = FLOW_TYPE_PACKET_LENGTH; }
 | DSCP		{ $$ = FLOW_TYPE_DSCP; }
 | LABEL	{ $$ = FLOW_TYPE_LABEL; }
 ;

flow_num_type: flow_num_type_{ flow_builder_set_type(this_flow, $1); };
flow_flag_type: TCP FLAGS    { flow_builder_set_type(this_flow, FLOW_TYPE_TCP_FLAGS); };
flow_frag_type: FRAGMENT     { flow_builder_set_type(this_flow, FLOW_TYPE_FRAGMENT); };

flow_srcdst:
   DST		{ $$ = FLOW_TYPE_DST_PREFIX; }
 | SRC		{ $$ = FLOW_TYPE_SRC_PREFIX; }
 ;

flow_num_opts:
   flow_num_op expr {
     flow_check_cf_value_length(this_flow, $2);
     flow_builder_add_op_val(this_flow, $1, $2);
   }
 | flow_num_opts flow_logic_op flow_num_op expr {
     flow_check_cf_value_length(this_flow, $4);
     flow_builder_add_op_val(this_flow, $2 | $3, $4);
   }
 | flow_num_opt_ext
 | flow_num_opts OR flow_num_opt_ext
 ;

flow_num_opt_ext_expr:
   expr {
     flow_check_cf_value_length(this_flow, $1);
     flow_builder_add_op_val(this_flow, FLOW_OP_EQ, $1);
   }
 | expr DDOT expr {
     flow_check_cf_value_length(this_flow, $1);
     flow_check_cf_value_length(this_flow, $3);
     flow_builder_add_op_val(this_flow, FLOW_OP_GEQ, $1);
     flow_builder_add_op_val(this_flow, FLOW_OP_AND | FLOW_OP_LEQ, $3);
   }
 ;

flow_num_opt_ext:
   flow_num_opt_ext_expr
 | flow_num_opt_ext ',' flow_num_opt_ext_expr
 ;

flow_bmk_opts:
   flow_neg expr '/' expr {
     flow_check_cf_bmk_values(this_flow, $1, $2, $4);
     flow_builder_add_val_mask(this_flow, $1, $2, $4);
   }
 | flow_bmk_opts flow_logic_op flow_neg expr '/' expr {
     flow_check_cf_bmk_values(this_flow, $3, $4, $6);
     flow_builder_add_val_mask(this_flow, $2 | $3, $4, $6);
   }
 | flow_bmk_opts ',' flow_neg expr '/' expr {
     flow_check_cf_bmk_values(this_flow, $3, $4, $6);
     flow_builder_add_val_mask(this_flow, 0x40 | $3, $4, $6); /* AND */
   }
 ;

flow_neg:
   /* empty */ 	{ $$ = 0x00; }
 | '!'		{ $$ = 0x02; }
 ;

flow_frag_val:
   DONT_FRAGMENT  { $$ = 1; }
 | IS_FRAGMENT	  { $$ = 2; }
 | FIRST_FRAGMENT { $$ = 4; }
 | LAST_FRAGMENT  { $$ = 8; }
 ;

flow_frag_opts:
   flow_neg flow_frag_val {
     flow_builder_add_val_mask(this_flow, 0, ($1 ? 0 : $2), $2);
   }
 | flow_frag_opts flow_logic_op flow_neg flow_frag_val {
     flow_builder_add_val_mask(this_flow, $2, ($3 ? 0 : $4), $4);
   }
 | flow_frag_opts ',' flow_neg flow_frag_val {
     flow_builder_add_val_mask(this_flow, 0x40, ($3 ? 0 : $4), $4); /* AND */
   }
 ;

flow4_item:
   flow_srcdst net_ip4 {
     flow_builder_set_type(this_flow, $1);
     flow_builder4_add_pfx(this_flow, (net_addr_ip4 *) &($2));
   }
 | flow_num_type flow_num_opts
 | flow_flag_type flow_bmk_opts
 | flow_frag_type flow_frag_opts
 ;

flow6_item:
   flow_srcdst net_ip6 {
     flow_builder_set_type(this_flow, $1);
     flow_builder6_add_pfx(this_flow, (net_addr_ip6 *) &($2), 0);
   }
 | flow_srcdst net_ip6 OFFSET NUM {
     if ($4 > $2.pxlen)
       cf_error("Prefix offset is higher than prefix length");
     flow_builder_set_type(this_flow, $1);
     flow_builder6_add_pfx(this_flow, (net_addr_ip6 *) &($2), $4);
   }
 | flow_num_type flow_num_opts
 | flow_flag_type flow_bmk_opts
 | flow_frag_type flow_frag_opts
 ;

flow4_opts:
   /* empty */
 | flow4_opts flow4_item ';'
 ;

flow6_opts:
 /* empty */
 | flow6_opts flow6_item ';'
 ;

flow_builder_init:
{
  if (this_flow == NULL)
    this_flow = flow_builder_init(config_pool);	  /* FIXME: This should be allocated from tmp in future */
  else
    flow_builder_clear(this_flow);
};

flow_builder_set_ipv4: { this_flow->ipv6 = 0; };
flow_builder_set_ipv6: { this_flow->ipv6 = 1; };

net_flow4_: FLOW4 '{' flow_builder_init flow_builder_set_ipv4 flow4_opts '}'
{
  $$ = (net_addr *) flow_builder4_finalize(this_flow, cfg_mem);
  flow4_validate_cf((net_addr_flow4 *) $$);
};

net_flow6_: FLOW6 '{' flow_builder_init flow_builder_set_ipv6 flow6_opts '}'
{
  $$ = (net_addr *) flow_builder6_finalize(this_flow, cfg_mem);
  flow6_validate_cf((net_addr_flow6 *) $$);
};

net_flow_: net_flow4_ | net_flow6_ ;


CF_CODE

CF_END

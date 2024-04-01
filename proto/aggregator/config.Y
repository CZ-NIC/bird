/*
 *	BIRD -- Aggregator configuration
 *
 *	(c) 2023       Igor Putovny <igor.putovny@nic.cz>
 *	(c) 2023       Maria Matejka <mq@ucw.cz>
 *	(c) 2023       CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/aggregator/aggregator.h"

CF_DEFINES

#define AGGREGATOR_CFG ((struct aggregator_config *) this_proto)
#define AGGR_ITEM_ALLOC ((struct aggr_item_node *) cfg_allocz(sizeof(struct aggr_item_node)))

CF_DECLS

CF_KEYWORDS(AGGREGATOR, PEER, AGGREGATE, ON, MERGE, BY)

%type <xp> aggr_item aggr_list

CF_GRAMMAR

proto: aggregator_proto ;

aggregator_proto_start: proto_start AGGREGATOR
{
  this_proto = proto_config_new(&proto_aggregator, $1);
  this_channel = AGGREGATOR_CFG->src = channel_config_new(NULL, "source", 0, this_proto);
  AGGREGATOR_CFG->dst = channel_config_new(NULL, "destination", 0, this_proto);

  AGGREGATOR_CFG->src->ra_mode = AGGREGATOR_CFG->dst->ra_mode = RA_ANY;
};

aggregator_proto_item:
   proto_item
 | channel_item_
 | PEER TABLE rtable { AGGREGATOR_CFG->dst->table = $3; }
 | AGGREGATE ON {
    if (AGGREGATOR_CFG->aggr_on)
      cf_error("Only one aggregate on clause allowed");

    cf_enter_filters();
    cf_push_block_scope(new_config);
 } aggr_list {
    int count = new_config->current_scope->slots;
    cf_pop_block_scope(new_config);
    cf_exit_filters();

    if (!AGGREGATOR_CFG->aggr_on_net)
      cf_error("aggregate on must be always include 'net'.");

   struct f_inst *rot = NULL;
   while ($4.begin)
   {
     struct f_inst *tmp = $4.begin->next;
     $4.begin->next = rot;
     rot = $4.begin;
     $4.begin = tmp;
   }

   AGGREGATOR_CFG->aggr_on_count = count;
   AGGREGATOR_CFG->aggr_on = f_linearize(rot, count);

   struct f_line *premerge = f_linearize($4.end, 0);
   premerge->args = count;
   AGGREGATOR_CFG->premerge = premerge;
 }
 | MERGE BY {
   cf_enter_filters();
   cf_push_block_scope(new_config);
   f_predefined_variable(new_config, "routes", T_ROUTES_BLOCK);
 } function_body {
   cf_pop_block_scope(new_config);
   cf_exit_filters();
   $4->args++;
   AGGREGATOR_CFG->merge_by = $4;
 }
;

aggregator_proto_opts: /* empty */ | aggregator_proto_opts aggregator_proto_item ';' ;
aggregator_proto: aggregator_proto_start proto_name '{' aggregator_proto_opts '}' ;


aggr_list:
   aggr_item
 | aggr_list ',' aggr_item {
    if ($$.begin = $3.begin)
      $$.begin->next = $1.begin;
    else
      $$.begin = $1.begin;

    if ($$.end = $3.end)
      $$.end->next = $1.end;
    else
      $$.end = $1.end;
 }
 ;

aggr_item:
   '(' term ')' {
     switch ($2->type) {
       case T_INT:
       case T_BOOL:
       case T_PAIR:
       case T_QUAD:
       case T_ENUM:
       case T_IP:
       case T_EC:
       case T_LC:
       case T_RD:
	 /* Fits, OK */
	 break;

       default:
	 cf_error("Expression evaluated to type %s unsupported by aggregator. Store this value as a custom attribute instead", f_type_name($2->type));
     }

     $$.begin = $2;
     $$.end = NULL;
     f_new_var(new_config->current_scope);
   }
  | lvalue {
    $$.begin = f_lval_getter(&$1);
    int vari = f_new_var(new_config->current_scope);

    if ($1.type == F_LVAL_SA && $1.sa.sa_code == SA_NET)
      AGGREGATOR_CFG->aggr_on_net = 1;
    if (($1.type == F_LVAL_CONSTANT) || 
	($1.type == F_LVAL_SA && $1.sa.readonly))
      $$.end = NULL;
    else
    {
      char varname[12];
      bsnprintf(varname, 12, "!aggr%d", vari);
      $$.end = f_lval_setter(&$1,
	  f_new_inst(FI_VAR_GET, cf_define_symbol(
	      new_config, cf_get_symbol(new_config, varname),
	      SYM_VARIABLE | $$.begin->type, offset, vari
	      )));
    }
  }
  ;

CF_CODE

CF_END

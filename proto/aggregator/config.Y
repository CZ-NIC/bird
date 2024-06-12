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
#include "lib/settle.h"

CF_DEFINES

#define AGGREGATOR_CFG ((struct aggregator_config *) this_proto)
#define AGGR_ITEM_ALLOC ((struct aggr_item_node *) cfg_allocz(sizeof(struct aggr_item_node)))


CF_DECLS

CF_KEYWORDS(AGGREGATOR, AGGREGATE, ON, MERGE, BY, RELOAD, AFTER)

%type <ai> aggr_item aggr_list

CF_GRAMMAR

toksym: AGGREGATOR | AGGREGATE | MERGE | BY ;

proto: aggregator_proto ;

aggregator_proto_start: proto_start AGGREGATOR
{
  this_proto = proto_config_new(&proto_aggregator, $1);
  this_channel = AGGREGATOR_CFG->src = channel_config_new(NULL, "source", 0, this_proto);
  AGGREGATOR_CFG->dst = channel_config_new(NULL, "destination", 0, this_proto);

  /*
   * Aggregation mode is set to prefix aggregation by default, in which case we want to receive
   * updates with the best routes.
   */
  AGGREGATOR_CFG->aggr_mode = PREFIX_AGGR;
  AGGREGATOR_CFG->src->ra_mode = RA_OPTIMAL;
  AGGREGATOR_CFG->dst->ra_mode = RA_ANY;

  AGGREGATOR_CFG->notify_settle_cf = (struct settle_config) {
    .min = 10 MS_,
    .max = 100 MS_,
  };
};

aggregator_proto_item:
   proto_item
 | channel_item_
 | PEER TABLE rtable { AGGREGATOR_CFG->dst->table = $3; }
 | AGGREGATE ON aggr_list {
    if (AGGREGATOR_CFG->aggr_on)
      cf_error("Only one aggregate on clause allowed");

    int count = 0;

    for (const struct aggr_item_node *item = $3; item; item = item->next) {
      log(L_WARN "type %d sacode %d", item->i.type, item->i.sa.sa_code);

      /*
       * If NET attribute is present, aggregate routes within the same net
       * and receive updates with any routes.
       */
      if (item->i.type == AGGR_ITEM_STATIC_ATTR && item->i.sa.sa_code == SA_NET) {
        AGGREGATOR_CFG->aggr_mode = NET_AGGR;
        AGGREGATOR_CFG->src->ra_mode = RA_ANY;
      }

      count++;
    }

   AGGREGATOR_CFG->aggr_on = cfg_alloc(sizeof(struct aggr_item) * count);

   int pos = 0;
   for (const struct aggr_item_node *item = $3; item; item = item->next) {
     if (item->i.type == AGGR_ITEM_DYNAMIC_ATTR)
       AGGREGATOR_CFG->aggr_on_da_count++;

     AGGREGATOR_CFG->aggr_on[pos++] = item->i;
   }

   AGGREGATOR_CFG->aggr_on_count = pos;
 }
 | MERGE BY {
   cf_push_block_scope(new_config);
   cf_create_symbol(new_config, "routes", SYM_VARIABLE | T_ROUTES_BLOCK, offset, f_new_var(sym_->scope));
 } function_body {
   cf_pop_block_scope(new_config);
   $4->args++;
   AGGREGATOR_CFG->merge_by = $4;
 }
 | RELOAD AFTER settle { AGGREGATOR_CFG->notify_settle_cf = $3; }
;

aggregator_proto_opts: /* empty */ | aggregator_proto_opts aggregator_proto_item ';' ;
aggregator_proto: aggregator_proto_start proto_name '{' aggregator_proto_opts '}' {
  if (AGGREGATOR_CFG->src->table->addr_type != AGGREGATOR_CFG->dst->table->addr_type)
    cf_error("Both rtables in aggregator must have the same network type");

  if (PREFIX_AGGR == AGGREGATOR_CFG->aggr_mode)
    if (AGGREGATOR_CFG->src->table->addr_type != NET_IP4 && AGGREGATOR_CFG->src->table->addr_type != NET_IP6)
      cf_error("Trie aggregation is available only for IP4 or IPv6 networks");
};


aggr_list:
   aggr_item
 | aggr_list ',' aggr_item {
       if ($3 == NULL) {
         $$ = $1;
       } else {
         $$ = $3;
         $$->next = $1;
       }
   }
 ;

aggr_item:
   '(' term ')' {
       $$ = AGGR_ITEM_ALLOC;
       $$->i.type = AGGR_ITEM_TERM;
       $$->i.line = f_linearize($2, 1);
    }
  | CF_SYM_KNOWN {
      switch ($1->class) {
        case SYM_ATTRIBUTE:
          $$ = AGGR_ITEM_ALLOC;
          $$->i.type = AGGR_ITEM_DYNAMIC_ATTR;
          $$->i.da = *$1->attribute;
          break;
        case SYM_CONSTANT_RANGE:
          $$ = NULL;
          break;
        default:
          cf_error("Can't aggregate on symbol type %s.", cf_symbol_class_name($1));
      }
    }
  | dynamic_attr {
      $$ = AGGR_ITEM_ALLOC;
      $$->i.type = AGGR_ITEM_DYNAMIC_ATTR;
      $$->i.da = $1;
    }
  | static_attr {
      $$ = AGGR_ITEM_ALLOC;
      $$->i.type = AGGR_ITEM_STATIC_ATTR;
      $$->i.sa = $1;
    }
  ;

/* Settle timer configuration */
settle:
   expr_us expr_us {
     if ($1 > $2)
       cf_error("Minimum settle time %t is bigger than maximum settle time %t", $1, $2);
     $$.min = $1 MS_;
     $$.max = $2 MS_;
   }
 ;

CF_CODE

CF_END

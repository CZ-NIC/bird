/*
 *	BIRD -- Router Advertisement Configuration
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/bfd/bfd.h"

CF_DEFINES

#define BFD_CFG ((struct bfd_config *) this_proto)
#define BFD_SESSION this_bfd_session
#define BFD_NEIGHBOR this_bfd_neighbor

static struct bfd_session_config *this_bfd_session;
static struct bfd_neighbor *this_bfd_neighbor;


CF_DECLS

CF_KEYWORDS(BFD, MIN, IDLE, RX, TX, INTERVAL, MULTIPLIER, MULTIHOP, PASSIVE,
	NEIGHBOR, DEV)

%type <iface> bfd_neigh_iface
%type <a> bfd_neigh_local

CF_GRAMMAR

CF_ADDTO(proto, bfd_proto)

bfd_proto_start: proto_start BFD
{
  this_proto = proto_config_new(&proto_bfd, sizeof(struct bfd_config), $1);
  init_list(&BFD_CFG->neigh_list);
};

bfd_proto_item:
   proto_item
 | bfd_neighbor
 ;

bfd_proto_opts:
   /* empty */
 | bfd_proto_opts bfd_proto_item ';'
 ;

bfd_proto:
   bfd_proto_start proto_name '{' bfd_proto_opts '}';


bfd_session_start:
{
  this_bfd_session = cfg_allocz(sizeof(struct bfd_session_config));

  BFD_SESSION->min_rx_int = BFD_DEFAULT_MIN_RX_INT;
  BFD_SESSION->min_tx_int = BFD_DEFAULT_MIN_TX_INT;
  BFD_SESSION->idle_tx_int = BFD_DEFAULT_IDLE_TX_INT;
  BFD_SESSION->multiplier = BFD_DEFAULT_MULTIPLIER;
};

bfd_session_item:
   INTERVAL expr_us { BFD_SESSION->min_rx_int = BFD_SESSION->min_tx_int = $2; }
 | MIN RX INTERVAL expr_us { BFD_SESSION->min_rx_int = $4; }
 | MIN TX INTERVAL expr_us { BFD_SESSION->min_tx_int = $4; }
 | IDLE TX INTERVAL expr_us { BFD_SESSION->idle_tx_int = $4; }
 | MULTIPLIER expr { BFD_SESSION->multiplier = $2; }
 | MULTIHOP bool { BFD_SESSION->multihop = $2; }
 | PASSIVE bool { BFD_SESSION->passive = $2; }
 ;

bfd_session_opts:
   /* empty */
 | bfd_session_opts bfd_session_item ';'
 ;

bfd_session_opt_list:
   /* empty */
 | '{' bfd_session_opts '}'
 ;

bfd_session: 
   bfd_session_start bfd_session_opt_list;


bfd_neigh_iface:
   /* empty */ { $$ = NULL; }
 | '%' SYM { $$ = if_get_by_name($2->name); }
 | DEV TEXT { $$ = if_get_by_name($2); }
 ;

bfd_neigh_local:
   /* empty */ { $$ = IPA_NONE; }
 | LOCAL ipa { $$ = $2; }
 ;

bfd_neighbor: NEIGHBOR ipa bfd_neigh_iface bfd_neigh_local bfd_session
{
  this_bfd_neighbor = cfg_allocz(sizeof(struct bfd_neighbor));
  add_tail(&BFD_CFG->neigh_list, NODE this_bfd_neighbor);

  BFD_NEIGHBOR->addr = $2;
  BFD_NEIGHBOR->local = $4;
  BFD_NEIGHBOR->iface = $3;
  BFD_NEIGHBOR->opts = BFD_SESSION;
};


CF_CLI(SHOW BFD SESSIONS, optsym, [<name>], [[Show information about BFD sessions]])
{ bfd_show_sessions(proto_get_named($4, &proto_bfd)); };

CF_CODE

CF_END

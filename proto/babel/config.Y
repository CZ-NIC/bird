/*
 *	BIRD -- Babel Configuration
 *
 *	Copyright (c) 2015-2016 Toke Hoiland-Jorgensen
 * 	(c) 2016--2017 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2016--2017 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */



CF_HDR

#include "proto/babel/babel.h"
#include "nest/iface.h"

CF_DEFINES

#define BABEL_CFG ((struct babel_config *) this_proto)
#define BABEL_IFACE ((struct babel_iface_config *) this_ipatt)

CF_DECLS

CF_KEYWORDS(BABEL, INTERFACE, METRIC, RXCOST, HELLO, UPDATE, INTERVAL, PORT,
	TYPE, WIRED, WIRELESS, RX, TX, BUFFER, PRIORITY, LENGTH, CHECK, LINK,
	NEXT, HOP, IPV4, IPV6, BABEL_METRIC, SHOW, INTERFACES, NEIGHBORS,
	ENTRIES, RANDOMIZE, ROUTER, ID, AUTHENTICATION, NONE, MAC, PERMISSIVE,
	EXTENDED, TUNNEL, RTT, MIN, MAX, DECAY, SEND, TIMESTAMPS)

CF_GRAMMAR

proto: babel_proto ;

babel_proto_start: proto_start BABEL
{
  this_proto = proto_config_new(&proto_babel, $1);
  init_list(&BABEL_CFG->iface_list);
  BABEL_CFG->hold_time = 1 S_;
};

babel_proto_item:
   proto_item
 | proto_channel
 | INTERFACE babel_iface
 | RANDOMIZE ROUTER ID bool { BABEL_CFG->randomize_router_id = $4; }
 ;

babel_proto_opts:
   /* empty */
 | babel_proto_opts babel_proto_item ';'
 ;

babel_proto:
   babel_proto_start proto_name '{' babel_proto_opts '}';


babel_iface_start:
{
  this_ipatt = cfg_allocz(sizeof(struct babel_iface_config));
  add_tail(&BABEL_CFG->iface_list, NODE this_ipatt);
  init_list(&this_ipatt->ipn_list);
  reset_passwords();

  BABEL_IFACE->port = BABEL_PORT;
  BABEL_IFACE->type = BABEL_IFACE_TYPE_WIRED;
  BABEL_IFACE->limit = BABEL_HELLO_LIMIT;
  BABEL_IFACE->tx_tos = IP_PREC_INTERNET_CONTROL;
  BABEL_IFACE->tx_priority = sk_priority_control;
  BABEL_IFACE->rtt_min = BABEL_RTT_MIN;
  BABEL_IFACE->rtt_max = BABEL_RTT_MAX;
  BABEL_IFACE->rtt_decay = BABEL_RTT_DECAY;
  BABEL_IFACE->rtt_send = 1;
  BABEL_IFACE->check_link = 1;
  BABEL_IFACE->ext_next_hop = 1;
};


babel_iface_finish:
{
  if (BABEL_IFACE->type == BABEL_IFACE_TYPE_WIRELESS)
  {
    if (!BABEL_IFACE->hello_interval)
      BABEL_IFACE->hello_interval = BABEL_HELLO_INTERVAL_WIRELESS;
    if (!BABEL_IFACE->rxcost)
      BABEL_IFACE->rxcost = BABEL_RXCOST_WIRELESS;
  }
  else
  {
    if (!BABEL_IFACE->hello_interval)
      BABEL_IFACE->hello_interval = BABEL_HELLO_INTERVAL_WIRED;
    if (!BABEL_IFACE->rxcost)
      BABEL_IFACE->rxcost = BABEL_RXCOST_WIRED;
    if (BABEL_IFACE->type == BABEL_IFACE_TYPE_TUNNEL && !BABEL_IFACE->rtt_cost)
      BABEL_IFACE->rtt_cost = BABEL_RXCOST_RTT;
  }

  if (BABEL_IFACE->rtt_cost && !BABEL_IFACE->rtt_send)
    cf_error("Can't set RTT cost when sending timestamps is disabled");

  if (BABEL_IFACE->rtt_min >= BABEL_IFACE->rtt_max)
    cf_error("Min RTT must be smaller than max RTT");

  /* Make sure we do not overflow the 16-bit centisec fields */
  if (!BABEL_IFACE->update_interval)
    BABEL_IFACE->update_interval = MIN_(BABEL_IFACE->hello_interval*BABEL_UPDATE_INTERVAL_FACTOR, BABEL_MAX_INTERVAL);
  BABEL_IFACE->ihu_interval = MIN_(BABEL_IFACE->hello_interval*BABEL_IHU_INTERVAL_FACTOR, BABEL_MAX_INTERVAL);

  BABEL_CFG->hold_time = MAX_(BABEL_CFG->hold_time, BABEL_IFACE->update_interval*BABEL_HOLD_TIME_FACTOR);

  BABEL_IFACE->passwords = get_passwords();

  if (!BABEL_IFACE->auth_type != !BABEL_IFACE->passwords)
    cf_error("Authentication and password options should be used together");

  if (BABEL_IFACE->passwords)
  {
    struct password_item *pass;
    uint len = 0, i = 0;

    WALK_LIST(pass, *BABEL_IFACE->passwords)
    {
      /* Set default crypto algorithm (HMAC-SHA256) */
      if (!pass->alg)
	pass->alg = ALG_HMAC_SHA256;

      if (!((pass->alg & ALG_HMAC) ||
	    (pass->alg == ALG_BLAKE2S_128) ||
	    (pass->alg == ALG_BLAKE2S_256) ||
	    (pass->alg == ALG_BLAKE2B_256) ||
	    (pass->alg == ALG_BLAKE2B_512)))
	cf_error("Only HMAC and Blake2 algorithms are supported");

      len += mac_type_length(pass->alg);
      i++;
    }

    BABEL_IFACE->mac_num_keys = i;
    BABEL_IFACE->mac_total_len = len;
  }

};


babel_iface_item:
 | PORT expr { BABEL_IFACE->port = $2; if (($2<1) || ($2>65535)) cf_error("Invalid port number"); }
 | RXCOST expr { BABEL_IFACE->rxcost = $2; if (($2<1) || ($2>65535)) cf_error("Invalid rxcost"); }
 | LIMIT expr { BABEL_IFACE->limit = $2; if (($2<1) || ($2>16)) cf_error("Limit must be in range 1-16"); }
 | TYPE WIRED { BABEL_IFACE->type = BABEL_IFACE_TYPE_WIRED; }
 | TYPE WIRELESS { BABEL_IFACE->type = BABEL_IFACE_TYPE_WIRELESS; }
 | TYPE TUNNEL { BABEL_IFACE->type = BABEL_IFACE_TYPE_TUNNEL; }
 | HELLO INTERVAL expr_us { BABEL_IFACE->hello_interval = $3; if (($3<BABEL_MIN_INTERVAL) || ($3>BABEL_MAX_INTERVAL)) cf_error("Hello interval must be in range 10 ms - 655 s"); }
 | UPDATE INTERVAL expr_us { BABEL_IFACE->update_interval = $3; if (($3<BABEL_MIN_INTERVAL) || ($3>BABEL_MAX_INTERVAL)) cf_error("Update interval must be in range 10 ms - 655 s"); }
 | RX BUFFER expr { BABEL_IFACE->rx_buffer = $3; if (($3<256) || ($3>65535)) cf_error("RX buffer must be in range 256-65535"); }
 | TX LENGTH expr { BABEL_IFACE->tx_length = $3; if (($3<256) || ($3>65535)) cf_error("TX length must be in range 256-65535"); }
 | TX tos { BABEL_IFACE->tx_tos = $2; }
 | TX PRIORITY expr { BABEL_IFACE->tx_priority = $3; }
 | CHECK LINK bool { BABEL_IFACE->check_link = $3; }
 | NEXT HOP IPV4 ipa { BABEL_IFACE->next_hop_ip4 = $4; if (!ipa_is_ip4($4)) cf_error("Must be an IPv4 address"); }
 | NEXT HOP IPV6 ipa { BABEL_IFACE->next_hop_ip6 = $4; if (!ipa_is_ip6($4)) cf_error("Must be an IPv6 address"); }
 | EXTENDED NEXT HOP bool { BABEL_IFACE->ext_next_hop = $4; }
 | AUTHENTICATION NONE { BABEL_IFACE->auth_type = BABEL_AUTH_NONE; }
 | AUTHENTICATION MAC { BABEL_IFACE->auth_type = BABEL_AUTH_MAC; BABEL_IFACE->auth_permissive = 0; }
 | AUTHENTICATION MAC PERMISSIVE { BABEL_IFACE->auth_type = BABEL_AUTH_MAC; BABEL_IFACE->auth_permissive = 1; }
 | RTT MIN expr_us { BABEL_IFACE->rtt_min = $3; }
 | RTT MAX expr_us { BABEL_IFACE->rtt_max = $3; }
 | RTT COST expr { BABEL_IFACE->rtt_cost = $3; if ($3 >= BABEL_INFINITY) cf_error("RTT cost must be < 65535"); }
 | RTT DECAY expr { BABEL_IFACE->rtt_decay = $3; if (($3 < 1) || ($3 > 256)) cf_error("RTT decay must be between 1-256"); }
 | SEND TIMESTAMPS bool { BABEL_IFACE->rtt_send = $3; }
 | password_list
 ;

babel_iface_opts:
   /* empty */
 | babel_iface_opts babel_iface_item ';'
 ;

babel_iface_opt_list:
   /* empty */
 | '{' babel_iface_opts '}'
 ;


babel_iface:
  babel_iface_start iface_patt_list_nopx babel_iface_opt_list babel_iface_finish;

dynamic_attr: BABEL_METRIC { $$ = f_new_dynamic_attr(EAF_TYPE_INT, T_INT, EA_BABEL_METRIC); } ;

CF_CLI_HELP(SHOW BABEL, ..., [[Show information about Babel protocol]]);

CF_CLI(SHOW BABEL INTERFACES, optproto opttext, [<name>] [\"<interface>\"], [[Show information about Babel interfaces]])
{ PROTO_WALK_CMD($4, &proto_babel, p) babel_show_interfaces(p, $5); };

CF_CLI(SHOW BABEL NEIGHBORS, optproto opttext, [<name>] [\"<interface>\"], [[Show information about Babel neighbors]])
{ PROTO_WALK_CMD($4, &proto_babel, p) babel_show_neighbors(p, $5); };

CF_CLI(SHOW BABEL ENTRIES, optproto opttext, [<name>], [[Show information about Babel prefix entries]])
{ PROTO_WALK_CMD($4, &proto_babel, p) babel_show_entries(p); };

CF_CLI(SHOW BABEL ROUTES, optproto opttext, [<name>], [[Show information about Babel route entries]])
{ PROTO_WALK_CMD($4, &proto_babel, p)  babel_show_routes(p); };

CF_CODE

CF_END

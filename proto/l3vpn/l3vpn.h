/*
 *	BIRD -- Layer3 VPN Protocol Configuration
 *
 *	(c) 2011-2013 Yandex, LLC
 *      Author: Alexander V. Chernikov <melifaro@yandex-team.ru>
 *
 *	(c) 2016 CZ.NIC, z.s.p.o.
 *      Updated by Jan Moskyto Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_L3VPN_H_
#define _BIRD_L3VPN_H_

#include "nest/protocol.h"
#include "nest/route.h"

struct l3vpn_config {
  struct proto_config c;
  struct channel_config *vpn;
  struct channel_config *ip;
  struct channel_config *mpls;
  u64 rd;				/* VPN route distinguisher */
};

struct l3vpn_proto {
  struct proto p;
  struct channel *vpn;
  struct channel *ip;
  struct channel *mpls;
  struct fib iptompls;			/* FIB to lookup IP->MPLS mappings */

  u64 rd;				/* VPN route distinguisher */
};

extern struct protocol proto_l3vpn;

struct l3vpn_ip_to_mpls {
  ea_list el;
  eattr ea;
  struct adata ad;
  struct fib_node n;
};

#define L3VPN_LABEL_AUTO  (1<<20)

#endif

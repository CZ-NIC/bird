/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SNMP_H_
#define _BIRD_SNMP_H_

#include "lib/ip.h"
#include "lib/socket.h"
#include "lib/timer.h"
#include "nest/bird.h"
#include "nest/protocol.h"
#include "filter/data.h"
#include "proto/bgp/bgp.h"


#define SNMP_UNDEFINED	0
#define SNMP_BGP	1
#define SNMP_OSPF	2
#define SNMP_INVALID  255

#define SNMP_PORT 705

#define SNMP_RX_BUFFER_SIZE 8192
#define SNMP_TX_BUFFER_SIZE 8192

enum snmp_proto_state {
  SNMP_INIT = 1,
  SNMP_LOCKED,
  SNMP_OPEN,
  SNMP_REGISTER,
  SNMP_CONN,
  SNMP_STOP,
  SNMP_DOWN,
};

/* hash table macros */
#define SNMP_HASH_KEY(n)  n->peer_ip
#define SNMP_HASH_NEXT(n) n->next
#define SNMP_HASH_EQ(ip1, ip2) ipa_equal(ip1, ip2)
#define SNMP_HASH_FN(ip)  ipa_hash(ip)

#define SNMP_HASH_LESS4(ip1, ip2) ip4_less(ip1, ip2)
#define SNMP_HASH_LESS6(ip1, ip2) ip6_less(ip1, ip2)

/* hash table only store ip4 addresses */
#define SNMP_HASH_LESS(ip1, ip2) SNMP_HASH_LESS4(ip1,ip2)

/* context hash table macros */
#define SNMP_H_CONTEXT_KEY(c)		c->context
#define SNMP_H_CONTEXT_NEXT(c)		c->next
#define SNMP_H_CONTEXT_EQ(s1,s2)	strcmp(s1,s2)
#define SNMP_H_CONTEXT_FN(s)		mem_hash(s, strlen(s))

struct snmp_bond {
  node n;
  struct proto_config *proto;
  u8 type;
  const char *context;
};

struct snmp_config {
  struct proto_config cf;
  ip_addr local_ip;
  ip_addr remote_ip;
  u16 local_port;
  u16 remote_port;

  ip_addr bgp_local_id;	  /* BGP4-MIB related fields */
  u32 bgp_local_as;

  u8 timeout;
  u8 priority;
  //struct iface *iface;
  u32 bonds;
  uint contexts; /* Number of all conetexts including the default */
  const char *description;
  list bgp_entries;
  // TODO add support for subagent oid identification
};

#define SNMP_BGP_P_REGISTERING	0x01
#define SNMP_BGP_P_REGISTERED	0x02

struct snmp_bgp_peer {
  const struct bgp_config *config;
  ip_addr peer_ip;
  uint context_id;
  u8 flags;
  struct snmp_bgp_peer *next;
};

struct snmp_register {
  node n;
  u8 mib_class;
  u32 session_id;
  u32 transaction_id;
  u32 packet_id;
  struct oid *oid;
};

struct snmp_registered_oid {
  node n;
  struct oid *oid;
};

struct snmp_context {
  const char *context; /* string name */
  //uint length; /* strlen() of name */
  uint context_id;
  u8 flags;
  struct snmp_context *next;
};

struct snmp_proto {
  struct proto p;
  struct object_lock *lock;
  pool *pool;			  /* a shortcut to the procotol mem. pool */
  linpool *lp;			  /* linpool for bgp_trie nodes */

  ip_addr local_ip;
  ip_addr remote_ip;
  u16 local_port;
  u16 remote_port;

  ip_addr bgp_local_id;		  /* BGP4-MIB related fields */
  u32 bgp_local_as;

  sock *sock;
  u8 timeout;			  /* timeout is part of MIB registration. It
				    specifies how long should the master
				    agent wait for request responses. */

  u32 session_id;
  u32 transaction_id;
  u32 packet_id;

  uint register_to_ack;		    /* counter of pending responses to register-pdu */
  list register_queue;		    /* list containing snmp_register records */
  list bgp_registered;		    /* list of currently registered bgp oids
				     * (struct snmp_registered_oid) */

  // map
  struct f_trie *bgp_trie;
  HASH(struct snmp_bgp_peer) bgp_hash;
  HASH(struct snmp_context) context_hash;
  struct snmp_context **context_id_map;
  uint context_id_map_size;
  uint context_max;
  struct tbf rl_gen;

  timer *ping_timer;

  uint startup_delay;
  timer *startup_timer;
  u8 state;

  uint to_send;
  uint errs;
};

//void snmp_tx(sock *sk);
void snmp_startup(struct snmp_proto *p);
void snmp_connected(sock *sk);
void snmp_startup_timeout(timer *tm);
void snmp_reconnect(timer *tm);


#endif

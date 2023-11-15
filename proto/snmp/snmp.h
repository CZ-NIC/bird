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
  SNMP_DOWN = 0,
  SNMP_INIT = 1,
  SNMP_LOCKED,
  SNMP_OPEN,
  SNMP_REGISTER,
  SNMP_CONN,
  SNMP_STOP,
  SNMP_RESET,
};

struct snmp_bond {
  node n;
  struct proto_config *config;
  u8 type;
};

struct snmp_config {
  struct proto_config cf;
  ip_addr local_ip;
  ip_addr remote_ip;
  u16 local_port;
  u16 remote_port;

  ip_addr bgp_local_id;	  /* BGP4-MIB related fields */
  u32 bgp_local_as;

  btime timeout;
  btime startup_delay;
  u8 priority;
  //struct iface *iface;
  u32 bonds;
  const char *description;
  list bgp_entries;
  // TODO add support for subagent oid identification
};

#define SNMP_BGP_P_REGISTERING	0x01
#define SNMP_BGP_P_REGISTERED	0x02

struct snmp_bgp_peer {
  const struct bgp_proto *bgp_proto;
  ip4_addr peer_ip;		      /* used as hash key */
  struct snmp_bgp_peer *next;
};

struct snmp_registration {
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
  void *last_header;		  /* points to partial PDU header */
  btime timeout;		  /* timeout is part of MIB registration. It
				    specifies how long should the master
				    agent wait for request responses. */

  u32 session_id;
  u32 transaction_id;
  u32 packet_id;

  uint registrations_to_ack;		    /* counter of pending responses to register-pdu */
  list registration_queue;		    /* list containing snmp_register records */
  list bgp_registered;		    /* list of currently registered bgp oids
				     * (struct snmp_registered_oid) */

  // map
  struct f_trie *bgp_trie;
  HASH(struct snmp_bgp_peer) bgp_hash;
  struct tbf rl_gen;

  timer *ping_timer;
  btime startup_delay;
  timer *startup_timer;
  u8 state;
};

//void snmp_tx(sock *sk);
void snmp_startup(struct snmp_proto *p);
void snmp_connected(sock *sk);
void snmp_startup_timeout(timer *tm);
void snmp_reconnect(timer *tm);
void snmp_sock_disconnect(struct snmp_proto *p, int reconnect);
void snmp_set_state(struct snmp_proto *p, enum snmp_proto_state state);


#endif

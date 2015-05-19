/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _MRTDUMP_H_
#define _MRTDUMP_H_

#include "nest/protocol.h"

/* MRTDump values */
#define MRTDUMP_HDR_LENGTH	12
#define PEER_TYPE_AS_32BIT	0b00000010 /* MRT TABLE_DUMP_V2: PEER_INDEX_TABLE: Peer Type: Use 32bit ASN */
#define PEER_TYPE_IPV6		0b00000001 /* MRT TABLE_DUMP_V2: PEER_INDEX_TABLE: Peer Type: Use IPv6 IP Address */

/* MRT Types */
enum mrt_type
{
  TABLE_DUMP_V2		= 13,
  BGP4MP		= 16,
};

/* MRT TABLE_DUMP_V2 Sub-Types */
enum table_dump_v2_type
{
  PEER_INDEX_TABLE	= 1,
  RIB_IPV4_UNICAST	= 2,
  RIB_IPV4_MULTICAST	= 3,
  RIB_IPV6_UNICAST	= 4,
  RIB_IPV6_MULTICAST 	= 5,
  RIB_GENERIC		= 6,
};

/* MRT BGP4MP Sub-Types */
enum bgp4mp_subtype
{
  BGP4MP_MESSAGE		= 1,
  BGP4MP_MESSAGE_AS4		= 4,
  BGP4MP_STATE_CHANGE_AS4	= 5,
};

struct mrt_msg
{
  byte  *msg;			/* Buffer with final formatted data */
  size_t msg_length;		/* Size of used buffer */
  size_t msg_capacity;		/* Number of allocated bytes in msg */
#define MRT_MSG_DEFAULT_CAPACITY 64 /* in bytes */
  pool *mem_pool;
};

/* TABLE_DUMP_V2 -> PEER_INDEX_TABLE */
struct mrt_peer_index_table
{
  struct mrt_msg *msg;
  u16 peer_count;
  u16 name_length;
};

/* TABLE_DUMP_V2 -> RIB_IPV4_UNICAST or RIB_IPV6_UNICAST */
struct mrt_rib_table
{
  struct mrt_msg *msg;
  enum table_dump_v2_type type;	/* RIB_IPV4_UNICAST or RIB_IPV6_UNICAST */
  u16 entry_count;		/* Number of RIB Entries */
  struct bgp_proto *bgp_proto;
};

/* TABLE_DUMP_V2 -> RIB Entry */
struct mrt_rib_entry
{
  u16 peer_index;
  u32 originated_time;
  u16 attributes_length;
  byte *attributes;
};

void mrt_msg_init(struct mrt_msg *msg, pool *mem_pool);
void mrt_msg_free(struct mrt_msg *msg);
void mrt_peer_index_table_init(struct mrt_peer_index_table *pit_msg, u32 collector_bgp_id, const char *name);
void mrt_peer_index_table_add_peer(struct mrt_peer_index_table *pit_msg, u32 peer_bgp_id, ip_addr *peer_ip_addr, u32 peer_as);
void mrt_rib_table_init(struct mrt_rib_table *rt_msg, u32 sequence_number, u8 prefix_length, ip_addr *prefix);
void mrt_rib_table_add_entry(struct mrt_rib_table *rt_msg, const struct mrt_rib_entry *rib);

/* implemented in sysdep */
void mrt_dump_message(const struct proto *p, u16 type, u16 subtype, byte *buf, u32 len);

#endif	/* _MRTDUMP_H_ */

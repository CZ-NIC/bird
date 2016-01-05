/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MRTDUMP_H_
#define _BIRD_MRTDUMP_H_

#include <limits.h>

#include "nest/protocol.h"
#include "lib/lists.h"
#include "nest/route.h"
#include "lib/event.h"

#define MRT_HDR_LENGTH		12	/* MRT Timestamp + MRT Type + MRT Subtype + MRT Load Length */
#define MRT_PEER_TYPE_32BIT_ASN	2	/* MRT Table Dump: Peer Index Table: Peer Type: Use 32bit ASN */
#define MRT_PEER_TYPE_IPV6	1	/* MRT Table Dump: Peer Index Table: Peer Type: Use IPv6 IP Address */

#ifdef PATH_MAX
#define BIRD_PATH_MAX PATH_MAX
#else
#define BIRD_PATH_MAX 4096
#endif

/* MRT Types */
#define MRT_TABLE_DUMP_V2 	13
#define MRT_BGP4MP		16

/* MRT Table Dump v2 Subtypes */
#define MRT_PEER_INDEX_TABLE	1
#define MRT_RIB_IPV4_UNICAST	2
#define MRT_RIB_IPV4_MULTICAST	3
#define MRT_RIB_IPV6_UNICAST	4
#define MRT_RIB_IPV6_MULTICAST 	5
#define MRT_RIB_GENERIC		6
#define MRT_RIB_IPV4_UNICAST_ADDPATH	8	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_RIB_IPV4_MULTICAST_ADDPATH	9	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_RIB_IPV6_UNICAST_ADDPATH	10	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_RIB_IPV6_MULTICAST_ADDPATH 	11	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_RIB_GENERIC_ADDPATH		12	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_RIB_NO_ADDPATH	0
#define MRT_RIB_ADDPATH		1


/* MRT BGP4MP Subtypes */
#define MRT_BGP4MP_MESSAGE	1
#define MRT_BGP4MP_MESSAGE_AS4	4
#define MRT_BGP4MP_MESSAGE_ADDPATH 	8	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_BGP4MP_MESSAGE_AS4_ADDPATH 	9	/* Experimental draft-petrie-grow-mrt-add-paths */
#define MRT_BGP4MP_STATE_CHANGE_AS4 	5

struct mrt_buffer
{
  byte  *msg;			/* Buffer with final formatted data */
  size_t msg_length;		/* Size of used buffer */
  size_t msg_capacity;		/* Number of allocated bytes in msg */
#define MRT_BUFFER_DEFAULT_CAPACITY 64 /* Size in bytes */
};

struct mrt_peer_index_table
{
  struct mrt_buffer msg;
  u16 peer_count;		/* Datatype u16 should fit with the size 16bit in MRT packet */
  u32 peer_count_offset;
};

struct mrt_rib_table
{
  struct mrt_buffer msg;
  int subtype; 			/* RIB_IPV4_UNICAST or RIB_IPV6_UNICAST */
  u16 entry_count;		/* Number of RIB Entries */
  u32 entry_count_offset;	/* Offset in msg->msg[?] to position where start the entries count */
};

struct mrt_rib_entry
{
  u16 peer_index;
  u32 originated_time;
  u32 path_id;			/* draft-petrie-grow-mrt-add-paths */
  u16 attributes_length;
  byte *attributes;		/* encoded BGP attributes */
};

struct mrt_table_dump_ctx {
  struct rtable *rtable;
  struct fib_iterator fit;
  struct mrt_rib_table rib_table;
  u32 rib_sequence_number;
  struct rfile *rfile;		/* tracking for mrt table dump file */
  char *file_path;		/* full path for mrt table dump file */
  byte state;
#define MRT_STATE_RUNNING	0
#define MRT_STATE_COMPLETED	1
  event *step;
  struct mrt_table_individual_config config; /* Own special configuration of MRT */
};

void mrt_buffer_alloc(struct mrt_buffer *buf);
void mrt_buffer_free(struct mrt_buffer *buf);

void mrt_peer_index_table_header(struct mrt_peer_index_table *state, u32 collector_bgp_id, const char *name);
void mrt_peer_index_table_add_peer(struct mrt_peer_index_table *state, u32 peer_bgp_id, u32 peer_as, ip_addr peer_ip_addr);
void mrt_peer_index_table_dump(struct mrt_peer_index_table *state, int file_descriptor);

void mrt_rib_table_alloc(struct mrt_rib_table *state);
void mrt_rib_table_header(struct mrt_rib_table *state, u32 sequence_number, u8 prefix_length, ip_addr prefix, uint is_addpath);
void mrt_rib_table_add_entry(struct mrt_rib_table *state, const struct mrt_rib_entry *entry);

/* implemented in sysdep */
void mrt_dump_message_proto(struct proto *p, u16 type, u16 subtype, byte *buf, u32 len);
void mrt_dump_message(int file_descriptor, u16 type, u16 subtype, byte *buf, u32 len);

#endif	/* _BIRD_MRTDUMP_H_ */

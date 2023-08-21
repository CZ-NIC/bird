/*
 *	BIRD -- The BGP Monitoring Protocol (BMP)
 *
 *	(c) 2020 Akamai Technologies, Inc. (Pawel Maslanka, pmaslank@akamai.com)
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: BGP Monitoring Protocol (BMP)
 *
 * Supported standards:
 * o RFC 7854 - BMP standard
 *
 * TODO:
 * - Support Peer Distinguisher ID in Per-Peer Header
 * - Support peer type as RD Instance in Peer Type field of Per-Peer Header.
 *   Currently, there are supported Global and Local Instance Peer types
 * - Support corresponding FSM event code during send PEER DOWN NOTIFICATION
 * - Support DE_CONFIGURED PEER DOWN REASON code in PEER DOWN NOTIFICATION message
 * - If connection with BMP collector will lost then we don't establish connection again
 * - Set Peer Type by its a global and local-scope IP address
 *
 * The BMP session is managed by a simple state machine with three states: Idle
 * (!started, !sk), Connect (!started, sk active), and Established (started). It
 * has three events: connect successful (Connect -> Established), socket error
 * (any -> Idle), and connect timeout (Idle/Connect -> Connect, resetting the
 * TCP socket).
 */

#include "proto/bmp/bmp.h"
#include "proto/bmp/buffer.h"
#include "proto/bmp/map.h"

#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <limits.h>

#include "nest/cli.h"
#include "filter/filter.h"
#include "proto/bgp/bgp.h"
#include "sysdep/unix/unix.h"
#include "lib/event.h"
#include "lib/ip.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/unaligned.h"
#include "nest/iface.h"
#include "nest/route.h"

// List of BMP instances
static list STATIC_LIST_INIT(bmp_proto_list);

#define HASH_PEER_KEY(n)		n->bgp
#define HASH_PEER_NEXT(n)		n->next
#define HASH_PEER_EQ(b1,b2)		b1 == b2
#define HASH_PEER_FN(b)			ptr_hash(b)

#define BMP_STREAM_KEY_POLICY		0x100

#define HASH_STREAM_KEY(n)		n->bgp, n->key
#define HASH_STREAM_NEXT(n)		n->next
#define HASH_STREAM_EQ(b1,k1,b2,k2)	b1 == b2 && k1 == k2
#define HASH_STREAM_FN(b,k)		ptr_hash(b) ^ u32_hash(k)

#define HASH_TABLE_KEY(n)		n->table
#define HASH_TABLE_NEXT(n)		n->next
#define HASH_TABLE_EQ(t1,t2)		t1 == t2
#define HASH_TABLE_FN(t)		ptr_hash(t)

/* BMP Common Header [RFC 7854 - Section 4.1] */
enum bmp_version {
  BMP_VER_UNUSED = 0, // Version 0 is reserved and MUST NOT be sent
  BMP_VERSION_1 = 1,  // Version 1 was used by draft version of RFC 7854
  BMP_VERSION_2 = 2,  // Version 2 was used by draft version of RFC 7854
  BMP_VERSION_3 = 3   // Version 3 is used by all messages defined in RFC 7854
};

enum bmp_message_type {
  BMP_ROUTE_MONITOR = 0,   // Route Monitoring
  BMP_STATS_REPORT = 1,    // Statistics Report
  BMP_PEER_DOWN_NOTIF = 2, // Peer Down Notification
  BMP_PEER_UP_NOTIF = 3,   // Peer Up Notification
  BMP_INIT_MSG = 4,        // Initiation Message
  BMP_TERM_MSG = 5,        // Termination Message
  BMP_ROUTE_MIRROR_MSG = 6 // Route Mirroring Message
};

// Total size of Common Header
#define BMP_COMMON_HDR_SIZE 6
// Defines size of padding when IPv4 address is going to be put into field
// which can accept also IPv6 address
#define BMP_PADDING_IP4_ADDR_SIZE 12

/* BMP Per-Peer Header [RFC 7854 - Section 4.2] */
// Total size of Per-Peer Header
#define BMP_PER_PEER_HDR_SIZE 42

enum bmp_peer_type {
  BMP_PEER_TYPE_GLOBAL_INSTANCE = 0,
  BMP_PEER_TYPE_RD_INSTANCE = 1,
  BMP_PEER_TYPE_LOCAL_INSTANCE = 2
};

#define BMP_PEER_HDR_FLAG_V_SHIFT 7
enum bmp_peer_flag_v_t {
  // The Peer address is an IPv4 address
  BMP_PEER_HDR_FLAG_V_IP4 = (0 << BMP_PEER_HDR_FLAG_V_SHIFT),
  // The Peer address is an IPv6 address
  BMP_PEER_HDR_FLAG_V_IP6 = (1 << BMP_PEER_HDR_FLAG_V_SHIFT)
};

#define BMP_PEER_HDR_FLAG_L_SHIFT 6
enum bmp_peer_flag_l {
  BMP_PEER_HDR_FLAG_L_PRE_POLICY_ADJ_RIB_IN = (0 << BMP_PEER_HDR_FLAG_L_SHIFT),
  BMP_PEER_HDR_FLAG_L_POST_POLICY_ADJ_RIB_IN = (1 << BMP_PEER_HDR_FLAG_L_SHIFT)
};

#define BMP_PEER_HDR_FLAG_A_SHIFT 5
enum bmp_peer_flag_a {
  // The 4-byte AS_PATH format
  BMP_PEER_HDR_FLAG_A_AS_PATH_4B = (0 << BMP_PEER_HDR_FLAG_A_SHIFT),
  // The legacy 2-byte AS_PATH format
  BMP_PEER_HDR_FLAG_A_AS_PATH_2B = (1 << BMP_PEER_HDR_FLAG_A_SHIFT)
};

#define BMP_PEER_HDR_FLAGS_INIT(flags) \
  (flags) = 0
#define BMP_PEER_HDR_FLAGS_SET(flags, bit_mask) \
  (flags) |= (bit_mask)

/* BMP Information TLV header [RFC 7854 - Section 4.4] */
// Total size of Type and Length fields of Information TLV Header without
// variable part
#define BMP_INFO_TLV_FIX_SIZE 4

enum bmp_info_tlv_type {
  BMP_INFO_TLV_TYPE_STRING = 0,    // String
  BMP_INFO_TLV_TYPE_SYS_DESCR = 1, // SysDescr
  BMP_INFO_TLV_TYPE_SYS_NAME = 2   // SysName
};

/* BMP Peer Up Notification message header [RFC 7854 - Section 4.10] */
// Total size of all fields of Peer Up Notification message except variable part
#define BMP_PEER_UP_NOTIF_MSG_FIX_SIZE 20

enum bmp_peer_down_notif_reason {
  // The local system closed the session
  BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION = 1,
  // The local system closed the session
  BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION = 2,
  // The remote system closed the session with a notification message
  BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION = 3,
  // The remote system closed the session without a notification message
  BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION = 4,
  // Information for this peer will no longer be sent to the monitoring station
  // for configuration reasons
  BMP_PEER_DOWN_REASON_PEER_DE_CONFIGURED = 5
};

/* BMP Termination Message [RFC 7854 - Section 4.5] */
#define BMP_TERM_INFO_TYPE_SIZE 2
enum bmp_term_info_type {
  BMP_TERM_INFO_STRING = 0, // The Information field contains string
  BMP_TERM_INFO_REASON = 1, // The Information field contains 2-byte reason code
};

// 2-byte code in the Information field
#define BMP_TERM_REASON_CODE_SIZE 2
enum bmp_term_reason {
  BMP_TERM_REASON_ADM = 0,  // Session administratively closed
  BMP_TERM_REASON_UNK = 1,  // Unspecified reason
  BMP_TERM_REASON_OOR = 2,  // Out of resources
  BMP_TERM_REASON_DUP = 3,  // Redundant connection
  BMP_TERM_REASON_PERM = 4, // Session permanently administratively closed
};

// Size of Information Length field in Termination Message header
#define BMP_TERM_INFO_LEN_FIELD_SIZE 2

// Default chunk size request when memory allocation
#define DEFAULT_MEM_BLOCK_SIZE 4096

// Initial delay for connection to the BMP collector
#define CONNECT_INIT_TIME (200 MS)

// Timeout for connection to the BMP collector retry
#define CONNECT_RETRY_TIME (10 S)

#define IP4_MAX_TTL 255


#define IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(expr, msg, rv...)     \
  do {                                                                      \
    if ((expr))                                                             \
    {                                                                       \
      log(L_WARN "[BMP] " msg);                                             \
      return rv;                                                            \
    }                                                                       \
  } while (0)


#define IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(p, msg, rv...)	\
  do {									\
    IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(!(p), msg, rv);	\
  } while (0)


static void bmp_connected(struct birdsock *sk);
static void bmp_sock_err(sock *sk, int err);
static void bmp_close_socket(struct bmp_proto *p);

static void
bmp_send_peer_up_notif_msg(struct bmp_proto *p, const struct bgp_proto *bgp,
  const byte *tx_data, const size_t tx_data_size,
  const byte *rx_data, const size_t rx_data_size);

static void bmp_route_monitor_end_of_rib(struct bmp_proto *p, struct bmp_stream *bs);

// Stores necessary any data in list
struct bmp_data_node {
  node n;
  byte *data;
  size_t data_size;

  u32 remote_as;
  u32 remote_id;
  ip_addr remote_ip;
  btime timestamp;
  bool global_peer;
  bool policy;
};

static void
bmp_common_hdr_serialize(buffer *stream, const enum bmp_message_type type, const u32 data_size)
{
  bmp_put_u8(stream, BMP_VERSION_3);
  bmp_put_u32(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_put_u8(stream, type);
}

static void
bmp_info_tlv_hdr_serialize(buffer *stream, const enum bmp_info_tlv_type type,
  const char *str)
{
  size_t str_len = strlen(str);
  str_len = MIN(str_len, MIB_II_STR_LEN);

  bmp_put_u16(stream, type);
  bmp_put_u16(stream, str_len);
  bmp_put_data(stream, str, str_len);
}

// Serializes BMP Initiation message header [RFC 7854 - Section 4.3]
static void
bmp_init_msg_serialize(buffer *stream, const char *sys_descr, const char *sys_name)
{
  const size_t sys_descr_len = strlen(sys_descr);
  const size_t sys_name_len = strlen(sys_name);
  // We include MIB-II sysDescr and sysName in BMP INIT MSG so that's why
  // allocated 2x BMP_INFO_TLV_FIX_SIZE memory pool size
  const size_t data_size = (2 * BMP_INFO_TLV_FIX_SIZE) + sys_descr_len + sys_name_len;
  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_common_hdr_serialize(stream, BMP_INIT_MSG, data_size);
  bmp_info_tlv_hdr_serialize(stream, BMP_INFO_TLV_TYPE_SYS_DESCR, sys_descr);
  bmp_info_tlv_hdr_serialize(stream, BMP_INFO_TLV_TYPE_SYS_NAME, sys_name);
}

static void
bmp_schedule_tx_packet(struct bmp_proto *p, const byte *payload, const size_t size)
{
  ASSERT(p->started);

  struct bmp_data_node *tx_data = mb_alloc(p->tx_mem_pool, sizeof (struct bmp_data_node));
  tx_data->data = mb_alloc(p->tx_mem_pool, size);
  memcpy(tx_data->data, payload, size);
  tx_data->data_size = size;
  add_tail(&p->tx_queue, &tx_data->n);

  if (sk_tx_buffer_empty(p->sk)
      && !ev_active(p->tx_ev))
  {
    ev_schedule(p->tx_ev);
  }
}

static void
bmp_fire_tx(void *p_)
{
  struct bmp_proto *p = p_;

  if (!p->started)
    return;

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    EMPTY_LIST(p->tx_queue),
    "Called BMP TX event handler when there is not any data to send"
  );

  size_t cnt = 0; // Counts max packets which we want to send per TX slot
  struct bmp_data_node *tx_data;
  struct bmp_data_node *tx_data_next;
  WALK_LIST_DELSAFE(tx_data, tx_data_next, p->tx_queue)
  {
    if (tx_data->data_size > p->sk->tbsize)
    {
      sk_set_tbsize(p->sk, tx_data->data_size);
    }

    size_t data_size = tx_data->data_size;
    memcpy(p->sk->tbuf, tx_data->data, data_size);
    mb_free(tx_data->data);
    rem_node((node *) tx_data);
    mb_free(tx_data);

    if (sk_send(p->sk, data_size) <= 0)
      return;

    // BMP packets should be treat with lowest priority when scheduling sending
    // packets to target. That's why we want to send max. 32 packets per event
    // call
    if (++cnt > 32)
    {
      if (!ev_active(p->tx_ev))
      {
        ev_schedule(p->tx_ev);
      }

      return;
    }
  }
}

static void
bmp_tx(struct birdsock *sk)
{
  bmp_fire_tx(sk->data);
}

/* We need RX hook just to accept socket close events */
static int
bmp_rx(struct birdsock *sk UNUSED, uint size UNUSED)
{
  return 0;
}


static inline void
bmp_put_ipa(buffer *stream, const ip_addr addr)
{
  bmp_put_ip6(stream, ipa_is_ip4(addr) ?
	      ip6_build(0,0,0, ipa_to_u32(addr)) :
	      ipa_to_ip6(addr));
}

static void
bmp_put_bgp_hdr(buffer *stream, const u8 msg_type, const u16 msg_length)
{
  bmp_buffer_need(stream, BGP_HEADER_LENGTH);

  memset(stream->pos, 0xff, BGP_HDR_MARKER_LENGTH);
  stream->pos += BGP_HDR_MARKER_LENGTH;

  bmp_put_u16(stream, msg_length);
  bmp_put_u8(stream, msg_type);
}

/**
 * bmp_per_peer_hdr_serialize - serializes Per-Peer Header
 *
 * @is_post_policy: indicate the message reflects the post-policy Adj-RIB-In
 * @peer_addr: the remote IP address associated with the TCP session
 * @peer_as: the Autonomous System number of the peer
 * @peer_bgp_id: the BGP Identifier of the peer
 * @ts_sec: the time in seconds when the encapsulated routes were received
 * @ts_usec: the time in microseconds when the encapsulated routes were received
 */
static void
bmp_per_peer_hdr_serialize(buffer *stream, const bool is_global_instance_peer,
  const bool is_post_policy, const bool is_as_path_4bytes,
  const ip_addr peer_addr, const u32 peer_as, const u32 peer_bgp_id,
  const u32 ts_sec, const u32 ts_usec)
{
  // TODO: ATM we don't support BMP_PEER_TYPE_RD_INSTANCE
  const enum bmp_peer_type peer_type = is_global_instance_peer
                                      ? BMP_PEER_TYPE_GLOBAL_INSTANCE
                                      : BMP_PEER_TYPE_LOCAL_INSTANCE;
  const u8 peer_flag_v = ipa_is_ip4(peer_addr)
                           ? BMP_PEER_HDR_FLAG_V_IP4
                           : BMP_PEER_HDR_FLAG_V_IP6;
  const u8 peer_flag_l = is_post_policy
                           ? BMP_PEER_HDR_FLAG_L_POST_POLICY_ADJ_RIB_IN
                           : BMP_PEER_HDR_FLAG_L_PRE_POLICY_ADJ_RIB_IN;
  const u8 peer_flag_a = is_as_path_4bytes
                           ? BMP_PEER_HDR_FLAG_A_AS_PATH_4B
                           : BMP_PEER_HDR_FLAG_A_AS_PATH_2B;
  u8 peer_flags;
  BMP_PEER_HDR_FLAGS_INIT(peer_flags);
  BMP_PEER_HDR_FLAGS_SET(peer_flags, peer_flag_v);
  BMP_PEER_HDR_FLAGS_SET(peer_flags, peer_flag_l);
  BMP_PEER_HDR_FLAGS_SET(peer_flags, peer_flag_a);

  bmp_put_u8(stream, peer_type);
  bmp_put_u8(stream, peer_flags);
  // TODO: Provide appropriate peer Route Distinguisher if applicable
  bmp_put_u64(stream, 0x00); // 0x00 - Not supported peer distinguisher
  bmp_put_ipa(stream, peer_addr);
  bmp_put_u32(stream, peer_as);
  bmp_put_u32(stream, peer_bgp_id);
  bmp_put_u32(stream, ts_sec);
  bmp_put_u32(stream, ts_usec);
}

/* [4.6] Route Monitoring */
static void
bmp_route_monitor_msg_serialize(buffer *stream, const bool is_peer_global,
  const bool table_in_post_policy, const u32 peer_as, const u32 peer_bgp_id,
  const bool as4_support, const ip_addr remote_addr, const byte *update_msg,
  const size_t update_msg_size, btime timestamp)
{
  const size_t data_size = BMP_PER_PEER_HDR_SIZE + update_msg_size;
  u32 ts_sec = timestamp TO_S;
  u32 ts_usec = timestamp - (ts_sec S);

  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_common_hdr_serialize(stream, BMP_ROUTE_MONITOR, data_size);
  bmp_per_peer_hdr_serialize(stream, is_peer_global, table_in_post_policy,
    as4_support, remote_addr, peer_as, peer_bgp_id, ts_sec, ts_usec);
  bmp_put_data(stream, update_msg, update_msg_size);
}

static void
bmp_peer_up_notif_msg_serialize(buffer *stream, const bool is_peer_global,
  const u32 peer_as, const u32 peer_bgp_id, const bool as4_support,
  const ip_addr local_addr, const ip_addr remote_addr, const u16 local_port,
  const u16 remote_port, const byte *sent_msg, const size_t sent_msg_length,
  const byte *recv_msg, const size_t recv_msg_length)
{
  const size_t data_size =
    BMP_PER_PEER_HDR_SIZE + BMP_PEER_UP_NOTIF_MSG_FIX_SIZE +
    BGP_HEADER_LENGTH + sent_msg_length + BGP_HEADER_LENGTH + recv_msg_length;

  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_common_hdr_serialize(stream, BMP_PEER_UP_NOTIF, data_size);
  bmp_per_peer_hdr_serialize(stream, is_peer_global,
    false /* TODO: Hardcoded pre-policy Adj-RIB-In */, as4_support, remote_addr,
    peer_as, peer_bgp_id, 0, 0); // 0, 0 - No timestamp provided
  bmp_put_ipa(stream, local_addr);
  bmp_put_u16(stream, local_port);
  bmp_put_u16(stream, remote_port);
  bmp_put_bgp_hdr(stream, PKT_OPEN, BGP_HEADER_LENGTH + sent_msg_length);
  bmp_put_data(stream, sent_msg, sent_msg_length);
  bmp_put_bgp_hdr(stream, PKT_OPEN, BGP_HEADER_LENGTH + recv_msg_length);
  bmp_put_data(stream, recv_msg, recv_msg_length);
}

static void
bmp_peer_down_notif_msg_serialize(buffer *stream, const bool is_peer_global,
  const u32 peer_as, const u32 peer_bgp_id, const bool as4_support,
  const ip_addr remote_addr, const byte *data, const size_t data_size)
{
  const size_t payload_size = BMP_PER_PEER_HDR_SIZE + data_size;
  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + payload_size);
  bmp_common_hdr_serialize(stream, BMP_PEER_DOWN_NOTIF, payload_size);
  bmp_per_peer_hdr_serialize(stream, is_peer_global,
    false /* TODO: Hardcoded pre-policy adj RIB IN */,  as4_support, remote_addr,
    peer_as, peer_bgp_id, 0, 0); // 0, 0 - No timestamp provided
  bmp_put_data(stream, data, data_size);
}


/*
 *	BMP tables
 */

static struct bmp_table *
bmp_find_table(struct bmp_proto *p, struct rtable *tab)
{
  return HASH_FIND(p->table_map, HASH_TABLE, tab);
}

static struct bmp_table *
bmp_add_table(struct bmp_proto *p, struct rtable *tab)
{
  struct bmp_table *bt = mb_allocz(p->p.pool, sizeof(struct bmp_table));
  bt->table = tab;
  rt_lock_table(bt->table);

  HASH_INSERT(p->table_map, HASH_TABLE, bt);

  struct channel_config cc = {
    .name = "monitor",
    .channel = &channel_basic,
    .table = tab->config,
    .in_filter = FILTER_REJECT,
    .net_type = tab->addr_type,
    .ra_mode = RA_ANY,
    .bmp_hack = 1,
  };

  bt->channel = proto_add_channel(&p->p, &cc);
  channel_set_state(bt->channel, CS_UP);

  return bt;
}

static void
bmp_remove_table(struct bmp_proto *p, struct bmp_table *bt)
{
  channel_set_state(bt->channel, CS_FLUSHING);
  channel_set_state(bt->channel, CS_DOWN);
  proto_remove_channel(&p->p, bt->channel);

  HASH_REMOVE(p->table_map, HASH_TABLE, bt);

  rt_unlock_table(bt->table);
  bt->table = NULL;

  mb_free(bt);
}

static inline struct bmp_table *bmp_get_table(struct bmp_proto *p, struct rtable *tab)
{ return bmp_find_table(p, tab) ?: bmp_add_table(p, tab); }

static inline void bmp_lock_table(struct bmp_proto *p UNUSED, struct bmp_table *bt)
{ bt->uc++; }

static inline void bmp_unlock_table(struct bmp_proto *p, struct bmp_table *bt)
{ bt->uc--; if (!bt->uc) bmp_remove_table(p, bt); }


/*
 *	BMP streams
 */

static inline u32 bmp_stream_key(u32 afi, bool policy)
{ return afi ^ (policy ? BMP_STREAM_KEY_POLICY : 0); }

static inline u32 bmp_stream_afi(struct bmp_stream *bs)
{ return bs->key & ~BMP_STREAM_KEY_POLICY; }

static inline bool bmp_stream_policy(struct bmp_stream *bs)
{ return !!(bs->key & BMP_STREAM_KEY_POLICY); }

static struct bmp_stream *
bmp_find_stream(struct bmp_proto *p, const struct bgp_proto *bgp, u32 afi, bool policy)
{
  return HASH_FIND(p->stream_map, HASH_STREAM, bgp, bmp_stream_key(afi, policy));
}

static struct bmp_stream *
bmp_add_stream(struct bmp_proto *p, struct bmp_peer *bp, u32 afi, bool policy, struct rtable *tab, struct bgp_channel *sender)
{
  struct bmp_stream *bs = mb_allocz(p->p.pool, sizeof(struct bmp_stream));
  bs->bgp = bp->bgp;
  bs->key = bmp_stream_key(afi, policy);

  add_tail(&bp->streams, &bs->n);
  HASH_INSERT(p->stream_map, HASH_STREAM, bs);

  bs->table = bmp_get_table(p, tab);
  bmp_lock_table(p, bs->table);

  bs->sender = sender;
  bs->sync = false;

  return bs;
}

static void
bmp_remove_stream(struct bmp_proto *p, struct bmp_stream *bs)
{
  rem_node(&bs->n);
  HASH_REMOVE(p->stream_map, HASH_STREAM, bs);

  bmp_unlock_table(p, bs->table);
  bs->table = NULL;

  mb_free(bs);
}


/*
 *	BMP peers
 */

static struct bmp_peer *
bmp_find_peer(struct bmp_proto *p, const struct bgp_proto *bgp)
{
  return HASH_FIND(p->peer_map, HASH_PEER, bgp);
}

static struct bmp_peer *
bmp_add_peer(struct bmp_proto *p, struct bgp_proto *bgp)
{
  struct bmp_peer *bp = mb_allocz(p->p.pool, sizeof(struct bmp_peer));
  bp->bgp = bgp;

  init_list(&bp->streams);

  HASH_INSERT(p->peer_map, HASH_PEER, bp);

  struct bgp_channel *c;
  BGP_WALK_CHANNELS(bgp, c)
  {
    if (p->monitoring_rib.in_pre_policy && c->c.in_table)
      bmp_add_stream(p, bp, c->afi, false, c->c.in_table, c);

    if (p->monitoring_rib.in_post_policy && c->c.table)
      bmp_add_stream(p, bp, c->afi, true, c->c.table, c);
  }

  return bp;
}

static void
bmp_remove_peer(struct bmp_proto *p, struct bmp_peer *bp)
{
  struct bmp_stream *bs, *bs_next;
  WALK_LIST_DELSAFE(bs, bs_next, bp->streams)
    bmp_remove_stream(p, bs);

  HASH_REMOVE(p->peer_map, HASH_PEER, bp);

  mb_free(bp);
}

static void
bmp_peer_up_(struct bmp_proto *p, struct bgp_proto *bgp, bool sync,
	    const byte *tx_open_msg, uint tx_open_length,
	    const byte *rx_open_msg, uint rx_open_length)
{
  if (!p->started)
    return;

  struct bmp_peer *bp = bmp_find_peer(p, bgp);
  if (bp)
    return;

  TRACE(D_STATES, "Peer up for %s", bgp->p.name);

  bp = bmp_add_peer(p, bgp);

  bmp_send_peer_up_notif_msg(p, bgp, tx_open_msg, tx_open_length, rx_open_msg, rx_open_length);

  /*
   * We asssume peer_up() notifications are received before any route
   * notifications from that peer. Therefore, peers established after BMP
   * session coould be considered synced with empty RIB.
   */
  if (sync)
  {
    struct bmp_stream *bs;
    WALK_LIST(bs, bp->streams)
    {
      bmp_route_monitor_end_of_rib(p, bs);
      bs->sync = true;
    }
  }
}

void
bmp_peer_up(struct bgp_proto *bgp,
	    const byte *tx_open_msg, uint tx_open_length,
	    const byte *rx_open_msg, uint rx_open_length)
{
  struct bmp_proto *p; node *n;
  WALK_LIST2(p, n, bmp_proto_list, bmp_node)
    bmp_peer_up_(p, bgp, true, tx_open_msg, tx_open_length, rx_open_msg, rx_open_length);
}

static void
bmp_peer_init(struct bmp_proto *p, struct bgp_proto *bgp)
{
  struct bgp_conn *conn = bgp->conn;

  if (!conn || (conn->state != BS_ESTABLISHED) ||
      !conn->local_open_msg || !conn->remote_open_msg)
    return;

  bmp_peer_up_(p, bgp, false, conn->local_open_msg, conn->local_open_length,
	       conn->remote_open_msg, conn->remote_open_length);
}



static const struct birdsock *
bmp_get_birdsock(const struct bgp_proto *bgp)
{
  if (bgp->conn && bgp->conn->sk)
    return bgp->conn->sk;

  return NULL;
}

static const struct birdsock *
bmp_get_birdsock_ext(const struct bgp_proto *bgp)
{
  const struct birdsock *sk = bmp_get_birdsock(bgp);
  if (sk != NULL)
    return sk;

  if (bgp->incoming_conn.sk)
  {
    sk = bgp->incoming_conn.sk;
  }
  else if (bgp->outgoing_conn.sk)
  {
    sk = bgp->outgoing_conn.sk;
  }

  return sk;
}

static const struct bgp_caps *
bmp_get_bgp_remote_caps(const struct bgp_proto *bgp)
{
  if (bgp->conn && bgp->conn->remote_caps)
    return bgp->conn->remote_caps;

  return NULL;
}

static const struct bgp_caps *
bmp_get_bgp_remote_caps_ext(const struct bgp_proto *bgp)
{
  const struct bgp_caps *remote_caps = bmp_get_bgp_remote_caps(bgp);
  if (remote_caps != NULL)
    return remote_caps;

  if (bgp->incoming_conn.remote_caps)
  {
    remote_caps = bgp->incoming_conn.remote_caps;
  }
  else if (bgp->outgoing_conn.remote_caps)
  {
    remote_caps = bgp->outgoing_conn.remote_caps;
  }

  return remote_caps;
}

static bool
bmp_is_peer_global_instance(const struct bgp_proto *bgp)
{
  return (bgp->cf->peer_type != BGP_PT_EXTERNAL &&
            bgp->cf->peer_type != BGP_PT_INTERNAL)
              ? (bgp->local_as != bgp->remote_as)
              : (bgp->cf->peer_type == BGP_PT_EXTERNAL);
}

static void
bmp_send_peer_up_notif_msg(struct bmp_proto *p, const struct bgp_proto *bgp,
  const byte *tx_data, const size_t tx_data_size,
  const byte *rx_data, const size_t rx_data_size)
{
  ASSERT(p->started);

  const struct birdsock *sk = bmp_get_birdsock_ext(bgp);
  IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    sk,
    "[BMP] No BGP socket"
  );

  const bool is_global_instance_peer = bmp_is_peer_global_instance(bgp);
  buffer payload = bmp_buffer_alloc(p->buffer_mpool, DEFAULT_MEM_BLOCK_SIZE);
  bmp_peer_up_notif_msg_serialize(&payload, is_global_instance_peer,
    bgp->remote_as, bgp->remote_id, 1,
    sk->saddr, sk->daddr, sk->sport, sk->dport, tx_data, tx_data_size,
    rx_data, rx_data_size);
  bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));
  bmp_buffer_free(&payload);
}

static void
bmp_route_monitor_put_update(struct bmp_proto *p, struct bmp_stream *bs, const byte *data, size_t length, btime timestamp)
{
  struct bmp_data_node *upd_msg = mb_alloc(p->update_msg_mem_pool,
                               sizeof (struct bmp_data_node));
  upd_msg->data = mb_alloc(p->update_msg_mem_pool, length);
  memcpy(upd_msg->data, data, length);
  upd_msg->data_size = length;
  add_tail(&p->update_msg_queue, &upd_msg->n);

  /* Save some metadata */
  struct bgp_proto *bgp = bs->bgp;
  upd_msg->remote_as = bgp->remote_as;
  upd_msg->remote_id = bgp->remote_id;
  upd_msg->remote_ip = bgp->remote_ip;
  upd_msg->timestamp = timestamp;
  upd_msg->global_peer = bmp_is_peer_global_instance(bgp);
  upd_msg->policy = bmp_stream_policy(bs);

  /* Kick the commit */
  if (!ev_active(p->update_ev))
    ev_schedule(p->update_ev);
}

static void
bmp_route_monitor_notify(struct bmp_proto *p, struct bmp_stream *bs,
			 const net_addr *n, const struct rte *new, const struct rte_src *src)
{
  byte buf[BGP_MAX_EXT_MSG_LENGTH];
  byte *end = bgp_bmp_encode_rte(bs->sender, buf, n, new, src);

  btime delta_t = new ? current_time() - new->lastmod : 0;
  btime timestamp = current_real_time() - delta_t;

  if (end)
    bmp_route_monitor_put_update(p, bs, buf, end - buf, timestamp);
  else
    log(L_WARN "%s: Cannot encode update for %N", p->p.name, n);
}

static void
bmp_route_monitor_commit(void *p_)
{
  struct bmp_proto *p = p_;

  if (!p->started)
    return;

  buffer payload
    = bmp_buffer_alloc(p->buffer_mpool, DEFAULT_MEM_BLOCK_SIZE);

  struct bmp_data_node *data, *data_next;
  WALK_LIST_DELSAFE(data, data_next, p->update_msg_queue)
  {
    bmp_route_monitor_msg_serialize(&payload,
      data->global_peer, data->policy,
      data->remote_as, data->remote_id, true,
      data->remote_ip, data->data, data->data_size,
      data->timestamp);

    bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));

    bmp_buffer_flush(&payload);

    mb_free(data->data);
    rem_node(&data->n);
    mb_free(data);
  }

  bmp_buffer_free(&payload);
}

static void
bmp_route_monitor_end_of_rib(struct bmp_proto *p, struct bmp_stream *bs)
{
  TRACE(D_PACKETS, "Sending END-OF-RIB for %s.%s", bs->bgp->p.name, bs->sender->c.name);

  byte rx_end_payload[DEFAULT_MEM_BLOCK_SIZE];
  byte *pos = bgp_create_end_mark_(bs->sender, rx_end_payload + BGP_HEADER_LENGTH);
  memset(rx_end_payload + BGP_MSG_HDR_MARKER_POS, 0xff,
	 BGP_MSG_HDR_MARKER_SIZE); // BGP UPDATE MSG marker
  put_u16(rx_end_payload + BGP_MSG_HDR_LENGTH_POS, pos - rx_end_payload);
  put_u8(rx_end_payload + BGP_MSG_HDR_TYPE_POS, PKT_UPDATE);

  bmp_route_monitor_put_update(p, bs, rx_end_payload, pos - rx_end_payload, current_real_time());
}

static void
bmp_send_peer_down_notif_msg(struct bmp_proto *p, const struct bgp_proto *bgp,
  const byte *data, const size_t data_size)
{
  ASSERT(p->started);

  const struct bgp_caps *remote_caps = bmp_get_bgp_remote_caps_ext(bgp);
  bool is_global_instance_peer = bmp_is_peer_global_instance(bgp);
  buffer payload
    = bmp_buffer_alloc(p->buffer_mpool, DEFAULT_MEM_BLOCK_SIZE);
  bmp_peer_down_notif_msg_serialize(&payload, is_global_instance_peer,
    bgp->remote_as, bgp->remote_id,
    remote_caps ? remote_caps->as4_support : bgp->as4_session,
    bgp->remote_ip, data, data_size);
  bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));

  bmp_buffer_free(&payload);
}

static void
bmp_peer_down_(struct bmp_proto *p, const struct bgp_proto *bgp,
	       int err_class, int err_code, int err_subcode, const byte *data, int length)
{
  if (!p->started)
    return;

  struct bmp_peer *bp = bmp_find_peer(p, bgp);
  if (!bp)
    return;

  TRACE(D_STATES, "Peer down for %s", bgp->p.name);

  uint bmp_code = 0;
  uint fsm_code = 0;

  switch (err_class)
  {
  case BE_BGP_RX:
    bmp_code = BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION;
    break;

  case BE_BGP_TX:
  case BE_AUTO_DOWN:
  case BE_MAN_DOWN:
    bmp_code = BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION;
    break;

  default:
    bmp_code = BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION;
    length = 0;
    break;
  }

  buffer payload = bmp_buffer_alloc(p->buffer_mpool, 1 + BGP_HEADER_LENGTH + 2 + length);
  bmp_put_u8(&payload, bmp_code);

  switch (bmp_code)
  {
  case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION:
  case BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:
    bmp_put_bgp_hdr(&payload, BGP_HEADER_LENGTH + 2 + length, PKT_NOTIFICATION);
    bmp_put_u8(&payload, err_code);
    bmp_put_u8(&payload, err_subcode);
    bmp_put_data(&payload, data, length);
    break;

  case BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
    bmp_put_u16(&payload, fsm_code);
    break;
  }

  bmp_send_peer_down_notif_msg(p, bgp, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));

  bmp_buffer_free(&payload);

  bmp_remove_peer(p, bp);
}

void
bmp_peer_down(const struct bgp_proto *bgp,
	      int err_class, int code, int subcode, const byte *data, int length)
{
  struct bmp_proto *p; node *n;
  WALK_LIST2(p, n, bmp_proto_list, bmp_node)
    bmp_peer_down_(p, bgp, err_class, code, subcode, data, length);
}

static void
bmp_send_termination_msg(struct bmp_proto *p,
  const enum bmp_term_reason reason)
{
  const size_t term_msg_hdr_size = BMP_TERM_INFO_TYPE_SIZE
                                     + BMP_TERM_INFO_LEN_FIELD_SIZE
                                     + BMP_TERM_REASON_CODE_SIZE;
  const size_t term_msg_size = BMP_COMMON_HDR_SIZE + term_msg_hdr_size;
  buffer stream = bmp_buffer_alloc(p->buffer_mpool, term_msg_size);
  bmp_common_hdr_serialize(&stream, BMP_TERM_MSG, term_msg_hdr_size);
  bmp_put_u16(&stream, BMP_TERM_INFO_REASON);
  bmp_put_u16(&stream, BMP_TERM_REASON_CODE_SIZE); // 2-byte code indication the reason
  bmp_put_u16(&stream, reason);
  memcpy(p->sk->tbuf, bmp_buffer_data(&stream), bmp_buffer_pos(&stream));
  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    sk_send(p->sk, bmp_buffer_pos(&stream)) < 0,
    "Failed to send BMP termination message"
    );

  bmp_buffer_free(&stream);
}

int
bmp_preexport(struct channel *C UNUSED, rte *e)
{
  /* Reject non-direct routes */
  if (e->src->proto != e->sender->proto)
    return -1;

  /* Reject non-BGP routes */
  if (e->sender->channel != &channel_bgp)
    return -1;

  return 1;
}

static void
bmp_rt_notify(struct proto *P, struct channel *c, struct network *net,
		struct rte *new, struct rte *old)
{
  struct bmp_proto *p = (void *) P;

  struct bgp_channel *src = (void *) (new ?: old)->sender;
  struct bgp_proto *bgp = (void *) src->c.proto;
  bool policy = (c->table == src->c.table);

  /*
   * We assume that we receive peer_up before the first route and peer_down
   * synchronously with BGP session close. So if bmp_stream exists, the related
   * BGP session is up and could be accessed. That may not be true in
   * multithreaded setup.
   */

  struct bmp_stream *bs = bmp_find_stream(p, bgp, src->afi, policy);
  if (!bs)
    return;

  bmp_route_monitor_notify(p, bs, net->n.addr, new, (new ?: old)->src);
}

static void
bmp_feed_end(struct channel *c)
{
  struct bmp_proto *p = (void *) c->proto;

  struct bmp_table *bt = bmp_find_table(p, c->table);
  if (!bt)
    return;

  /*
   * Unsynced streams are added in one moment during BMP session establishment,
   * therefore we can assume that all unsynced streams (for given channel)
   * already received full feed now and are synced.
   *
   * TODO: Use more efficent way to find bmp_stream from bmp_table
   */

  HASH_WALK(p->stream_map, next, bs)
  {
    if ((bs->table == bt) && !bs->sync)
    {
      bmp_route_monitor_end_of_rib(p, bs);
      bs->sync = true;
    }
  }
  HASH_WALK_END;
}


/**
 * bmp_startup - enter established state
 * @p: BMP instance
 *
 * The bgp_startup() function is called when the BMP session is established.
 * It sends initiation and peer up messagages.
 */
static void
bmp_startup(struct bmp_proto *p)
{
  ASSERT(!p->started);
  p->started = true;
  p->sock_err = 0;

  TRACE(D_EVENTS, "BMP session established");

  proto_notify_state(&p->p, PS_UP);

  /* Send initiation message */
  buffer payload = bmp_buffer_alloc(p->buffer_mpool, DEFAULT_MEM_BLOCK_SIZE);
  bmp_init_msg_serialize(&payload, p->sys_descr, p->sys_name);
  bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));
  bmp_buffer_free(&payload);

  /* Send Peer Up messages */
  struct proto *peer;
  WALK_LIST(peer, proto_list)
    if ((peer->proto->class == PROTOCOL_BGP) && (peer->proto_state == PS_UP))
      bmp_peer_init(p, (struct bgp_proto *) peer);
}

/**
 * bmp_down - leave established state
 * @p: BMP instance
 *
 * The bgp_down() function is called when the BMP session fails. The caller is
 * responsible for changing protocol state.
 */
static void
bmp_down(struct bmp_proto *p)
{
  ASSERT(p->started);
  p->started = false;

  TRACE(D_EVENTS, "BMP session closed");

  /* Unregister existing peer structures */
  HASH_WALK_DELSAFE(p->peer_map, next, bp)
  {
    bmp_remove_peer(p, bp);
  }
  HASH_WALK_END;

  /* Removing peers should also remove all streams and tables */
  ASSERT(!p->peer_map.count && !p->stream_map.count && !p->table_map.count);
}

/**
 * bmp_connect - initiate an outgoing connection
 * @p: BMP instance
 *
 * The bmp_connect() function creates the socket and initiates an outgoing TCP
 * connection to the monitoring station. It is called to enter Connect state.
 */
static void
bmp_connect(struct bmp_proto *p)
{
  ASSERT(!p->started);

  sock *sk = sk_new(p->p.pool);
  sk->type = SK_TCP_ACTIVE;
  sk->saddr = p->local_addr;
  sk->daddr = p->station_ip;
  sk->dport = p->station_port;
  sk->ttl = IP4_MAX_TTL;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->tbsize = BGP_TX_BUFFER_EXT_SIZE;
  sk->tx_hook = bmp_connected;
  sk->err_hook = bmp_sock_err;

  p->sk = sk;
  sk->data = p;

  TRACE(D_EVENTS, "Connecting to %I port %u", sk->daddr, sk->dport);

  int rc = sk_open(sk);

  if (rc < 0)
    sk_log_error(sk, p->p.name);

  tm_start(p->connect_retry_timer, CONNECT_RETRY_TIME);
}

/* BMP connect successful event - switch from Connect to Established state */
static void
bmp_connected(struct birdsock *sk)
{
  struct bmp_proto *p = (void *) sk->data;

  TRACE(D_EVENTS, "Connected");

  sk->rx_hook = bmp_rx;
  sk->tx_hook = bmp_tx;
  tm_stop(p->connect_retry_timer);

  bmp_startup(p);
}

/* BMP socket error event - switch from any state to Idle state */
static void
bmp_sock_err(sock *sk, int err)
{
  struct bmp_proto *p = sk->data;

  p->sock_err = err;

  if (err)
    TRACE(D_EVENTS, "Connection lost (%M)", err);
  else
    TRACE(D_EVENTS, "Connection closed");

  if (p->started)
    bmp_down(p);

  bmp_close_socket(p);
  tm_start(p->connect_retry_timer, CONNECT_RETRY_TIME);

  proto_notify_state(&p->p, PS_START);
}

/* BMP connect timeout event - switch from Idle/Connect state to Connect state */
static void
bmp_connection_retry(timer *t)
{
  struct bmp_proto *p = t->data;

  if (p->started)
    return;

  bmp_close_socket(p);
  bmp_connect(p);
}

static void
bmp_close_socket(struct bmp_proto *p)
{
  rfree(p->sk);
  p->sk = NULL;
}


static void
bmp_postconfig(struct proto_config *CF)
{
  struct bmp_config *cf = (void *) CF;

  /* Do not check templates at all */
  if (cf->c.class == SYM_TEMPLATE)
    return;

  if (ipa_zero(cf->station_ip))
    cf_error("Station IP address not specified");

  if (!cf->station_port)
    cf_error("Station port number not specified");
}

/** Configuration handle section **/
static struct proto *
bmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct bmp_proto *p = (void *) P;
  struct bmp_config *cf = (void *) CF;

  P->rt_notify = bmp_rt_notify;
  P->preexport = bmp_preexport;
  P->feed_end = bmp_feed_end;

  p->cf = cf;
  p->local_addr = cf->local_addr;
  p->station_ip = cf->station_ip;
  p->station_port = cf->station_port;
  strcpy(p->sys_descr, cf->sys_descr);
  strcpy(p->sys_name, cf->sys_name);
  p->monitoring_rib.in_pre_policy = cf->monitoring_rib_in_pre_policy;
  p->monitoring_rib.in_post_policy = cf->monitoring_rib_in_post_policy;

  return P;
}

/**
 * bmp_start - initialize internal resources of BMP implementation.
 * NOTE: It does not connect to BMP collector yet.
 */
static int
bmp_start(struct proto *P)
{
  struct bmp_proto *p = (void *) P;

  p->buffer_mpool = rp_new(P->pool, "BMP Buffer");
  p->map_mem_pool = rp_new(P->pool, "BMP Map");
  p->tx_mem_pool = rp_new(P->pool, "BMP Tx");
  p->update_msg_mem_pool = rp_new(P->pool, "BMP Update");
  p->tx_ev = ev_new_init(p->p.pool, bmp_fire_tx, p);
  p->update_ev = ev_new_init(p->p.pool, bmp_route_monitor_commit, p);
  p->connect_retry_timer = tm_new_init(p->p.pool, bmp_connection_retry, p, 0, 0);
  p->sk = NULL;

  HASH_INIT(p->peer_map, P->pool, 4);
  HASH_INIT(p->stream_map, P->pool, 4);
  HASH_INIT(p->table_map, P->pool, 4);

  init_list(&p->tx_queue);
  init_list(&p->update_msg_queue);
  p->started = false;
  p->sock_err = 0;
  add_tail(&bmp_proto_list, &p->bmp_node);

  tm_start(p->connect_retry_timer, CONNECT_INIT_TIME);

  return PS_START;
}

static int
bmp_shutdown(struct proto *P)
{
  struct bmp_proto *p = (void *) P;

  if (p->started)
  {
    bmp_send_termination_msg(p, BMP_TERM_REASON_ADM);
    bmp_down(p);
  }

  p->sock_err = 0;
  rem_node(&p->bmp_node);

  return PS_DOWN;
}

static int
bmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  struct bmp_proto *p = (void *) P;
  const struct bmp_config *new = (void *) CF;
  const struct bmp_config *old = p->cf;

  int needs_restart = bstrcmp(new->sys_descr, old->sys_descr)
    || bstrcmp(new->sys_name, old->sys_name)
    || !ipa_equal(new->local_addr, old->local_addr)
    || !ipa_equal(new->station_ip, old->station_ip)
    || (new->station_port != old->station_port)
    || (new->monitoring_rib_in_pre_policy != old->monitoring_rib_in_pre_policy)
    || (new->monitoring_rib_in_post_policy != old->monitoring_rib_in_post_policy);

  /* If there is any change, restart the protocol */
  if (needs_restart)
    return 0;

  /* We must update our copy of configuration ptr */
  p->cf = new;

  return 1;
}

static void
bmp_get_status(struct proto *P, byte *buf)
{
  struct bmp_proto *p = (void *) P;

  if (P->proto_state == PS_DOWN)
    bsprintf(buf, "Down");
  else
  {
    const char *state = !p->started ? (!p->sk ? "Idle" : "Connect") : "Established";

    if (!p->sock_err)
      bsprintf(buf, "%s", state);
    else
      bsprintf(buf, "%-14s%s %M", state, "Error:", p->sock_err);
  }
}

static void
bmp_show_proto_info(struct proto *P)
{
  struct bmp_proto *p = (void *) P;

  if (P->proto_state != PS_DOWN)
  {
    cli_msg(-1006, "  %-19s %I", "Station address:", p->station_ip);
    cli_msg(-1006, "  %-19s %u", "Station port:", p->station_port);

    if (!ipa_zero(p->local_addr))
      cli_msg(-1006, "  %-19s %I", "Local address:", p->local_addr);

    if (p->sock_err)
      cli_msg(-1006, "  %-19s %M", "Last error:", p->sock_err);
  }
}

struct protocol proto_bmp = {
  .name = "BMP",
  .template = "bmp%d",
  .class = PROTOCOL_BMP,
  .proto_size = sizeof(struct bmp_proto),
  .config_size = sizeof(struct bmp_config),
  .postconfig = bmp_postconfig,
  .init = bmp_init,
  .start = bmp_start,
  .shutdown = bmp_shutdown,
  .reconfigure = bmp_reconfigure,
  .get_status = bmp_get_status,
  .show_proto_info = bmp_show_proto_info,
};

void
bmp_build(void)
{
  proto_build(&proto_bmp);
}

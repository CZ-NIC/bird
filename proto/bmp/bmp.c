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

// We allow for single instance of BMP protocol
static struct bmp_proto *g_bmp;

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

// Timeout for connection to the BMP collector retry
#define CONNECT_RETRY_SEC (10 S)

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


// Handle BIRD socket error event
static void
bmp_sock_err(sock *sk, int err);

static void
bmp_send_peer_up_notif_msg(struct bmp_proto *p, const struct bgp_proto *bgp,
  const byte* tx_data, const size_t tx_data_size,
  const byte* rx_data, const size_t rx_data_size);

static void
bmp_peer_map_walk_tx_open_msg_and_send_peer_up_notif(
  const struct bmp_peer_map_key key, const byte *tx_msg,
  const size_t tx_msg_size, void *bmp_);

// Stores necessary any data in list
struct bmp_data_node {
  node n;
  byte *data;
  size_t data_size;
};

static void
bmp_route_monitor_pre_policy_table_in_snapshot(struct channel *C);

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
  str_len = MIN(str_len, 65535);

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
  ASSERT(p->station_connected);

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

/**
 * bmp_startup - connect to the BMP collector.
 * NOTE: Send Initiation Message to the BMP collector.
 */
static void
bmp_startup(struct bmp_proto *p)
{
  ASSERT(p->station_connected && !p->started);

  buffer payload = bmp_buffer_alloc(p->buffer_mpool, DEFAULT_MEM_BLOCK_SIZE);
  bmp_init_msg_serialize(&payload, p->sys_descr, p->sys_name);
  bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));
  bmp_buffer_free(&payload);

  p->started = true;
}

static void
bmp_fire_tx(void *p_)
{
  struct bmp_proto *p = p_;
  byte *buf = p->sk->tbuf;
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
    memcpy(buf, tx_data->data, tx_data->data_size);
    mb_free(tx_data->data);
    rem_node((node *) tx_data);
    mb_free(tx_data);
    IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
      (sk_send(p->sk, data_size) <= 0),
      "Failed to send BMP packet"
    );

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

static inline int
bmp_open_socket(struct bmp_proto *p)
{
  sock *s = p->sk;
  s->daddr = p->station_ip;
  s->dport = p->station_port;
  s->err_hook = bmp_sock_err;

  int rc = sk_open(s);

  if (rc < 0)
    sk_log_error(s, p->p.name);

  return rc;
}

static void
bmp_connection_retry(timer *t)
{
  struct bmp_proto *p = t->data;

  if (bmp_open_socket(p) < 0)
  {
    log(L_DEBUG "Failed to connect to BMP station");
    return;
  }

  log(L_DEBUG "Connected to BMP station after connection retry");
  tm_stop(t);
}

void
bmp_sock_err(sock *sk, int err)
{
  struct bmp_proto *p = sk->data;
  log(L_WARN "[BMP:%s] Socket error: %M", p->p.name, err);
}

static inline void
bmp_put_ipa(buffer *stream, const ip_addr addr)
{
  bmp_put_ip6(stream, ipa_is_ip4(addr) ?
	      ip6_build(0,0,0, ipa_to_u32(addr)) :
	      ipa_to_ip6(addr));
}

static void
bmp_set_initial_bgp_hdr(buffer *stream, const u16 msg_size, const u8 msg_type)
{
  byte marker[BGP_MSG_HDR_MARKER_SIZE];
  memset(marker, 0xff, BGP_MSG_HDR_MARKER_SIZE);
  bmp_put_data(stream, marker, BGP_MSG_HDR_MARKER_SIZE);
  bmp_put_u16(stream, msg_size);
  bmp_put_u8(stream, msg_type);
}

/**
 * bmp_per_peer_hdr_serialize - serializes Per-Peer Header
 *
 * @is_pre_policy: indicate the message reflects the pre-policy Adj-RIB-In
 * @peer_addr: the remote IP address associated with the TCP session
 * @peer_as: the Autonomous System number of the peer
 * @peer_bgp_id: the BGP Identifier of the peer
 * @ts_sec: the time in seconds when the encapsulated routes were received
 * @ts_usec: the time in microseconds when the encapsulated routes were received
 */
static void
bmp_per_peer_hdr_serialize(buffer *stream, const bool is_global_instance_peer,
  const bool is_pre_policy, const bool is_as_path_4bytes,
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
  const u8 peer_flag_l = is_pre_policy
                           ? BMP_PEER_HDR_FLAG_L_PRE_POLICY_ADJ_RIB_IN
                           : BMP_PEER_HDR_FLAG_L_POST_POLICY_ADJ_RIB_IN;
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
  const bool table_in_pre_policy, const u32 peer_as, const u32 peer_bgp_id,
  const bool as4_support, const ip_addr remote_addr, const byte *update_msg,
  const size_t update_msg_size, u32 ts_sec, u32 ts_usec)
{
  const size_t data_size = BMP_PER_PEER_HDR_SIZE + update_msg_size;
  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_common_hdr_serialize(stream, BMP_ROUTE_MONITOR, data_size);
  bmp_per_peer_hdr_serialize(stream, is_peer_global, table_in_pre_policy,
    as4_support, remote_addr, peer_as, peer_bgp_id, ts_sec, ts_usec);
  bmp_put_data(stream, update_msg, update_msg_size);
}

static void
bmp_peer_up_notif_msg_serialize(buffer *stream, const bool is_peer_global,
  const u32 peer_as, const u32 peer_bgp_id, const bool as4_support,
  const ip_addr local_addr, const ip_addr remote_addr, const u16 local_port,
  const u16 remote_port, const byte *sent_msg, const size_t sent_msg_size,
  const byte *recv_msg, const size_t recv_msg_size)
{
  const size_t data_size = BMP_PER_PEER_HDR_SIZE + BMP_PEER_UP_NOTIF_MSG_FIX_SIZE
                             + sent_msg_size + recv_msg_size;
  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE + data_size);
  bmp_common_hdr_serialize(stream, BMP_PEER_UP_NOTIF, data_size);
  bmp_per_peer_hdr_serialize(stream, is_peer_global,
    true /* TODO: Hardcoded pre-policy Adj-RIB-In */, as4_support, remote_addr,
    peer_as, peer_bgp_id, 0, 0); // 0, 0 - No timestamp provided
  bmp_put_ipa(stream, local_addr);
  bmp_put_u16(stream, local_port);
  bmp_put_u16(stream, remote_port);
  bmp_set_initial_bgp_hdr(stream, sent_msg_size, PKT_OPEN);
  const size_t missing_bgp_hdr_size = BGP_MSG_HDR_MARKER_SIZE
                                        + BGP_MSG_HDR_LENGTH_SIZE
                                        + BGP_MSG_HDR_TYPE_SIZE;
  bmp_put_data(stream, sent_msg, sent_msg_size - missing_bgp_hdr_size);
  bmp_put_data(stream, recv_msg, recv_msg_size);
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
    true /* TODO: Hardcoded pre-policy adj RIB IN */,  as4_support, remote_addr,
    peer_as, peer_bgp_id, 0, 0); // 0, 0 - No timestamp provided
  bmp_put_data(stream, data, data_size);
}

/**
 * bmp_open - initialize internal resources of BMP implementation.
 * NOTE: It does not connect to BMP collector yet.
 */
void
bmp_open(const struct proto *P)
{
  struct bmp_proto *p = (void *) P;

  if (bmp_open_socket(p) < 0)
  {
    log(L_DEBUG "Failed to connect to BMP station");
    p->connect_retry_timer = tm_new_init(P->pool, bmp_connection_retry, p,
					 CONNECT_RETRY_SEC, 0 /* not randomized */);
    tm_start(p->connect_retry_timer, CONNECT_RETRY_SEC);
    p->station_connected = false;
  }
  else
  {
    log(L_DEBUG "Connected to BMP station");
  }
}

void
bmp_peer_map_walk_tx_open_msg_and_send_peer_up_notif(
  const struct bmp_peer_map_key key, const byte *tx_msg,
  const size_t tx_msg_size, void *bmp_)
{
  struct bmp_proto *p = bmp_;
  ASSERT(p->station_connected);

  const struct bmp_peer_map_entry *map_rx_msg = bmp_peer_map_get(&p->peer_open_msg.rx_msg, key);
  IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    map_rx_msg,
    "Processing TX BGP OPEN MSG but there is not corresponding received MSG"
  );

  const struct bmp_peer_map_entry *map_bgp_proto = bmp_peer_map_get(&p->bgp_peers, key);
  IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    map_bgp_proto,
    "There is not BGP proto related with stored TX/RX OPEN MSG"
  );

  const struct bgp_proto *bgp;
  memcpy(&bgp, map_bgp_proto->data.buf, sizeof (bgp));
  if (bgp->p.proto_state == PS_UP)
  {
    bmp_send_peer_up_notif_msg(p, bgp, tx_msg, tx_msg_size,
			       map_rx_msg->data.buf, map_rx_msg->data.buf_size);
  }
}

static void
bmp_peer_up(const struct bgp_proto *bgp)
{
  struct bgp_channel *c;
  WALK_LIST(c, bgp->p.channels)
  {
    bmp_route_monitor_pre_policy_table_in_snapshot((struct channel *) c);
  }
}

static const struct birdsock *
bmp_get_birdsock(const struct bgp_proto *bgp)
{
  if (bgp->conn && bgp->conn->sk)
  {
    return bgp->conn->sk;
  }

  return NULL;
}

static const struct birdsock *
bmp_get_birdsock_ext(const struct bgp_proto *bgp)
{
  const struct birdsock *sk = bmp_get_birdsock(bgp);

  if (sk != NULL)
  {
    return sk;
  }

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
  {
    return bgp->conn->remote_caps;
  }

  return NULL;
}

static const struct bgp_caps *
bmp_get_bgp_remote_caps_ext(const struct bgp_proto *bgp)
{
  const struct bgp_caps *remote_caps = bmp_get_bgp_remote_caps(bgp);
  if (remote_caps != NULL)
  {
    return remote_caps;
  }

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
  const byte* tx_data, const size_t tx_data_size,
  const byte* rx_data, const size_t rx_data_size)
{
  ASSERT(p->station_connected);

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

  bmp_peer_up(bgp);
}

void
bmp_put_sent_bgp_open_msg(const struct bgp_proto *bgp, const byte* pkt,
  const size_t pkt_size)
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  struct bmp_peer_map_key key = bmp_peer_map_key_create(bgp->remote_ip,
                                  bgp->remote_as);
  const struct bmp_peer_map_entry *map_entry
    = bmp_peer_map_get(&p->peer_open_msg.rx_msg, key);
  if (!map_entry || !p->started)
  {
    bmp_peer_map_insert(&p->peer_open_msg.tx_msg, key, pkt, pkt_size);

    if (!map_entry)
    {
      bmp_peer_map_insert(&p->bgp_peers, key, (const byte *) &bgp, sizeof (bgp));
    }

    return;
  }

  bmp_send_peer_up_notif_msg(p, bgp, pkt, pkt_size, map_entry->data.buf,
			     map_entry->data.buf_size);
}

void
bmp_put_recv_bgp_open_msg(const struct bgp_proto *bgp, const byte* pkt,
  const size_t pkt_size)
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  struct bmp_peer_map_key key
    = bmp_peer_map_key_create(bgp->remote_ip, bgp->remote_as);
  const struct bmp_peer_map_entry *map_data
    = bmp_peer_map_get(&p->peer_open_msg.tx_msg, key);
  if (!map_data || !p->started)
  {
    bmp_peer_map_insert(&p->peer_open_msg.rx_msg, key, pkt, pkt_size);

    if (!map_data)
    {
      bmp_peer_map_insert(&p->bgp_peers, key, (const byte *) &bgp, sizeof (bgp));
    }

    return;
  }

  bmp_send_peer_up_notif_msg(p, bgp, map_data->data.buf, map_data->data.buf_size,
			     pkt, pkt_size);
}

void
bmp_route_monitor_update_in_pre_begin()
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  if (p->monitoring_rib.in_pre_policy == false)
  {
    return;
  }

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    !p->started,
    "BMP instance not started yet"
  );

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    !EMPTY_LIST(p->rt_table_in_pre_policy.update_msg_queue),
    "Previous BMP route monitoring update not finished yet"
  );

  gettimeofday(&p->rt_table_in_pre_policy.update_begin_time,NULL);
  init_list(&p->rt_table_in_pre_policy.update_msg_queue);
  p->rt_table_in_pre_policy.update_msg_size = 0;
  p->rt_table_in_pre_policy.update_in_progress = true;
}

void
bmp_route_monitor_put_update_in_pre_msg(const byte *data, const size_t data_size)
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  if (p->monitoring_rib.in_pre_policy == false)
  {
    return;
  }

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    !p->started,
    "BMP instance not started yet"
  );

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    !p->rt_table_in_pre_policy.update_in_progress,
    "BMP route monitoring update not started yet"
  );

  struct bmp_data_node *upd_msg = mb_alloc(p->update_msg_mem_pool,
                               sizeof (struct bmp_data_node));
  upd_msg->data = mb_alloc(p->update_msg_mem_pool, data_size);
  memcpy(upd_msg->data, data, data_size);
  upd_msg->data_size = data_size;
  p->rt_table_in_pre_policy.update_msg_size += data_size;
  add_tail(&p->rt_table_in_pre_policy.update_msg_queue, &upd_msg->n);
}

void
bmp_route_monitor_update_in_pre_commit(const struct bgp_proto *bgp)
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  if (p->monitoring_rib.in_pre_policy == false)
  {
    return;
  }

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    (!p->started || EMPTY_LIST(p->rt_table_in_pre_policy.update_msg_queue)),
    "BMP route monitoring update not started yet"
  );

  const struct birdsock *sk = bmp_get_birdsock(bgp);
  IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    sk,
    "Failed to get bird socket from BGP proto"
  );

  const struct bgp_caps *remote_caps = bmp_get_bgp_remote_caps(bgp);
  IF_PTR_IS_NULL_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    remote_caps,
    "Failed to get remote capabilities from BGP proto"
  );

  bool is_global_instance_peer = bmp_is_peer_global_instance(bgp);
  buffer payload
    = bmp_buffer_alloc(p->buffer_mpool,
        p->rt_table_in_pre_policy.update_msg_size + DEFAULT_MEM_BLOCK_SIZE);

  buffer update_msgs
    = bmp_buffer_alloc(p->buffer_mpool,
        p->rt_table_in_pre_policy.update_msg_size);

  struct bmp_data_node *data;
  WALK_LIST(data, p->rt_table_in_pre_policy.update_msg_queue)
  {
    bmp_put_data(&update_msgs, data->data, data->data_size);
    bmp_route_monitor_msg_serialize(&payload,
      is_global_instance_peer, true /* TODO: Hardcoded pre-policy Adj-Rib-In */,
      bgp->conn->received_as, bgp->remote_id, remote_caps->as4_support,
      sk->daddr, bmp_buffer_data(&update_msgs), bmp_buffer_pos(&update_msgs),
      p->rt_table_in_pre_policy.update_begin_time.tv_sec,
      p->rt_table_in_pre_policy.update_begin_time.tv_usec);

    bmp_schedule_tx_packet(p, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));

    bmp_buffer_flush(&payload);
    bmp_buffer_flush(&update_msgs);
  }

  bmp_buffer_free(&payload);
  bmp_buffer_free(&update_msgs);
}

void
bmp_route_monitor_update_in_pre_end()
{
  struct bmp_proto *p = g_bmp;

  if (!p)
  {
    return;
  }

  if (p->monitoring_rib.in_pre_policy == false)
  {
    return;
  }

  IF_COND_TRUE_PRINT_ERR_MSG_AND_RETURN_OPT_VAL(
    (!p->started || EMPTY_LIST(p->rt_table_in_pre_policy.update_msg_queue)),
    "BMP route monitoring update not started yet"
  );

  struct bmp_data_node *upd_msg;
  struct bmp_data_node *upd_msg_next;
  WALK_LIST_DELSAFE(upd_msg, upd_msg_next, p->rt_table_in_pre_policy.update_msg_queue)
  {
    mb_free(upd_msg->data);
    rem_node((node *) upd_msg);
    mb_free(upd_msg);
  }
}

static void
bmp_route_monitor_pre_policy_table_in_snapshot(struct channel *C)
{
  struct bmp_proto *p = g_bmp;

  if (p->monitoring_rib.in_pre_policy == false)
  {
    return;
  }

  struct rtable *tab = C->in_table;
  if (!tab)
  {
    return;
  }

  size_t cnt = 0;
  struct proto *P;
  struct fib_iterator fit;
  memset(&fit, 0x00, sizeof (fit));
  FIB_ITERATE_INIT(&fit, &tab->fib);
  FIB_ITERATE_START(&tab->fib, &fit, net, n)
  {
    P = n->routes->sender->proto;
    if (P->proto->class != PROTOCOL_BGP)
    {
      continue;
    }

    bmp_route_monitor_update_in_pre_begin();

    rte *e;
    for (e = n->routes; e; e = e->next)
    {
      bgp_rte_update_in_notify(C, n->n.addr, e, e->src);
    }

    bmp_route_monitor_update_in_pre_commit((struct bgp_proto *) P);
    bmp_route_monitor_update_in_pre_end();
    ++cnt;
  }
  FIB_ITERATE_END;

  if (cnt > 0)
  {
    bmp_route_monitor_update_in_pre_begin();
    byte rx_end_payload[DEFAULT_MEM_BLOCK_SIZE];
    byte *pos
      = bgp_create_end_mark((struct bgp_channel *) C, rx_end_payload
                                                        + BGP_HEADER_LENGTH);
    memset(rx_end_payload + BGP_MSG_HDR_MARKER_POS, 0xff,
             BGP_MSG_HDR_MARKER_SIZE); // BGP UPDATE MSG marker
    put_u16(rx_end_payload + BGP_MSG_HDR_LENGTH_POS, pos - rx_end_payload);
    put_u8(rx_end_payload + BGP_MSG_HDR_TYPE_POS, PKT_UPDATE);
    bmp_route_monitor_put_update_in_pre_msg(rx_end_payload, pos - rx_end_payload);
    bmp_route_monitor_update_in_pre_commit((struct bgp_proto *) C->proto);
    bmp_route_monitor_update_in_pre_end();
  }
}

static void
bmp_send_peer_down_notif_msg(struct bmp_proto *p, const struct bgp_proto *bgp,
  const byte* data, const size_t data_size)
{
  ASSERT(p->station_connected);

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

void
bmp_peer_down(const struct bgp_proto *bgp, const int err_class, const byte *pkt,
  size_t pkt_size)
{
  struct bmp_proto *p = g_bmp;

  if (!p || !p->started)
  {
    return;
  }

  struct bmp_peer_map_key key
    = bmp_peer_map_key_create(bgp->remote_ip, bgp->remote_as);
  if (!bmp_peer_map_get(&p->bgp_peers, key))
  {
    return;
  }

  bmp_peer_map_remove(&p->peer_open_msg.tx_msg, key);
  bmp_peer_map_remove(&p->peer_open_msg.rx_msg, key);
  bmp_peer_map_remove(&p->bgp_peers, key);
  const size_t missing_bgp_hdr_size = BGP_MSG_HDR_MARKER_SIZE
                                        + BGP_MSG_HDR_LENGTH_SIZE
                                        + BGP_MSG_HDR_TYPE_SIZE;
  buffer payload
    = bmp_buffer_alloc(p->buffer_mpool, pkt_size + missing_bgp_hdr_size + 1);
  if (pkt != NULL && pkt_size > 0)
  {
    byte marker[BGP_MSG_HDR_MARKER_SIZE];
    memset(marker, 0xff, BGP_MSG_HDR_MARKER_SIZE); // NOTIF MSG marker
    if (!memcmp(pkt, marker, BGP_MSG_HDR_MARKER_SIZE))
    {
      // So it is received BGP PDU
      bmp_put_u8(&payload, BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION);
      bmp_put_data(&payload, pkt, pkt_size);
    }
    else
    {
      bmp_put_u8(&payload, BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION);
      bmp_put_data(&payload, marker, BGP_MSG_HDR_MARKER_SIZE);
      bmp_put_u16(&payload, pkt_size);
      bmp_put_u8(&payload, PKT_NOTIFICATION);
      bmp_put_data(&payload, pkt, pkt_size);
    }
  }
  else
  {
    // TODO: Handle De-configured Peer Down Reason Code
    if (err_class == BE_SOCKET || err_class == BE_MISC)
    {
      bmp_put_u8(&payload, BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION);
    }
    else
    {
      bmp_put_u8(&payload, BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION);
      // TODO: Fill in with appropriate FSM event code
      bmp_put_u16(&payload, 0x00); // no relevant Event code is defined
    }
  }

  bmp_send_peer_down_notif_msg(p, bgp, bmp_buffer_data(&payload), bmp_buffer_pos(&payload));

  bmp_buffer_free(&payload);
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

static void
bmp_station_connected(struct birdsock *sk)
{
  struct bmp_proto *p = (void *) sk->data;

  sk->tx_hook = bmp_tx;
  p->station_connected = true;

  bmp_startup(p);

  bmp_peer_map_walk(&p->peer_open_msg.tx_msg,
		    bmp_peer_map_walk_tx_open_msg_and_send_peer_up_notif, p);
  bmp_peer_map_flush(&p->peer_open_msg.tx_msg);
  bmp_peer_map_flush(&p->peer_open_msg.rx_msg);
}

static inline void
bmp_setup_socket(struct bmp_proto *p)
{
  sock *sk = sk_new(p->tx_mem_pool);
  sk->type = SK_TCP_ACTIVE;
  sk->ttl = IP4_MAX_TTL;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->tbsize = BGP_TX_BUFFER_EXT_SIZE;
  sk->tx_hook = bmp_station_connected;

  p->sk = sk;
  sk->data = p;
}

/** Configuration handle section **/
static struct proto *
bmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct bmp_proto *p = (void *) P;
  struct bmp_config *cf = (void *) CF;

  p->cf = cf;
  p->station_ip = cf->station_ip;
  p->station_port = cf->station_port;
  strcpy(p->sys_descr, cf->sys_descr);
  strcpy(p->sys_name, cf->sys_name);
  p->monitoring_rib.in_pre_policy = cf->monitoring_rib_in_pre_policy;
  p->monitoring_rib.in_post_policy = cf->monitoring_rib_in_post_policy;
  p->monitoring_rib.local = cf->monitoring_rib_local;

  return P;
}

static int
bmp_start(struct proto *P)
{
  struct bmp_proto *p = (void *) P;

  log(L_DEBUG "Init BMP");

  p->buffer_mpool = rp_new(P->pool, "BMP Buffer");
  p->map_mem_pool = rp_new(P->pool, "BMP Map");
  p->tx_mem_pool = rp_new(P->pool, "BMP Tx");
  p->update_msg_mem_pool = rp_new(P->pool, "BMP Update");
  p->tx_ev = ev_new_init(p->tx_mem_pool, bmp_fire_tx, p);

  bmp_peer_map_init(&p->peer_open_msg.tx_msg, p->map_mem_pool);
  bmp_peer_map_init(&p->peer_open_msg.rx_msg, p->map_mem_pool);
  bmp_peer_map_init(&p->bgp_peers, p->map_mem_pool);

  init_list(&p->tx_queue);
  init_list(&p->rt_table_in_pre_policy.update_msg_queue);
  p->station_connected = false;
  p->started = false;
  p->connect_retry_timer = NULL;

  bmp_setup_socket(p);
  bmp_open(P);

  g_bmp = p;

  return PS_UP;
}

static int
bmp_shutdown(struct proto *P)
{
  struct bmp_proto *p = (void *) P;
  bmp_send_termination_msg(p, BMP_TERM_REASON_ADM);

  p->station_connected = false;
  p->started = false;

  g_bmp = NULL;

  return PS_DOWN;
}

static int
bmp_reconfigure(struct proto *P UNUSED, struct proto_config *CF UNUSED)
{
  log(L_WARN "Reconfiguring BMP is not supported");
  return PS_UP;
}

struct protocol proto_bmp = {
  .name = "BMP",
  .template = "bmp%d",
  .class = PROTOCOL_BMP,
  .proto_size = sizeof(struct bmp_proto),
  .config_size = sizeof(struct bmp_config),
  .init = bmp_init,
  .start = bmp_start,
  .shutdown = bmp_shutdown,
  .reconfigure = bmp_reconfigure,
};

void
bmp_build(void)
{
  proto_build(&proto_bmp);
}

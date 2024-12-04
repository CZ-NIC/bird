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
#include "sysdep/unix/io-loop.h"
#include "lib/event.h"
#include "lib/ip.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/unaligned.h"
#include "lib/tlists.h"
#include "nest/iface.h"
#include "nest/route.h"

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

enum bmp_peer_type {
  BMP_PEER_TYPE_GLOBAL_INSTANCE = 0,
  BMP_PEER_TYPE_RD_INSTANCE = 1,
  BMP_PEER_TYPE_LOCAL_INSTANCE = 2
};

#define BMP_PEER_FLAG_V_IPV6		(1 << 7)
#define BMP_PEER_FLAG_L_POLICY		(1 << 6)
#define BMP_PEER_FLAG_A_NO_AS4		(1 << 5)

struct bmp_peer_hdr_info {
  ip_addr address;
  u32 as;
  u32 id;
  bool global;
  bool policy;
  bool no_as4;
  btime timestamp;
};

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

struct bmp_peer_down_info {
  u8 reason;
  u8 fsm_code;
  u8 err_code;
  u8 err_subcode;
  const byte *data;
  int length;
};

/* BMP Termination Message [RFC 7854 - Section 4.5] */
enum bmp_term_info_type {
  BMP_TERM_INFO_STRING = 0, // The Information field contains string
  BMP_TERM_INFO_REASON = 1, // The Information field contains 2-byte reason code
};

// 2-byte code in the Information field
enum bmp_term_reason {
  BMP_TERM_REASON_ADM = 0,  // Session administratively closed
  BMP_TERM_REASON_UNK = 1,  // Unspecified reason
  BMP_TERM_REASON_OOR = 2,  // Out of resources
  BMP_TERM_REASON_DUP = 3,  // Redundant connection
  BMP_TERM_REASON_PERM = 4, // Session permanently administratively closed
};

// Initial delay for connection to the BMP collector
#define CONNECT_INIT_TIME (200 MS)

// Timeout for connection to the BMP collector retry
#define CONNECT_RETRY_TIME (10 S)

#define IP4_MAX_TTL 255


#define bmp_buffer_need(b, sz)  ASSERT_DIE((b)->pos + (sz) <= (b)->end)

// Idea for following macros has been taken from |proto/mrt/mrt.c|
#define BMP_DEFINE_PUT_FUNC(S, T)                               \
  static inline void                                            \
  bmp_put_##S(buffer *b, const T x)                             \
  {                                                             \
    bmp_buffer_need(b, sizeof(T));			   \
    put_##S(b->pos, x);                                    \
    b->pos += sizeof(T);                                   \
  }

BMP_DEFINE_PUT_FUNC(u8, u8)
BMP_DEFINE_PUT_FUNC(u16, u16)
BMP_DEFINE_PUT_FUNC(u32, u32)
BMP_DEFINE_PUT_FUNC(u64, u64)
BMP_DEFINE_PUT_FUNC(ip4, ip4_addr)
BMP_DEFINE_PUT_FUNC(ip6, ip6_addr)

static inline void
bmp_put_data(buffer *b, const void *src, const size_t len)
{
  ASSERT_DIE(b->pos + len <= b->end);
  memcpy(b->pos, src, len);
  b->pos += len;
}

static inline buffer
bmp_default_buffer(struct bmp_proto *p)
{
  return (buffer) {
    .start = p->msgbuf,
    .pos = p->msgbuf,
    .end = p->msgbuf + sizeof p->msgbuf,
  };
}

static const struct ea_class *bgp_next_hop_ea_class = NULL;

static void bmp_connected(struct birdsock *sk);
static void bmp_sock_err(sock *sk, int err);
static void bmp_close_socket(struct bmp_proto *p);
static void bmp_check_routes(void *bt_);
static void bmp_feed_end(struct rt_export_request *req);
static void bmp_process_proto_state_change(struct bmp_proto *p, struct lfjour_item *last_up);
static void bmp_proto_state_changed(void *_p);

static void
bmp_send_peer_up_notif_msg(struct bmp_proto *p, ea_list *bgp,
    const adata *tx_data, const adata *rx_data, struct bgp_conn_sk_ad *sk);

static void bmp_route_monitor_end_of_rib(struct bmp_proto *p, struct bmp_stream *bs);

// Stores TX data
struct bmp_tx_buffer {
  struct bmp_tx_buffer *next;
  byte *pos;
  byte data[];
};

#define bmp_tx_remains(b) (((byte *) (b) + page_size) - (b)->pos)

/* A dummy resource to accurately show memory pages allocated for pending TX */
struct bmp_tx_resource {
  resource r;
  struct bmp_proto *p;
};

static void
bmp_tx_resource_free(resource *r UNUSED) {}

static void
bmp_tx_resource_dump(resource *r UNUSED, uint indent UNUSED) {}

static struct resmem
bmp_tx_resource_memsize(resource *r)
{
  struct bmp_proto *p = SKIP_BACK(struct bmp_tx_resource, r, r)->p;

  return (struct resmem) {
    .effective = p->tx_pending_count * page_size,
    .overhead = sizeof(struct bmp_tx_resource),
  };
}

static struct resclass bmp_tx_resource_class = {
  .name = "BMP TX buffers",
  .size = sizeof(struct bmp_tx_resource),
  .free = bmp_tx_resource_free,
  .dump = bmp_tx_resource_dump,
  .memsize = bmp_tx_resource_memsize,
};

static void
bmp_put_common_hdr(buffer *stream, enum bmp_message_type type, u32 length)
{
  bmp_buffer_need(stream, BMP_COMMON_HDR_SIZE);
  bmp_put_u8(stream, BMP_VERSION_3);
  bmp_put_u32(stream, length);
  bmp_put_u8(stream, type);
}

static void
bmp_fix_common_hdr(buffer *stream)
{
  uint length = stream->pos - stream->start;
  put_u32(stream->start + 1, length);
}

static void
bmp_put_info_tlv(buffer *stream, enum bmp_info_tlv_type type, const char *str)
{
  size_t str_len = strlen(str);
  str_len = MIN(str_len, MIB_II_STR_LEN);

  bmp_buffer_need(stream, 4 + str_len);
  bmp_put_u16(stream, type);
  bmp_put_u16(stream, str_len);
  bmp_put_data(stream, str, str_len);
}

// Serializes BMP Initiation message header [RFC 7854 - Section 4.3]
static void
bmp_init_msg_serialize(buffer *stream, const char *sys_descr, const char *sys_name)
{
  bmp_put_common_hdr(stream, BMP_INIT_MSG, 0);
  bmp_put_info_tlv(stream, BMP_INFO_TLV_TYPE_SYS_DESCR, sys_descr);
  bmp_put_info_tlv(stream, BMP_INFO_TLV_TYPE_SYS_NAME, sys_name);
  bmp_fix_common_hdr(stream);
}

static void
bmp_schedule_tx_packet(struct bmp_proto *p, buffer *msg)
{
  const byte *payload = msg->start;
  size_t size = msg->pos - msg->start;

  ASSERT(p->started);

  while (size)
  {
    if (!p->tx_last || !bmp_tx_remains(p->tx_last))
    {
      if (p->tx_pending_count >= p->tx_pending_limit)
	return ev_send_loop(p->p.loop, p->tx_overflow_event);

      p->tx_pending_count++;

      struct bmp_tx_buffer *btb = alloc_page();
      btb->pos = btb->data;
      btb->next = NULL;

      if (p->tx_last)
      {
	ASSERT_DIE(!p->tx_last->next);
	p->tx_last->next = btb;
      }
      else
	ASSERT_DIE(p->tx_pending_count == 1);

      p->tx_last = btb;

      if (!p->tx_pending)
	p->tx_pending = btb;
    }

    size_t cpylen = bmp_tx_remains(p->tx_last);
    if (size < cpylen)
      cpylen = size;

    memcpy(p->tx_last->pos, payload, cpylen);
    p->tx_last->pos += cpylen;

    payload += cpylen;
    size -= cpylen;
  }

  if (!p->sk->tbuf && !ev_active(p->tx_ev))
    ev_send_loop(p->p.loop, p->tx_ev);
}

static void
bmp_tx_buffer_free(struct bmp_proto *p, struct bmp_tx_buffer *btb)
{
  if (btb == p->tx_last)
  {
    p->tx_last = NULL;
    ASSERT_DIE(!p->tx_pending_count);
  }

  free_page(btb);
}

static void
bmp_fire_tx(void *p_)
{
  struct bmp_proto *p = p_;

  if (!p->started)
    return;

  int cnt = 0;
  for (struct bmp_tx_buffer *btb; btb = p->tx_pending; )
  {
    ASSERT_DIE(!p->sk->tbuf);

    p->sk->tbuf = btb->data;
    u64 sz = btb->pos - btb->data;

    p->tx_sent += sz;
    p->tx_sent_total += sz;

    if (p->tx_pending == p->tx_last)
      p->tx_last = NULL;

    p->tx_pending = btb->next;
    p->tx_pending_count--;

    if (sk_send(p->sk, sz) <= 0)
      return;

    p->sk->tbuf = NULL;
    bmp_tx_buffer_free(p, btb);

    if (cnt++ > 1024)
    {
      if (!ev_active(p->tx_ev))
        ev_send_loop(p->p.loop, p->tx_ev);
      return;
    }
  }
}

static void
bmp_tx(struct birdsock *sk)
{
  struct bmp_proto *p = sk->data;

  struct bmp_tx_buffer *btb = SKIP_BACK(struct bmp_tx_buffer, data[0], sk->tbuf);
  bmp_tx_buffer_free(p, btb);

  sk->tbuf = NULL;

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
 * bmp_put_per_peer_hdr - serializes Per-Peer Header
 *
 * @is_post_policy: indicate the message reflects the post-policy Adj-RIB-In
 * @peer_addr: the remote IP address associated with the TCP session
 * @peer_as: the Autonomous System number of the peer
 * @peer_bgp_id: the BGP Identifier of the peer
 * @ts_sec: the time in seconds when the encapsulated routes were received
 * @ts_usec: the time in microseconds when the encapsulated routes were received
 */
static void
bmp_put_per_peer_hdr(buffer *stream, const struct bmp_peer_hdr_info *peer)
{
  // TODO: ATM we do not support BMP_PEER_TYPE_RD_INSTANCE
  u8 peer_type = peer->global ?
    BMP_PEER_TYPE_GLOBAL_INSTANCE :
    BMP_PEER_TYPE_LOCAL_INSTANCE;

  u8 peer_flags =
    (ipa_is_ip6(peer->address) ? BMP_PEER_FLAG_V_IPV6 : 0) |
    (peer->policy ? BMP_PEER_FLAG_L_POLICY : 0) |
    (peer->no_as4 ? BMP_PEER_FLAG_A_NO_AS4 : 0);

  u32 ts_sec = peer->timestamp TO_S;
  u32 ts_usec = peer->timestamp - (ts_sec S);

  bmp_buffer_need(stream, BMP_PER_PEER_HDR_SIZE);
  bmp_put_u8(stream, peer_type);
  bmp_put_u8(stream, peer_flags);
  bmp_put_u64(stream, 0); // Not supported peer distinguisher
  bmp_put_ipa(stream, peer->address);
  bmp_put_u32(stream, peer->as);
  bmp_put_u32(stream, peer->id);
  bmp_put_u32(stream, ts_sec);
  bmp_put_u32(stream, ts_usec);
}

static void
bmp_peer_up_notif_msg_serialize(buffer *stream, const struct bmp_peer_hdr_info *peer,
				const ip_addr local_addr, const u16 local_port, const u16 remote_port,
				const adata *sent_msg, const adata *recv_msg)
{
  bmp_put_common_hdr(stream, BMP_PEER_UP_NOTIF, 0);
  bmp_put_per_peer_hdr(stream, peer);

  bmp_buffer_need(stream, BMP_PEER_UP_NOTIF_MSG_FIX_SIZE);
  bmp_put_ipa(stream, local_addr);
  bmp_put_u16(stream, local_port);
  bmp_put_u16(stream, remote_port);
  bmp_put_bgp_hdr(stream, PKT_OPEN, BGP_HEADER_LENGTH + sent_msg->length);
  bmp_put_data(stream, sent_msg->data, sent_msg->length);
  bmp_put_bgp_hdr(stream, PKT_OPEN, BGP_HEADER_LENGTH + recv_msg->length);
  bmp_put_data(stream, recv_msg->data, recv_msg->length);

  bmp_fix_common_hdr(stream);
}

static void
bmp_peer_down_notif_msg_serialize(buffer *stream, const struct bmp_peer_hdr_info *peer,
				  const struct bmp_peer_down_info *info)
{
  bmp_put_common_hdr(stream, BMP_PEER_DOWN_NOTIF, 0);
  bmp_put_per_peer_hdr(stream, peer);

  bmp_put_u8(stream, info->reason);

  switch (info->reason)
  {
  case BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION:
  case BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION:;
    uint bgp_msg_length = BGP_HEADER_LENGTH + 2 + info->length;
    bmp_buffer_need(stream, bgp_msg_length);
    bmp_put_bgp_hdr(stream, PKT_NOTIFICATION, bgp_msg_length);
    bmp_put_u8(stream, info->err_code);
    bmp_put_u8(stream, info->err_subcode);
    bmp_put_data(stream, info->data, info->length);
    break;

  case BMP_PEER_DOWN_REASON_LOCAL_NO_NOTIFICATION:
    bmp_put_u16(stream, info->fsm_code);
    break;
  }

  bmp_fix_common_hdr(stream);
}


/*
 *	BMP tables
 */

static struct bmp_table *
bmp_find_table(struct bmp_proto *p, rtable *tab)
{
  return HASH_FIND(p->table_map, HASH_TABLE, tab);
}

const struct channel_class channel_bmp = {
  .channel_size =	sizeof(struct channel),
  .config_size =	sizeof(struct channel_config),
  /*.init =		
  .start =		
  .shutdown =		
  .cleanup =		
  .reconfigure =	*/
};

static struct bmp_table *
bmp_add_table(struct bmp_proto *p, rtable *tab)
{
  struct bmp_table *bt = mb_allocz(p->p.pool, sizeof(struct bmp_table));
  bt->table = tab;
  bt->p = p;
  rt_lock_table(bt->table);

  HASH_INSERT(p->table_map, HASH_TABLE, bt);

  bt->event.data = bt;

  bt->event.hook = bmp_check_routes;
  bt->out_req = (struct rt_export_request) {
    .name = mb_sprintf(p->p.pool, "%s.export", p->p.name),
    .r = (struct lfjour_recipient) {
      .target = proto_event_list(&p->p),
      .event = &bt->event,
    },
    .pool = p->p.pool,
    .trace_routes = p->p.debug,
    //.dump = channel_dump_export_req, TODO: this will crash on `dump tables` from CLI
    .fed = bmp_feed_end,
  };

  rt_export_subscribe(tab, all, &bt->out_req);
  return bt;
}


static void
bmp_remove_table(struct bmp_proto *p, struct bmp_table *bt)
{
  if (bt->channel)
  {
    channel_set_state(bt->channel, CS_STOP);
    channel_set_state(bt->channel, CS_DOWN);
  }
    rt_export_unsubscribe(all, &bt->out_req);

  HASH_REMOVE(p->table_map, HASH_TABLE, bt);

  rt_unlock_table(bt->table);
  bt->table = NULL;

  mb_free(bt);
}

static inline void bmp_lock_table(struct bmp_proto *p UNUSED, struct bmp_table *bt)
{ bt->uc++; }

struct bmp_table *
bmp_get_table(struct bmp_proto *p, rtable *tab)
{
  struct bmp_table *bt = bmp_find_table(p, tab);
  if (bt)
  {
   while (true) {
      atomic_int i = bt->uc;
      if (i == 0)
      {
        struct bmp_table *new = bmp_add_table(p, tab);
        bmp_lock_table(p, new);
        return new;
      }
      if (atomic_compare_exchange_strong_explicit(&bt->uc, &i, i+1, memory_order_acq_rel, memory_order_relaxed))
        return bt;
    }
  }
  struct bmp_table *new = bmp_add_table(p, tab);
  bmp_lock_table(p, new);
  return new;
}

static inline void bmp_unlock_table(struct bmp_proto *p, struct bmp_table *bt)
{ atomic_int i = 1;
  if (atomic_compare_exchange_strong_explicit(&bt->uc, &i, 0, memory_order_acq_rel, memory_order_relaxed))
    bmp_remove_table(p, bt);
  else
    bt->uc--;
}


/*
 *	BMP streams
 */

static inline u32 bmp_stream_key(u32 afi, bool policy)
{ return afi ^ (policy ? BMP_STREAM_KEY_POLICY : 0); }

static inline bool bmp_stream_policy(struct bmp_stream *bs)
{ return !!(bs->key & BMP_STREAM_KEY_POLICY); }

static struct bmp_stream *
bmp_find_stream(struct bmp_proto *p, const struct bgp_proto *bgp, u32 afi, bool policy)
{
  ea_list *bgp_attr = proto_get_state(bgp->p.id);
  struct bmp_stream *s = HASH_FIND(p->stream_map, HASH_STREAM, bgp_attr, bmp_stream_key(afi, policy));

  while (s == NULL)
  {
    struct lfjour_item *li = lfjour_get(&p->proto_state_reader);
    if (!li)
      return NULL;

    bmp_process_proto_state_change(p, li);
    s = HASH_FIND(p->stream_map, HASH_STREAM, bgp_attr, bmp_stream_key(afi, policy));
  }
  return s;
}

static struct bmp_stream *
bmp_add_stream(struct bmp_proto *p, struct bmp_peer *bp, u32 afi, bool policy, rtable *tab, ea_list *sender, int in_pre_policy)
{
  struct bmp_stream *bs = mb_allocz(p->p.pool, sizeof(struct bmp_stream));
  bs->bgp = bp->bgp;
  bs->key = bmp_stream_key(afi, policy);

  add_tail(&bp->streams, &bs->n);
  HASH_INSERT(p->stream_map, HASH_STREAM, bs);

  bs->table = bmp_get_table(p, tab);

  bs->sender = sender;
  bs->sync = false;
  bs->in_pre_policy = in_pre_policy;

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
bmp_find_peer(struct bmp_proto *p, ea_list *bgp_attr)
{
  return HASH_FIND(p->peer_map, HASH_PEER, bgp_attr);
}

static struct bmp_peer *
bmp_add_peer(struct bmp_proto *p, ea_list *bgp_attr)
{
  struct bmp_peer *bp;
  if (DG_IS_LOCKED(p->p.pool->domain))
    bp = mb_allocz(p->p.pool, sizeof(struct bmp_peer));
  else
  {
    DG_LOCK(p->p.pool->domain);
    bp = mb_allocz(p->p.pool, sizeof(struct bmp_peer));
    DG_UNLOCK(p->p.pool->domain);
  }
  bp->bgp = bgp_attr;

  init_list(&bp->streams);

  HASH_INSERT(p->peer_map, HASH_PEER, bp);

  const adata *channels_adata = ea_get_adata(bgp_attr, &ea_proto_channel_list);
  int id_count = channels_adata->length / sizeof(u32);
  u32 *chann_ids = (u32 *) channels_adata->data;

  for (int i = 0; i < id_count; i++)
  {
    ea_list *chan_attr;
    PST_LOCKED(ts)
      chan_attr = ts->channels[chann_ids[i]];

    if (chan_attr == NULL)
      continue;

    rtable *ch_table = (rtable *) ea_get_ptr(chan_attr, &ea_rtable, 0);
    int in_keep = ea_get_int(chan_attr, &ea_in_keep, 0);

    if (p->monitoring_rib.in_pre_policy && ch_table)
    {
      if (in_keep == RIK_PREFILTER)
        bmp_add_stream(p, bp, ea_get_int(chan_attr, &ea_bgp_afi, 0), false, ch_table, chan_attr, 1);
      else
        log(L_WARN "%s: Failed to request pre-policy for %s.%s, import table disabled",
	    p->p.name,
	    ea_get_adata(bgp_attr, &ea_name)->data,
	    ea_get_adata(chan_attr, &ea_name)->data);
    }

    if (p->monitoring_rib.in_post_policy && ch_table)
      bmp_add_stream(p, bp, ea_get_int(chan_attr, &ea_bgp_afi, 0), true, ch_table, chan_attr, 0);
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
bmp_peer_up_(struct bmp_proto *p, ea_list *bgp_attr, bool sync,
	     const adata *tx_open_msg, const adata *rx_open_msg,
	     struct bgp_conn_sk_ad *sk)
{
  if (!p->started)
    return;

  struct bmp_peer *bp = bmp_find_peer(p, bgp_attr);
  if (bp)
    return;

  const char *name = ea_get_adata(bgp_attr, &ea_name)->data;
  TRACE(D_STATES, "Peer up for %s", name);

  bp = bmp_add_peer(p, bgp_attr);

  bmp_send_peer_up_notif_msg(p, bgp_attr, tx_open_msg, rx_open_msg, sk);

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

static bool
bmp_peer_up_inout(struct bmp_proto *p, ea_list *bgp_attr, bool sync)
{
  int in_state = ea_get_int(bgp_attr, &ea_bgp_in_conn_state, 0);
  int out_state = ea_get_int(bgp_attr, &ea_bgp_out_conn_state, 0);

  if (in_state == BS_ESTABLISHED)
  {
    ASSERT_DIE(out_state != BS_ESTABLISHED);

    const adata *loc_open = ea_get_adata(bgp_attr, &ea_bgp_in_conn_local_open_msg);
    const adata *rem_open = ea_get_adata(bgp_attr, &ea_bgp_in_conn_remote_open_msg);
    SKIP_BACK_DECLARE(struct bgp_conn_sk_ad, sk, ad, ea_get_adata(bgp_attr, &ea_bgp_in_conn_sk));

    ASSERT_DIE(loc_open && rem_open);
    bmp_peer_up_(p, bgp_attr, sync, loc_open, rem_open, sk);

    return true;
  }

  if (out_state == BS_ESTABLISHED)
  {
    const adata *loc_open = ea_get_adata(bgp_attr, &ea_bgp_out_conn_local_open_msg);
    const adata *rem_open = ea_get_adata(bgp_attr, &ea_bgp_out_conn_remote_open_msg);
    SKIP_BACK_DECLARE(struct bgp_conn_sk_ad, sk, ad, ea_get_adata(bgp_attr, &ea_bgp_out_conn_sk));

    ASSERT_DIE(loc_open && rem_open);
    bmp_peer_up_(p, bgp_attr, sync, loc_open, rem_open, sk);

    return true;
  }

  return false;
}

static bool
bmp_is_peer_global_instance(ea_list *bgp)
{
  int peer_type = ea_get_int(bgp, &ea_bgp_peer_type, 0);
  int local_as = ea_get_int(bgp, &ea_bgp_loc_as, 0);
  int remote_as = ea_get_int(bgp, &ea_bgp_rem_as, 0);

  return (peer_type != BGP_PT_EXTERNAL &&
            peer_type != BGP_PT_INTERNAL)
              ? (local_as != remote_as)
              : (peer_type == BGP_PT_EXTERNAL);
}

static void
bmp_send_peer_up_notif_msg(struct bmp_proto *p, ea_list *bgp,
    const adata *tx_data, const adata *rx_data, struct bgp_conn_sk_ad *sk)
{
  ASSERT(p->started);

  struct bmp_peer_hdr_info peer = {
    .address = ea_get_ip(bgp, &ea_bgp_rem_ip, IPA_NONE),
    .as = ea_get_int(bgp, &ea_bgp_rem_as, 0),
    .id = ea_get_int(bgp, &ea_bgp_rem_id, 0),
    .global = bmp_is_peer_global_instance(bgp),
    .policy = false,		// Hardcoded pre-policy Adj-RIB-In
    .timestamp = 0,		// No timestamp provided
  };

  buffer payload = bmp_default_buffer(p);
  bmp_peer_up_notif_msg_serialize(&payload, &peer, sk->saddr, sk->sport, sk->dport, tx_data, rx_data);
  bmp_schedule_tx_packet(p, &payload);
}

static void
bmp_route_monitor_notify(struct bmp_proto *p, struct bgp_proto *bgp_p, u32 afi, bool policy, const rte *new, ea_list *old)
{
  /* Idempotent update */
  if ((old == new->attrs) || old && new->attrs && ea_same(old, new->attrs))
    return;

  /* No stream, probably flushed already */
  struct bmp_stream *bs = bmp_find_stream(p, bgp_p, afi, policy);
  if (!bs)
    return;

  ea_list *bgp = bs->bgp;
  ea_list *c = bs->sender;

  btime delta_t = new ? current_time() - new->lastmod : 0;

  struct bmp_peer_hdr_info peer = {
    .address = ea_get_ip(bgp, &ea_bgp_rem_ip, IPA_NONE),
    .as = ea_get_int(bgp, &ea_bgp_rem_as, 0),
    .id = ea_get_int(bgp, &ea_bgp_rem_id, 0),
    .global = bmp_is_peer_global_instance(bgp),
    .policy = bmp_stream_policy(bs),
    .timestamp = current_real_time() - delta_t,
  };

  buffer msg = bmp_default_buffer(p);
  bmp_put_common_hdr(&msg, BMP_ROUTE_MONITOR, 0);
  bmp_put_per_peer_hdr(&msg, &peer);

  bmp_buffer_need(&msg, BGP_MAX_EXT_MSG_LENGTH);
  byte *pos = bgp_bmp_encode_rte(c, bgp_p, msg.pos + BGP_HEADER_LENGTH, msg.end, new);
  if (!pos)
  {
    log(L_WARN "%s: Cannot encode update for %N", p->p.name, new->net);
    return;
  }
  bmp_put_bgp_hdr(&msg, PKT_UPDATE, pos - msg.pos);
  msg.pos = pos;

  bmp_fix_common_hdr(&msg);
  bmp_schedule_tx_packet(p, &msg);
}

static void
bmp_route_monitor_end_of_rib(struct bmp_proto *p, struct bmp_stream *bs)
{
  ea_list *bgp = bs->bgp;
  ea_list *c = bs->sender;

  struct bmp_peer_hdr_info peer = {
    .address = ea_get_ip(bgp, &ea_bgp_rem_ip, IPA_NONE),
    .as = ea_get_int(bgp, &ea_bgp_rem_as, 0),
    .id = ea_get_int(bgp, &ea_bgp_rem_id, 0),
    .global = bmp_is_peer_global_instance(bgp),
    .policy = bmp_stream_policy(bs),
    .timestamp = current_real_time(),
  };

  TRACE(D_PACKETS, "Sending END-OF-RIB for %s.%s", ea_get_adata(bgp, &ea_name)->data, ea_get_adata(c, &ea_name)->data);

  buffer msg = bmp_default_buffer(p);
  bmp_put_common_hdr(&msg, BMP_ROUTE_MONITOR, 0);
  bmp_put_per_peer_hdr(&msg, &peer);

  bmp_buffer_need(&msg, BGP_MAX_EXT_MSG_LENGTH);
  byte *pos = bgp_create_end_mark_ea_(c, msg.pos + BGP_HEADER_LENGTH);
  bmp_put_bgp_hdr(&msg, PKT_UPDATE, pos - msg.pos);
  msg.pos = pos;

  bmp_fix_common_hdr(&msg);
  bmp_schedule_tx_packet(p, &msg);
}

static void
bmp_send_peer_down_notif_msg(struct bmp_proto *p, ea_list *bgp,
			     const struct bmp_peer_down_info *info)
{
  ASSERT(p->started);

  int as4_session = ea_get_int(bgp, &ea_bgp_as4_session, 0);
  int in_state = ea_get_int(bgp, &ea_bgp_in_conn_state, 0);
  int out_state = ea_get_int(bgp, &ea_bgp_out_conn_state, 0);
  int in_as4 = ea_get_int(bgp, &ea_bgp_as4_in_conn, 0);
  int out_as4 = ea_get_int(bgp, &ea_bgp_as4_out_conn, 0);

  if (in_state && in_as4)
    as4_session = in_as4;
  else if (out_state && out_as4)
    as4_session = out_as4;

  struct bmp_peer_hdr_info peer = {
    .address = ea_get_ip(bgp, &ea_bgp_rem_ip, IPA_NONE),
    .as = ea_get_int(bgp, &ea_bgp_rem_as, 0),
    .id = ea_get_int(bgp, &ea_bgp_rem_id, 0),
    .global = bmp_is_peer_global_instance(bgp),
    .policy = false,		// Hardcoded pre-policy Adj-RIB-In
    .no_as4 = !as4_session,
    .timestamp = 0,		// No timestamp provided
  };

  buffer payload = bmp_default_buffer(p);
  bmp_peer_down_notif_msg_serialize(&payload, &peer, info);
  bmp_schedule_tx_packet(p, &payload);
}

static void
bmp_peer_down_(struct bmp_proto *p, ea_list *bgp, struct bgp_session_close_ad *bscad)
{
  if (!p->started)
    return;

  struct bmp_peer *bp = bmp_find_peer(p, bgp);
  if (!bp)
    return;

  TRACE(D_STATES, "Peer down for %s", ea_find(bgp, &ea_name)->u.ad->data);

  struct bmp_peer_down_info info = {
    .err_code = bscad->notify_code,
    .err_subcode = bscad->notify_subcode,
    .data = bscad->data,
    .length = bscad->ad.length - sizeof *bscad + sizeof bscad->ad,
  };

  switch (bscad->last_error_class)
  {
  case BE_BGP_RX:
    info.reason = BMP_PEER_DOWN_REASON_REMOTE_BGP_NOTIFICATION;
    break;

  case BE_BGP_TX:
  case BE_AUTO_DOWN:
  case BE_MAN_DOWN:
    info.reason = BMP_PEER_DOWN_REASON_LOCAL_BGP_NOTIFICATION;
    break;

  default:
    info.reason = BMP_PEER_DOWN_REASON_REMOTE_NO_NOTIFICATION;
    info.length = 0;
    break;
  }

  bmp_send_peer_down_notif_msg(p, bgp, &info);

  bmp_remove_peer(p, bp);
}


static void
bmp_send_termination_msg(struct bmp_proto *p, enum bmp_term_reason reason)
{
  buffer stream = bmp_default_buffer(p);

  bmp_put_common_hdr(&stream, BMP_TERM_MSG, 0);
  bmp_buffer_need(&stream, 6);
  bmp_put_u16(&stream, BMP_TERM_INFO_REASON);
  bmp_put_u16(&stream, 2); // Length of the reason
  bmp_put_u16(&stream, reason);
  bmp_fix_common_hdr(&stream);

  if (p->sk->tbuf)
    bmp_tx_buffer_free(p, SKIP_BACK(struct bmp_tx_buffer, data[0], p->sk->tbuf));

  p->sk->tbuf = stream.start;
  if (sk_send(p->sk, stream.pos - stream.start) < 0)
    log(L_WARN "%s: Cannot send BMP termination message", p->p.name);
  p->sk->tbuf = NULL;
}

static void
bmp_split_policy(struct bmp_proto *p, const rte *new, const rte *old)
{
  rte loc = *(new ?: old);

  struct proto *rte_proto = (struct proto*) SKIP_BACK(struct proto, sources, loc.src->owner);
  struct bgp_proto *bgp = (struct bgp_proto *) rte_proto;
  struct bgp_channel *src_ch = SKIP_BACK(struct bgp_channel, c.in_req, loc.sender->req);

  /* Ignore piped routes */
  if (src_ch->c.proto != rte_proto)
    return;

  /* Ignore non-BGP routes */
  if (rte_proto->proto != &proto_bgp)
    return;

  /* Checking the pre policy */
  if (p->monitoring_rib.in_pre_policy)
  {
    /* Compute the pre policy attributes */
    loc.attrs = new ? ea_strip_to(new->attrs, BIT32_ALL(EALS_PREIMPORT)) : NULL;
    ea_list *old_attrs = old ? ea_strip_to(old->attrs, BIT32_ALL(EALS_PREIMPORT)) : NULL;

    bmp_route_monitor_notify(p, bgp, src_ch->afi, false, &loc, old_attrs);
  }

  /* Checking the post policy */
  if (p->monitoring_rib.in_post_policy)
  {
    /* Compute the post policy attributes */
    loc.attrs = new ? ea_normalize(new->attrs, 0) : NULL;
    ea_list *old_attrs = old ? ea_normalize(old->attrs, 0) : NULL;

    bmp_route_monitor_notify(p, bgp, src_ch->afi, true, &loc, old_attrs);
  }
}

static void
bmp_check_routes(void *bt_)
{
  struct bmp_table *bt = (struct bmp_table *)bt_;
  struct bmp_proto *p = bt->p;

  RT_EXPORT_WALK(&bt->out_req, u)
  {
    switch (u->kind)
    {
      case RT_EXPORT_STOP:
	bug("Main table export stopped");

      case RT_EXPORT_FEED:
	/* Send updates one after another */
	for (uint i = 0; i < u->feed->count_routes; i++)
	{
	  rte *new = &u->feed->block[i];
	  if (new->flags & REF_OBSOLETE)
	    break;

	  bmp_split_policy(p, new, NULL);
	}
	break;

      case RT_EXPORT_UPDATE:
	bmp_split_policy(p, u->update->new, u->update->old);
	break;
    }
  }
}

static void
bmp_feed_end(struct rt_export_request *req)
{
  SKIP_BACK_DECLARE(struct bmp_table, bt, out_req, req);

  struct bmp_proto *p = bt->p;

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
  buffer payload = bmp_default_buffer(p);
  bmp_init_msg_serialize(&payload, p->sys_descr, p->sys_name);
  bmp_schedule_tx_packet(p, &payload);

  /* Send Peer Up messages */
  u32 length;
  PST_LOCKED(ts) /* The size of protos field will never decrease, the inconsistency caused by growing is not important */
    length = ts->length_states;

  /* Subscribe to protocol state changes */
  p->proto_state_reader = (struct lfjour_recipient) {
    .event = &p->proto_state_changed,
    .target = proto_event_list(&p->p),
  };

  p->proto_state_changed = (event) {
    .hook = bmp_proto_state_changed,
    .data = p,
  };

  proto_states_subscribe(&p->proto_state_reader);

  /* Load protocol states */
  for (u32 i = 0; i < length; i++)
  {
    ea_list *proto_attr = proto_get_state(i);
    if (proto_attr == NULL)
      continue;

    struct protocol *proto = (struct protocol *) ea_get_ptr(proto_attr, &ea_protocol_type, 0);
    const int state = ea_get_int(proto_attr, &ea_state, 0);

    if (proto != &proto_bgp || state != PS_UP)
      continue;

    bmp_peer_up_inout(p, proto_attr, false);
  }
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
  p->tx_sent = 0;

  TRACE(D_EVENTS, "BMP session closed");

  proto_states_unsubscribe(&p->proto_state_reader);
  ev_postpone(&p->proto_state_changed);

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
  sk->tx_hook = bmp_connected;
  sk->err_hook = bmp_sock_err;

  p->sk = sk;
  sk->data = p;

  TRACE(D_EVENTS, "Connecting to %I port %u", sk->daddr, sk->dport);

  int rc = sk_open(sk, p->p.loop);

  if (rc < 0)
    sk_log_error(sk, p->p.name);

  tm_start_in(p->connect_retry_timer, CONNECT_RETRY_TIME, p->p.loop);
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

/* BMPbmp_startup socket error event - switch from any state to Idle state */
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
  tm_start_in(p->connect_retry_timer, CONNECT_RETRY_TIME, p->p.loop);

  if (p->p.proto_state == PS_UP)
    proto_notify_state(&p->p, PS_START);
}

static void
bmp_tx_overflow(void *_p)
{
  struct bmp_proto *p = _p;
  if (p->tx_pending_count < p->tx_pending_limit)
    return;

  p->sock_err = 0;

  log(L_ERR "%s: Connection stalled", p->p.name);

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
  if (p->sk && p->sk->tbuf)
    bmp_tx_buffer_free(p, SKIP_BACK(struct bmp_tx_buffer, data[0], p->sk->tbuf));

  struct bmp_tx_buffer *btb = p->tx_pending;
  while (btb)
  {
    p->tx_pending_count--;

    struct bmp_tx_buffer *next = btb->next;
    bmp_tx_buffer_free(p, btb);
    btb = next;
  }

  p->tx_pending = NULL;

  ASSERT_DIE(!p->tx_last);
  ASSERT_DIE(!p->tx_pending_count);

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


static void
bmp_process_proto_state_change(struct bmp_proto *p, struct lfjour_item *last_up)
{
  struct proto_pending_update *ppu = SKIP_BACK(struct proto_pending_update, li, last_up);
  if (!ppu)
    return;

  if (bmp_peer_up_inout(p, ppu->new, true))
    goto done;

  SKIP_BACK_DECLARE(struct bgp_session_close_ad, bscad, ad, ea_get_adata(ppu->new, &ea_bgp_close_bmp));
  if (bscad)
  {
    bmp_peer_down_(p, ppu->new, bscad);
    goto done;
  }

done:
  lfjour_release(&p->proto_state_reader, last_up);
}

static void
bmp_proto_state_changed(void *_p)
{
  struct bmp_proto *p = _p;

  ASSERT_DIE(birdloop_inside(p->p.loop));

  struct lfjour_item *last_up;
  while (last_up = lfjour_get(&p->proto_state_reader))
    bmp_process_proto_state_change(p, last_up);
}

/** Configuration handle section **/
static struct proto *
bmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct bmp_proto *p = (void *) P;
  struct bmp_config *cf = (void *) CF;

  ASSERT_DIE(birdloop_inside(&main_birdloop));
  if (!bgp_next_hop_ea_class)
    bgp_next_hop_ea_class = ea_class_find_by_name("bgp_next_hop");

  p->cf = cf;
  p->local_addr = cf->local_addr;
  p->station_ip = cf->station_ip;
  p->station_port = cf->station_port;
  strcpy(p->sys_descr, cf->sys_descr);
  strcpy(p->sys_name, cf->sys_name);
  p->monitoring_rib.in_pre_policy = cf->monitoring_rib_in_pre_policy;
  p->monitoring_rib.in_post_policy = cf->monitoring_rib_in_post_policy;
  p->tx_pending_limit = cf->tx_pending_limit;

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

  p->tx_ev = ev_new_init(p->p.pool, bmp_fire_tx, p);
  p->tx_pending = NULL;
  p->tx_pending_count = 0;
  p->tx_overflow_event = ev_new_init(p->p.pool, bmp_tx_overflow, p);
  p->connect_retry_timer = tm_new_init(p->p.pool, bmp_connection_retry, p, 0, 0);
  p->sk = NULL;

  resource *r = ralloc(P->pool, &bmp_tx_resource_class);
  SKIP_BACK(struct bmp_tx_resource, r, r)->p = p;

  HASH_INIT(p->peer_map, P->pool, 4);
  HASH_INIT(p->stream_map, P->pool, 4);
  HASH_INIT(p->table_map, P->pool, 4);

  p->started = false;
  p->sock_err = 0;

  tm_start_in(p->connect_retry_timer, CONNECT_INIT_TIME, p->p.loop);

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
    bmp_close_socket(p);
  }

  p->sock_err = 0;

  return PS_FLUSH;
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

  /* Reconfigure tx buffer size limits */
  p->tx_pending_limit = new->tx_pending_limit;

  return 1;
}

static void
bmp_get_status(struct proto *P, byte *buf)
{
  struct bmp_proto *p = (void *) P;

  if (P->proto_state == PS_DOWN_XX)
    bsprintf(buf, "Down");
  else if (P->proto_state == PS_FLUSH)
    bsprintf(buf, "Flush");
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

  if (P->proto_state != PS_DOWN_XX)
  {
    cli_msg(-1006, "  %-19s %I", "Station address:", p->station_ip);
    cli_msg(-1006, "  %-19s %u", "Station port:", p->station_port);

    if (!ipa_zero(p->local_addr))
      cli_msg(-1006, "  %-19s %I", "Local address:", p->local_addr);

    if (p->sock_err)
      cli_msg(-1006, "  %-19s %M", "Last error:", p->sock_err);

    cli_msg(-1006, "  %-19s % 9sB (limit %sB)", "Pending TX:",
	fmt_order(p->tx_pending_count * (u64) page_size, 1, 10000),
	fmt_order(p->tx_pending_limit * (u64) page_size, 1, 10000));

    cli_msg(-1006, "  %-19s % 9sB", "Session TX:", fmt_order(p->tx_sent, 1, 10000));
    cli_msg(-1006, "  %-19s % 9sB", "Total TX:", fmt_order(p->tx_sent_total, 1, 10000));
  }
}

struct protocol proto_bmp = {
  .name = "BMP",
  .template = "bmp%d",
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

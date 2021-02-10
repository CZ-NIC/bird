/*
 *	BIRD -- BGP Packet Processing
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *	(c) 2008--2016 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2008--2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include <stdlib.h>

#include "nest/bird.h"
#include "nest/iface.h"
#include "nest/protocol.h"
#include "nest/route.h"
#include "nest/attrs.h"
#include "proto/mrt/mrt.h"
#include "conf/conf.h"
#include "lib/unaligned.h"
#include "lib/flowspec.h"
#include "lib/socket.h"

#include "nest/cli.h"

#include "bgp.h"


#define BGP_RR_REQUEST		0
#define BGP_RR_BEGIN		1
#define BGP_RR_END		2

#define BGP_NLRI_MAX		(4 + 1 + 32)

#define BGP_MPLS_BOS		1	/* Bottom-of-stack bit */
#define BGP_MPLS_MAX		10	/* Max number of labels that 24*n <= 255 */
#define BGP_MPLS_NULL		3	/* Implicit NULL label */
#define BGP_MPLS_MAGIC		0x800000 /* Magic withdraw label value, RFC 3107 3 */


static struct tbf rl_rcv_update = TBF_DEFAULT_LOG_LIMITS;
static struct tbf rl_snd_update = TBF_DEFAULT_LOG_LIMITS;

/* Table for state -> RFC 6608 FSM error subcodes */
static byte fsm_err_subcode[BS_MAX] = {
  [BS_OPENSENT] = 1,
  [BS_OPENCONFIRM] = 2,
  [BS_ESTABLISHED] = 3
};


static struct bgp_channel *
bgp_get_channel(struct bgp_proto *p, u32 afi)
{
  uint i;

  for (i = 0; i < p->channel_count; i++)
    if (p->afi_map[i] == afi)
      return p->channel_map[i];

  return NULL;
}

static inline void
put_af3(byte *buf, u32 id)
{
  put_u16(buf, id >> 16);
  buf[2] = id & 0xff;
}

static inline void
put_af4(byte *buf, u32 id)
{
  put_u16(buf, id >> 16);
  buf[2] = 0;
  buf[3] = id & 0xff;
}

static inline u32
get_af3(byte *buf)
{
  return (get_u16(buf) << 16) | buf[2];
}

static inline u32
get_af4(byte *buf)
{
  return (get_u16(buf) << 16) | buf[3];
}

static void
init_mrt_bgp_data(struct bgp_conn *conn, struct mrt_bgp_data *d)
{
  struct bgp_proto *p = conn->bgp;
  int p_ok = conn->state >= BS_OPENCONFIRM;

  memset(d, 0, sizeof(struct mrt_bgp_data));
  d->peer_as = p->remote_as;
  d->local_as = p->local_as;
  d->index = (p->neigh && p->neigh->iface) ? p->neigh->iface->index : 0;
  d->af = ipa_is_ip4(p->remote_ip) ? BGP_AFI_IPV4 : BGP_AFI_IPV6;
  d->peer_ip = conn->sk ? conn->sk->daddr : IPA_NONE;
  d->local_ip = conn->sk ? conn->sk->saddr : IPA_NONE;
  d->as4 = p_ok ? p->as4_session : 0;
}

static uint bgp_find_update_afi(byte *pos, uint len);

static int
bgp_estimate_add_path(struct bgp_proto *p, byte *pkt, uint len)
{
  /* No need to estimate it for other messages than UPDATE */
  if (pkt[18] != PKT_UPDATE)
    return 0;

  /* 1 -> no channel, 2 -> all channels, 3 -> some channels */
  if (p->summary_add_path_rx < 3)
    return p->summary_add_path_rx == 2;

  uint afi = bgp_find_update_afi(pkt, len);
  struct bgp_channel *c = bgp_get_channel(p, afi);
  if (!c)
  {
    /* Either frame error (if !afi) or unknown AFI/SAFI,
       will be reported later in regular parsing */
    BGP_TRACE(D_PACKETS, "MRT processing noticed invalid packet");
    return 0;
  }

  return c->add_path_rx;
}

static void
bgp_dump_message(struct bgp_conn *conn, byte *pkt, uint len)
{
  struct mrt_bgp_data d;
  init_mrt_bgp_data(conn, &d);

  d.message = pkt;
  d.msg_len = len;
  d.add_path = bgp_estimate_add_path(conn->bgp, pkt, len);

  mrt_dump_bgp_message(&d);
}

void
bgp_dump_state_change(struct bgp_conn *conn, uint old, uint new)
{
  struct mrt_bgp_data d;
  init_mrt_bgp_data(conn, &d);

  d.old_state = old;
  d.new_state = new;

  mrt_dump_bgp_state_change(&d);
}

static byte *
bgp_create_notification(struct bgp_conn *conn, byte *buf)
{
  struct bgp_proto *p = conn->bgp;

  BGP_TRACE(D_PACKETS, "Sending NOTIFICATION(code=%d.%d)", conn->notify_code, conn->notify_subcode);
  buf[0] = conn->notify_code;
  buf[1] = conn->notify_subcode;
  memcpy(buf+2, conn->notify_data, conn->notify_size);
  return buf + 2 + conn->notify_size;
}


/* Capability negotiation as per RFC 5492 */

const struct bgp_af_caps *
bgp_find_af_caps(struct bgp_caps *caps, u32 afi)
{
  struct bgp_af_caps *ac;

  WALK_AF_CAPS(caps, ac)
    if (ac->afi == afi)
      return ac;

  return NULL;
}

static struct bgp_af_caps *
bgp_get_af_caps(struct bgp_caps **pcaps, u32 afi)
{
  struct bgp_caps *caps = *pcaps;
  struct bgp_af_caps *ac;

  WALK_AF_CAPS(caps, ac)
    if (ac->afi == afi)
      return ac;

  uint n = caps->af_count;
  if (uint_is_pow2(n))
    *pcaps = caps = mb_realloc(caps, sizeof(struct bgp_caps) +
			       (2 * n) * sizeof(struct bgp_af_caps));

  ac = &caps->af_data[caps->af_count++];
  memset(ac, 0, sizeof(struct bgp_af_caps));
  ac->afi = afi;

  return ac;
}

static int
bgp_af_caps_cmp(const void *X, const void *Y)
{
  const struct bgp_af_caps *x = X, *y = Y;
  return (x->afi < y->afi) ? -1 : (x->afi > y->afi) ? 1 : 0;
}


void
bgp_prepare_capabilities(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_channel *c;
  struct bgp_caps *caps;
  struct bgp_af_caps *ac;

  if (!p->cf->capabilities)
  {
    /* Just prepare empty local_caps */
    conn->local_caps = mb_allocz(p->p.pool, sizeof(struct bgp_caps));
    return;
  }

  /* Prepare bgp_caps structure */
  int n = list_length(&p->p.channels);
  caps = mb_allocz(p->p.pool, sizeof(struct bgp_caps) + n * sizeof(struct bgp_af_caps));
  conn->local_caps = caps;

  caps->as4_support = p->cf->enable_as4;
  caps->ext_messages = p->cf->enable_extended_messages;
  caps->route_refresh = p->cf->enable_refresh;
  caps->enhanced_refresh = p->cf->enable_refresh;

  if (caps->as4_support)
    caps->as4_number = p->public_as;

  if (p->cf->gr_mode)
  {
    caps->gr_aware = 1;
    caps->gr_time = p->cf->gr_time;
    caps->gr_flags = p->p.gr_recovery ? BGP_GRF_RESTART : 0;
  }

  if (p->cf->llgr_mode)
    caps->llgr_aware = 1;

  if (p->cf->enable_hostname && config->hostname)
  {
    size_t length = strlen(config->hostname);
    char *hostname = mb_allocz(p->p.pool, length+1);
    memcpy(hostname, config->hostname, length+1);
    caps->hostname = hostname;
  }

  /* Allocate and fill per-AF fields */
  WALK_LIST(c, p->p.channels)
  {
    ac = &caps->af_data[caps->af_count++];
    ac->afi = c->afi;
    ac->ready = 1;

    ac->ext_next_hop = bgp_channel_is_ipv4(c) && c->cf->ext_next_hop;
    caps->any_ext_next_hop |= ac->ext_next_hop;

    ac->add_path = c->cf->add_path;
    caps->any_add_path |= ac->add_path;

    if (c->cf->gr_able)
    {
      ac->gr_able = 1;

      if (p->p.gr_recovery)
	ac->gr_af_flags |= BGP_GRF_FORWARDING;
    }

    if (c->cf->llgr_able)
    {
      ac->llgr_able = 1;
      ac->llgr_time = c->cf->llgr_time;

      if (p->p.gr_recovery)
	ac->llgr_flags |= BGP_LLGRF_FORWARDING;
    }
  }

  /* Sort capability fields by AFI/SAFI */
  qsort(caps->af_data, caps->af_count, sizeof(struct bgp_af_caps), bgp_af_caps_cmp);
}

static byte *
bgp_write_capabilities(struct bgp_conn *conn, byte *buf)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_caps *caps = conn->local_caps;
  struct bgp_af_caps *ac;
  byte *buf_head = buf;
  byte *data;

  /* Create capability list in buffer */

  /*
   * Note that max length is ~ 22+21*af_count. With max 12 channels that is
   * 274. We are limited just by buffer size (4096, minus header), as we support
   * extended optional parameres. Therefore, we have enough space for expansion.
   */

  WALK_AF_CAPS(caps, ac)
    if (ac->ready)
    {
      *buf++ = 1;		/* Capability 1: Multiprotocol extensions */
      *buf++ = 4;		/* Capability data length */
      put_af4(buf, ac->afi);
      buf += 4;
    }

  if (caps->route_refresh)
  {
    *buf++ = 2;			/* Capability 2: Support for route refresh */
    *buf++ = 0;			/* Capability data length */
  }

  if (caps->any_ext_next_hop)
  {
    *buf++ = 5;			/* Capability 5: Support for extended next hop */
    *buf++ = 0;			/* Capability data length, will be fixed later */
    data = buf;

    WALK_AF_CAPS(caps, ac)
      if (ac->ext_next_hop)
      {
	put_af4(buf, ac->afi);
	put_u16(buf+4, BGP_AFI_IPV6);
	buf += 6;
      }

    data[-1] = buf - data;
  }

  if (caps->ext_messages)
  {
    *buf++ = 6;			/* Capability 6: Support for extended messages */
    *buf++ = 0;			/* Capability data length */
  }

  if (caps->gr_aware)
  {
    *buf++ = 64;		/* Capability 64: Support for graceful restart */
    *buf++ = 0;			/* Capability data length, will be fixed later */
    data = buf;

    put_u16(buf, caps->gr_time);
    buf[0] |= caps->gr_flags;
    buf += 2;

    WALK_AF_CAPS(caps, ac)
      if (ac->gr_able)
      {
	put_af3(buf, ac->afi);
	buf[3] = ac->gr_af_flags;
	buf += 4;
      }

    data[-1] = buf - data;
  }

  if (caps->as4_support)
  {
    *buf++ = 65;		/* Capability 65: Support for 4-octet AS number */
    *buf++ = 4;			/* Capability data length */
    put_u32(buf, p->public_as);
    buf += 4;
  }

  if (caps->any_add_path)
  {
    *buf++ = 69;		/* Capability 69: Support for ADD-PATH */
    *buf++ = 0;			/* Capability data length, will be fixed later */
    data = buf;

    WALK_AF_CAPS(caps, ac)
      if (ac->add_path)
      {
	put_af3(buf, ac->afi);
	buf[3] = ac->add_path;
	buf += 4;
      }

    data[-1] = buf - data;
  }

  if (caps->enhanced_refresh)
  {
    *buf++ = 70;		/* Capability 70: Support for enhanced route refresh */
    *buf++ = 0;			/* Capability data length */
  }

  if (caps->llgr_aware)
  {
    *buf++ = 71;		/* Capability 71: Support for long-lived graceful restart */
    *buf++ = 0;			/* Capability data length, will be fixed later */
    data = buf;

    WALK_AF_CAPS(caps, ac)
      if (ac->llgr_able)
      {
	put_af3(buf, ac->afi);
	buf[3] = ac->llgr_flags;
	put_u24(buf+4, ac->llgr_time);
	buf += 7;
      }

    data[-1] = buf - data;
  }

  if (caps->hostname)
  {
    *buf++ = 73;                /* Capability 73: Hostname */
    *buf++ = 0;			/* Capability data length */
    data = buf;

    /* Hostname */
    size_t length = strlen(caps->hostname);
    *buf++ = length;
    memcpy(buf, caps->hostname, length);
    buf += length;

    /* Domain, not implemented */
    *buf++ = 0;

    data[-1] = buf - data;
  }

  caps->length = buf - buf_head;

  return buf;
}

static int
bgp_read_capabilities(struct bgp_conn *conn, byte *pos, int len)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_caps *caps;
  struct bgp_af_caps *ac;
  int i, cl;
  u32 af;

  if (!conn->remote_caps)
    caps = mb_allocz(p->p.pool, sizeof(struct bgp_caps) + sizeof(struct bgp_af_caps));
  else
  {
    caps = conn->remote_caps;
    conn->remote_caps = NULL;
  }

  caps->length += len;

  while (len > 0)
  {
    if (len < 2 || len < (2 + pos[1]))
      goto err;

    /* Capability length */
    cl = pos[1];

    /* Capability type */
    switch (pos[0])
    {
    case  1: /* Multiprotocol capability, RFC 4760 */
      if (cl != 4)
	goto err;

      af = get_af4(pos+2);
      ac = bgp_get_af_caps(&caps, af);
      ac->ready = 1;
      break;

    case  2: /* Route refresh capability, RFC 2918 */
      if (cl != 0)
	goto err;

      caps->route_refresh = 1;
      break;

    case  5: /* Extended next hop encoding capability, RFC 5549 */
      if (cl % 6)
	goto err;

      for (i = 0; i < cl; i += 6)
      {
	/* Specified only for IPv4 prefixes with IPv6 next hops */
	if ((get_u16(pos+2+i+0) != BGP_AFI_IPV4) ||
	    (get_u16(pos+2+i+4) != BGP_AFI_IPV6))
	  continue;

	af = get_af4(pos+2+i);
	ac = bgp_get_af_caps(&caps, af);
	ac->ext_next_hop = 1;
      }
      break;

    case  6: /* Extended message length capability, RFC draft */
      if (cl != 0)
	goto err;

      caps->ext_messages = 1;
      break;

    case 64: /* Graceful restart capability, RFC 4724 */
      if (cl % 4 != 2)
	goto err;

      /* Only the last instance is valid */
      WALK_AF_CAPS(caps, ac)
      {
	ac->gr_able = 0;
	ac->gr_af_flags = 0;
      }

      caps->gr_aware = 1;
      caps->gr_flags = pos[2] & 0xf0;
      caps->gr_time = get_u16(pos + 2) & 0x0fff;

      for (i = 2; i < cl; i += 4)
      {
	af = get_af3(pos+2+i);
	ac = bgp_get_af_caps(&caps, af);
	ac->gr_able = 1;
	ac->gr_af_flags = pos[2+i+3];
      }
      break;

    case 65: /* AS4 capability, RFC 6793 */
      if (cl != 4)
	goto err;

      caps->as4_support = 1;
      caps->as4_number = get_u32(pos + 2);
      break;

    case 69: /* ADD-PATH capability, RFC 7911 */
      if (cl % 4)
	goto err;

      for (i = 0; i < cl; i += 4)
      {
	byte val = pos[2+i+3];
	if (!val || (val > BGP_ADD_PATH_FULL))
	{
	  log(L_WARN "%s: Got ADD-PATH capability with unknown value %u, ignoring",
	      p->p.name, val);
	  break;
	}
      }

      for (i = 0; i < cl; i += 4)
      {
	af = get_af3(pos+2+i);
	ac = bgp_get_af_caps(&caps, af);
	ac->add_path = pos[2+i+3];
      }
      break;

    case 70: /* Enhanced route refresh capability, RFC 7313 */
      if (cl != 0)
	goto err;

      caps->enhanced_refresh = 1;
      break;

    case 71: /* Long lived graceful restart capability, RFC draft */
      if (cl % 7)
	goto err;

      /* Presumably, only the last instance is valid */
      WALK_AF_CAPS(caps, ac)
      {
	ac->llgr_able = 0;
	ac->llgr_flags = 0;
	ac->llgr_time = 0;
      }

      caps->llgr_aware = 1;

      for (i = 0; i < cl; i += 7)
      {
	af = get_af3(pos+2+i);
	ac = bgp_get_af_caps(&caps, af);
	ac->llgr_able = 1;
	ac->llgr_flags = pos[2+i+3];
	ac->llgr_time = get_u24(pos + 2+i+4);
      }
      break;

    case 73: /* Hostname, RFC draft */
      if ((cl < 2) || (cl < 2 + pos[2]))
        goto err;

      int length = pos[2];
      char *hostname = mb_allocz(p->p.pool, length+1);
      memcpy(hostname, pos + 3, length);
      hostname[length] = 0;

      for (i = 0; i < length; i++)
        if (hostname[i] < ' ')
          hostname[i] = ' ';

      caps->hostname = hostname;

      /* We can safely ignore all other capabilities */
    }

    ADVANCE(pos, len, 2 + cl);
  }

  /* The LLGR capability must be advertised together with the GR capability,
     otherwise it must be disregarded */
  if (!caps->gr_aware && caps->llgr_aware)
  {
    caps->llgr_aware = 0;
    WALK_AF_CAPS(caps, ac)
    {
      ac->llgr_able = 0;
      ac->llgr_flags = 0;
      ac->llgr_time = 0;
    }
  }

  conn->remote_caps = caps;
  return 0;

err:
  mb_free(caps);
  bgp_error(conn, 2, 0, NULL, 0);
  return -1;
}

static int
bgp_check_capabilities(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_caps *local = conn->local_caps;
  struct bgp_caps *remote = conn->remote_caps;
  struct bgp_channel *c;
  int count = 0;

  /* This is partially overlapping with bgp_conn_enter_established_state(),
     but we need to run this just after we receive OPEN message */

  WALK_LIST(c, p->p.channels)
  {
    const struct bgp_af_caps *loc = bgp_find_af_caps(local,  c->afi);
    const struct bgp_af_caps *rem = bgp_find_af_caps(remote, c->afi);

    /* Find out whether this channel will be active */
    int active = loc && loc->ready &&
      ((rem && rem->ready) || (!remote->length && (c->afi == BGP_AF_IPV4)));

    /* Mandatory must be active */
    if (c->cf->mandatory && !active)
      return 0;

    if (active)
      count++;
  }

  /* We need at least one channel active */
  if (!count)
    return 0;

  return 1;
}

static int
bgp_read_options(struct bgp_conn *conn, byte *pos, uint len, uint rest)
{
  struct bgp_proto *p = conn->bgp;
  int ext = 0;

  /* Handle extended length (draft-ietf-idr-ext-opt-param-07) */
  if ((len > 0) && (rest > 0) && (pos[0] == 255))
  {
    if (rest < 3)
      goto err;

    /* Update pos/len to describe optional data */
    len = get_u16(pos+1);
    ext = 1;
    pos += 3;
    rest -= 3;
  }

  /* Verify that optional data fits into OPEN packet */
  if (len > rest)
    goto err;

  /* Length of option parameter header */
  uint hlen = ext ? 3 : 2;

  while (len > 0)
  {
    if (len < hlen)
      goto err;

    uint otype = get_u8(pos);
    uint olen = ext ? get_u16(pos+1) : get_u8(pos+1);

    if (len < (hlen + olen))
      goto err;

    if (otype == 2)
    {
      /* BGP capabilities, RFC 5492 */
      if (p->cf->capabilities)
	if (bgp_read_capabilities(conn, pos + hlen, olen) < 0)
	  return -1;
    }
    else
    {
      /* Unknown option */
      bgp_error(conn, 2, 4, pos, hlen + olen);
      return -1;
    }

    ADVANCE(pos, len, hlen + olen);
  }

  /* Prepare empty caps if no capability option was announced */
  if (!conn->remote_caps)
    conn->remote_caps = mb_allocz(p->p.pool, sizeof(struct bgp_caps));

  return 0;

err:
  bgp_error(conn, 2, 0, NULL, 0);
  return -1;
}

static byte *
bgp_create_open(struct bgp_conn *conn, byte *buf)
{
  struct bgp_proto *p = conn->bgp;

  BGP_TRACE(D_PACKETS, "Sending OPEN(ver=%d,as=%d,hold=%d,id=%08x)",
	    BGP_VERSION, p->public_as, p->cf->hold_time, p->local_id);

  buf[0] = BGP_VERSION;
  put_u16(buf+1, (p->public_as < 0xFFFF) ? p->public_as : AS_TRANS);
  put_u16(buf+3, p->cf->hold_time);
  put_u32(buf+5, p->local_id);

  if (p->cf->capabilities)
  {
    /* Prepare local_caps and write capabilities to buffer */
    byte *pos = buf+12;
    byte *end = bgp_write_capabilities(conn, pos);
    uint len = end - pos;

    if (len < 254)
    {
      buf[9] = len + 2;		/* Optional parameters length */
      buf[10] = 2;		/* Option 2: Capability list */
      buf[11] = len;		/* Option data length */
    }
    else /* draft-ietf-idr-ext-opt-param-07 */
    {
      /* Move capabilities 4 B forward */
      memmove(buf + 16, pos, len);
      pos = buf + 16;
      end = pos + len;

      buf[9] = 255;		/* Non-ext OP length, fake */
      buf[10] = 255;		/* Non-ext OP type, signals extended length */
      put_u16(buf+11, len + 3);	/* Extended optional parameters length */
      buf[13] = 2;		/* Option 2: Capability list */
      put_u16(buf+14, len);	/* Option extended data length */
    }

    return end;
  }
  else
  {
    buf[9] = 0;			/* No optional parameters */
    return buf + 10;
  }

  return buf;
}

static void
bgp_rx_open(struct bgp_conn *conn, byte *pkt, uint len)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_conn *other;
  u32 asn, hold, id;

  /* Check state */
  if (conn->state != BS_OPENSENT)
  { bgp_error(conn, 5, fsm_err_subcode[conn->state], NULL, 0); return; }

  /* Check message length */
  if (len < 29)
  { bgp_error(conn, 1, 2, pkt+16, 2); return; }

  if (pkt[19] != BGP_VERSION)
  { u16 val = BGP_VERSION; bgp_error(conn, 2, 1, (byte *) &val, 2); return; }

  asn = get_u16(pkt+20);
  hold = get_u16(pkt+22);
  id = get_u32(pkt+24);
  BGP_TRACE(D_PACKETS, "Got OPEN(as=%d,hold=%d,id=%R)", asn, hold, id);

  if (bgp_read_options(conn, pkt+29, pkt[28], len-29) < 0)
    return;

  if (hold > 0 && hold < 3)
  { bgp_error(conn, 2, 6, pkt+22, 2); return; }

  /* RFC 6286 2.2 - router ID is nonzero and AS-wide unique */
  if (!id || (p->is_internal && id == p->local_id))
  { bgp_error(conn, 2, 3, pkt+24, -4); return; }

  /* RFC 5492 4 - check for required capabilities */
  if (p->cf->capabilities && !bgp_check_capabilities(conn))
  { bgp_error(conn, 2, 7, NULL, 0); return; }

  struct bgp_caps *caps = conn->remote_caps;

  if (caps->as4_support)
  {
    u32 as4 = caps->as4_number;

    if ((as4 != asn) && (asn != AS_TRANS))
      log(L_WARN "%s: Peer advertised inconsistent AS numbers", p->p.name);

    /* When remote ASN is unspecified, it must be external one */
    if (p->remote_as ? (as4 != p->remote_as) : (as4 == p->local_as))
    { as4 = htonl(as4); bgp_error(conn, 2, 2, (byte *) &as4, 4); return; }

    conn->received_as = as4;
  }
  else
  {
    if (p->remote_as ? (asn != p->remote_as) : (asn == p->local_as))
    { bgp_error(conn, 2, 2, pkt+20, 2); return; }

    conn->received_as = asn;
  }

  /* Check the other connection */
  other = (conn == &p->outgoing_conn) ? &p->incoming_conn : &p->outgoing_conn;
  switch (other->state)
  {
  case BS_CONNECT:
  case BS_ACTIVE:
    /* Stop outgoing connection attempts */
    bgp_conn_enter_idle_state(other);
    break;

  case BS_IDLE:
  case BS_OPENSENT:
  case BS_CLOSE:
    break;

  case BS_OPENCONFIRM:
    /*
     * Description of collision detection rules in RFC 4271 is confusing and
     * contradictory, but it is essentially:
     *
     * 1. Router with higher ID is dominant
     * 2. If both have the same ID, router with higher ASN is dominant [RFC6286]
     * 3. When both connections are in OpenConfirm state, one initiated by
     *    the dominant router is kept.
     *
     * The first line in the expression below evaluates whether the neighbor
     * is dominant, the second line whether the new connection was initiated
     * by the neighbor. If both are true (or both are false), we keep the new
     * connection, otherwise we keep the old one.
     */
    if (((p->local_id < id) || ((p->local_id == id) && (p->public_as < p->remote_as)))
	== (conn == &p->incoming_conn))
    {
      /* Should close the other connection */
      BGP_TRACE(D_EVENTS, "Connection collision, giving up the other connection");
      bgp_error(other, 6, 7, NULL, 0);
      break;
    }
    /* Fall thru */
  case BS_ESTABLISHED:
    /* Should close this connection */
    BGP_TRACE(D_EVENTS, "Connection collision, giving up this connection");
    bgp_error(conn, 6, 7, NULL, 0);
    return;

  default:
    bug("bgp_rx_open: Unknown state");
  }

  /* Update our local variables */
  conn->hold_time = MIN(hold, p->cf->hold_time);
  conn->keepalive_time = p->cf->keepalive_time ? : conn->hold_time / 3;
  conn->as4_session = conn->local_caps->as4_support && caps->as4_support;
  conn->ext_messages = conn->local_caps->ext_messages && caps->ext_messages;
  p->remote_id = id;

  DBG("BGP: Hold timer set to %d, keepalive to %d, AS to %d, ID to %x, AS4 session to %d\n",
      conn->hold_time, conn->keepalive_time, p->remote_as, p->remote_id, conn->as4_session);

  bgp_schedule_packet(conn, NULL, PKT_KEEPALIVE);
  bgp_start_timer(conn->hold_timer, conn->hold_time);
  bgp_conn_enter_openconfirm_state(conn);
}


/*
 *	Next hop handling
 */

#define REPORT(msg, args...) \
  ({ log(L_REMOTE "%s: " msg, s->proto->p.name, ## args); })

#define DISCARD(msg, args...) \
  ({ REPORT(msg, ## args); return; })

#define WITHDRAW(msg, args...) \
  ({ REPORT(msg, ## args); s->err_withdraw = 1; return; })

#define BAD_AFI		"Unexpected AF <%u/%u> in UPDATE"
#define BAD_NEXT_HOP	"Invalid NEXT_HOP attribute"
#define NO_NEXT_HOP	"Missing NEXT_HOP attribute"
#define NO_LABEL_STACK	"Missing MPLS stack"


static void
bgp_apply_next_hop(struct bgp_parse_state *s, rta *a, ip_addr gw, ip_addr ll)
{
  struct bgp_proto *p = s->proto;
  struct bgp_channel *c = s->channel;

  if (c->cf->gw_mode == GW_DIRECT)
  {
    neighbor *nbr = NULL;

    /* GW_DIRECT -> single_hop -> p->neigh != NULL */
    if (ipa_nonzero(gw))
      nbr = neigh_find(&p->p, gw, NULL, 0);
    else if (ipa_nonzero(ll))
      nbr = neigh_find(&p->p, ll, p->neigh->iface, 0);

    if (!nbr || (nbr->scope == SCOPE_HOST))
      WITHDRAW(BAD_NEXT_HOP);

    a->dest = RTD_UNICAST;
    a->nh.gw = nbr->addr;
    a->nh.iface = nbr->iface;
    a->igp_metric = c->cf->cost;
  }
  else /* GW_RECURSIVE */
  {
    if (ipa_zero(gw))
      WITHDRAW(BAD_NEXT_HOP);

    rtable *tab = ipa_is_ip4(gw) ? c->igp_table_ip4 : c->igp_table_ip6;
    s->hostentry = rt_get_hostentry(tab, gw, ll, c->c.table);

    if (!s->mpls)
      rta_apply_hostentry(a, s->hostentry, NULL);

    /* With MPLS, hostentry is applied later in bgp_apply_mpls_labels() */
  }
}

static void
bgp_apply_mpls_labels(struct bgp_parse_state *s, rta *a, u32 *labels, uint lnum)
{
  if (lnum > MPLS_MAX_LABEL_STACK)
  {
    REPORT("Too many MPLS labels ($u)", lnum);

    a->dest = RTD_UNREACHABLE;
    a->hostentry = NULL;
    a->nh = (struct nexthop) { };
    return;
  }

  /* Handle implicit NULL as empty MPLS stack */
  if ((lnum == 1) && (labels[0] == BGP_MPLS_NULL))
    lnum = 0;

  if (s->channel->cf->gw_mode == GW_DIRECT)
  {
    a->nh.labels = lnum;
    memcpy(a->nh.label, labels, 4*lnum);
  }
  else /* GW_RECURSIVE */
  {
    mpls_label_stack ms;

    ms.len = lnum;
    memcpy(ms.stack, labels, 4*lnum);
    rta_apply_hostentry(a, s->hostentry, &ms);
  }
}


static int
bgp_match_src(struct bgp_export_state *s, int mode)
{
  switch (mode)
  {
  case NH_NO:		return 0;
  case NH_ALL:		return 1;
  case NH_IBGP:		return s->src && s->src->is_internal;
  case NH_EBGP:		return s->src && !s->src->is_internal;
  default:		return 0;
  }
}

static inline int
bgp_use_next_hop(struct bgp_export_state *s, eattr *a)
{
  struct bgp_proto *p = s->proto;
  struct bgp_channel *c = s->channel;
  ip_addr *nh = (void *) a->u.ptr->data;

  /* Handle next hop self option */
  if (c->cf->next_hop_self && bgp_match_src(s, c->cf->next_hop_self))
    return 0;

  /* Handle next hop keep option */
  if (c->cf->next_hop_keep && bgp_match_src(s, c->cf->next_hop_keep))
    return 1;

  /* Keep it when explicitly set in export filter */
  if (a->type & EAF_FRESH)
    return 1;

  /* Check for non-matching AF */
  if ((ipa_is_ip4(*nh) != bgp_channel_is_ipv4(c)) && !c->ext_next_hop)
    return 0;

  /* Keep it when exported to internal peers */
  if (p->is_interior && ipa_nonzero(*nh))
    return 1;

  /* Keep it when forwarded between single-hop BGPs on the same iface */
  struct iface *ifa = (s->src && s->src->neigh) ? s->src->neigh->iface : NULL;
  return p->neigh && (p->neigh->iface == ifa);
}

static inline int
bgp_use_gateway(struct bgp_export_state *s)
{
  struct bgp_proto *p = s->proto;
  struct bgp_channel *c = s->channel;
  rta *ra = s->route->attrs;

  /* Handle next hop self option - also applies to gateway */
  if (c->cf->next_hop_self && bgp_match_src(s, c->cf->next_hop_self))
    return 0;

  /* We need one valid global gateway */
  if ((ra->dest != RTD_UNICAST) || ra->nh.next || ipa_zero(ra->nh.gw) || ipa_is_link_local(ra->nh.gw))
    return 0;

  /* Check for non-matching AF */
  if ((ipa_is_ip4(ra->nh.gw) != bgp_channel_is_ipv4(c)) && !c->ext_next_hop)
    return 0;

  /* Use it when exported to internal peers */
  if (p->is_interior)
    return 1;

  /* Use it when forwarded to single-hop BGP peer on on the same iface */
  return p->neigh && (p->neigh->iface == ra->nh.iface);
}

static void
bgp_update_next_hop_ip(struct bgp_export_state *s, eattr *a, ea_list **to)
{
  if (!a || !bgp_use_next_hop(s, a))
  {
    if (bgp_use_gateway(s))
    {
      rta *ra = s->route->attrs;
      ip_addr nh[1] = { ra->nh.gw };
      bgp_set_attr_data(to, s->pool, BA_NEXT_HOP, 0, nh, 16);

      if (s->mpls)
      {
	u32 implicit_null = BGP_MPLS_NULL;
	u32 *labels = ra->nh.labels ? ra->nh.label : &implicit_null;
	uint lnum = ra->nh.labels ? ra->nh.labels : 1;
	bgp_set_attr_data(to, s->pool, BA_MPLS_LABEL_STACK, 0, labels, lnum * 4);
      }
    }
    else
    {
      ip_addr nh[2] = { s->channel->next_hop_addr, s->channel->link_addr };
      bgp_set_attr_data(to, s->pool, BA_NEXT_HOP, 0, nh, ipa_nonzero(nh[1]) ? 32 : 16);
      s->local_next_hop = 1;

      /* TODO: Use local MPLS assigned label */
      if (s->mpls)
      {
	u32 implicit_null = BGP_MPLS_NULL;
	bgp_set_attr_data(to, s->pool, BA_MPLS_LABEL_STACK, 0, &implicit_null, 4);
      }
    }
  }

  /* Check if next hop is valid */
  a = bgp_find_attr(*to, BA_NEXT_HOP);
  if (!a)
    WITHDRAW(NO_NEXT_HOP);

  ip_addr *nh = (void *) a->u.ptr->data;
  ip_addr peer = s->proto->remote_ip;
  uint len = a->u.ptr->length;

  /* Forbid zero next hop */
  if (ipa_zero(nh[0]) && ((len != 32) || ipa_zero(nh[1])))
    WITHDRAW(BAD_NEXT_HOP);

  /* Forbid next hop equal to neighbor IP */
  if (ipa_equal(peer, nh[0]) || ((len == 32) && ipa_equal(peer, nh[1])))
    WITHDRAW(BAD_NEXT_HOP);

  /* Forbid next hop with non-matching AF */
  if ((ipa_is_ip4(nh[0]) != bgp_channel_is_ipv4(s->channel)) &&
      !s->channel->ext_next_hop)
    WITHDRAW(BAD_NEXT_HOP);

  /* Just check if MPLS stack */
  if (s->mpls && !bgp_find_attr(*to, BA_MPLS_LABEL_STACK))
    WITHDRAW(NO_LABEL_STACK);
}

static uint
bgp_encode_next_hop_ip(struct bgp_write_state *s, eattr *a, byte *buf, uint size UNUSED)
{
  /* This function is used only for MP-BGP, see bgp_encode_next_hop() for IPv4 BGP */
  ip_addr *nh = (void *) a->u.ptr->data;
  uint len = a->u.ptr->length;

  ASSERT((len == 16) || (len == 32));

  /*
   * Both IPv4 and IPv6 next hops can be used (with ext_next_hop enabled). This
   * is specified in RFC 5549 for IPv4 and in RFC 4798 for IPv6. The difference
   * is that IPv4 address is directly encoded with IPv4 NLRI, but as IPv4-mapped
   * IPv6 address with IPv6 NLRI.
   */

  if (bgp_channel_is_ipv4(s->channel) && ipa_is_ip4(nh[0]))
  {
    put_ip4(buf, ipa_to_ip4(nh[0]));
    return 4;
  }

  put_ip6(buf, ipa_to_ip6(nh[0]));

  if (len == 32)
    put_ip6(buf+16, ipa_to_ip6(nh[1]));

  return len;
}

static void
bgp_decode_next_hop_ip(struct bgp_parse_state *s, byte *data, uint len, rta *a)
{
  struct bgp_channel *c = s->channel;
  struct adata *ad = lp_alloc_adata(s->pool, 32);
  ip_addr *nh = (void *) ad->data;

  if (len == 4)
  {
    nh[0] = ipa_from_ip4(get_ip4(data));
    nh[1] = IPA_NONE;
  }
  else if (len == 16)
  {
    nh[0] = ipa_from_ip6(get_ip6(data));
    nh[1] = IPA_NONE;

    if (ipa_is_link_local(nh[0]))
    { nh[1] = nh[0]; nh[0] = IPA_NONE; }
  }
  else if (len == 32)
  {
    nh[0] = ipa_from_ip6(get_ip6(data));
    nh[1] = ipa_from_ip6(get_ip6(data+16));

    if (ipa_is_link_local(nh[0]))
    { nh[1] = nh[0]; nh[0] = IPA_NONE; }

    if (ipa_is_ip4(nh[0]) || !ipa_is_link_local(nh[1]))
      nh[1] = IPA_NONE;
  }
  else
    bgp_parse_error(s, 9);

  if (ipa_zero(nh[1]))
    ad->length = 16;

  if ((bgp_channel_is_ipv4(c) != ipa_is_ip4(nh[0])) && !c->ext_next_hop)
    WITHDRAW(BAD_NEXT_HOP);

  // XXXX validate next hop

  bgp_set_attr_ptr(&(a->eattrs), s->pool, BA_NEXT_HOP, 0, ad);
  bgp_apply_next_hop(s, a, nh[0], nh[1]);
}

static uint
bgp_encode_next_hop_vpn(struct bgp_write_state *s, eattr *a, byte *buf, uint size UNUSED)
{
  ip_addr *nh = (void *) a->u.ptr->data;
  uint len = a->u.ptr->length;

  ASSERT((len == 16) || (len == 32));

  /*
   * Both IPv4 and IPv6 next hops can be used (with ext_next_hop enabled). This
   * is specified in RFC 5549 for VPNv4 and in RFC 4659 for VPNv6. The difference
   * is that IPv4 address is directly encoded with VPNv4 NLRI, but as IPv4-mapped
   * IPv6 address with VPNv6 NLRI.
   */

  if (bgp_channel_is_ipv4(s->channel) && ipa_is_ip4(nh[0]))
  {
    put_u64(buf, 0); /* VPN RD is 0 */
    put_ip4(buf+8, ipa_to_ip4(nh[0]));
    return 12;
  }

  put_u64(buf, 0); /* VPN RD is 0 */
  put_ip6(buf+8, ipa_to_ip6(nh[0]));

  if (len == 16)
    return 24;

  put_u64(buf+24, 0); /* VPN RD is 0 */
  put_ip6(buf+32, ipa_to_ip6(nh[1]));

  return 48;
}

static void
bgp_decode_next_hop_vpn(struct bgp_parse_state *s, byte *data, uint len, rta *a)
{
  struct bgp_channel *c = s->channel;
  struct adata *ad = lp_alloc_adata(s->pool, 32);
  ip_addr *nh = (void *) ad->data;

  if (len == 12)
  {
    nh[0] = ipa_from_ip4(get_ip4(data+8));
    nh[1] = IPA_NONE;
  }
  else if (len == 24)
  {
    nh[0] = ipa_from_ip6(get_ip6(data+8));
    nh[1] = IPA_NONE;

    if (ipa_is_link_local(nh[0]))
    { nh[1] = nh[0]; nh[0] = IPA_NONE; }
  }
  else if (len == 48)
  {
    nh[0] = ipa_from_ip6(get_ip6(data+8));
    nh[1] = ipa_from_ip6(get_ip6(data+32));

    if (ipa_is_ip4(nh[0]) || !ip6_is_link_local(nh[1]))
      nh[1] = IPA_NONE;
  }
  else
    bgp_parse_error(s, 9);

  if (ipa_zero(nh[1]))
    ad->length = 16;

  /* XXXX which error */
  if ((get_u64(data) != 0) || ((len == 48) && (get_u64(data+24) != 0)))
    bgp_parse_error(s, 9);

  if ((bgp_channel_is_ipv4(c) != ipa_is_ip4(nh[0])) && !c->ext_next_hop)
    WITHDRAW(BAD_NEXT_HOP);

  // XXXX validate next hop

  bgp_set_attr_ptr(&(a->eattrs), s->pool, BA_NEXT_HOP, 0, ad);
  bgp_apply_next_hop(s, a, nh[0], nh[1]);
}



static uint
bgp_encode_next_hop_none(struct bgp_write_state *s UNUSED, eattr *a UNUSED, byte *buf UNUSED, uint size UNUSED)
{
  return 0;
}

static void
bgp_decode_next_hop_none(struct bgp_parse_state *s UNUSED, byte *data UNUSED, uint len UNUSED, rta *a UNUSED)
{
  /*
   * Although we expect no next hop and RFC 7606 7.11 states that attribute
   * MP_REACH_NLRI with unexpected next hop length is considered malformed,
   * FlowSpec RFC 5575 4 states that next hop shall be ignored on receipt.
   */

  return;
}

static void
bgp_update_next_hop_none(struct bgp_export_state *s, eattr *a, ea_list **to)
{
  /* NEXT_HOP shall not pass */
  if (a)
    bgp_unset_attr(to, s->pool, BA_NEXT_HOP);
}


/*
 *	UPDATE
 */

static void
bgp_rte_update(struct bgp_parse_state *s, net_addr *n, u32 path_id, rta *a0)
{
  if (path_id != s->last_id)
  {
    s->last_src = rt_get_source(&s->proto->p, path_id);
    s->last_id = path_id;

    rta_free(s->cached_rta);
    s->cached_rta = NULL;
  }

  if (!a0)
  {
    /* Route withdraw */
    rte_update3(&s->channel->c, n, NULL, s->last_src);
    return;
  }

  /* Prepare cached route attributes */
  if (s->cached_rta == NULL)
  {
    a0->src = s->last_src;

    /* Workaround for rta_lookup() breaking eattrs */
    ea_list *ea = a0->eattrs;
    s->cached_rta = rta_lookup(a0);
    a0->eattrs = ea;
  }

  rta *a = rta_clone(s->cached_rta);
  rte *e = rte_get_temp(a);

  e->pflags = 0;
  e->u.bgp.suppressed = 0;
  e->u.bgp.stale = -1;
  rte_update3(&s->channel->c, n, e, s->last_src);
}

static void
bgp_encode_mpls_labels(struct bgp_write_state *s UNUSED, const adata *mpls, byte **pos, uint *size, byte *pxlen)
{
  const u32 dummy = 0;
  const u32 *labels = mpls ? (const u32 *) mpls->data : &dummy;
  uint lnum = mpls ? (mpls->length / 4) : 1;

  for (uint i = 0; i < lnum; i++)
  {
    put_u24(*pos, labels[i] << 4);
    ADVANCE(*pos, *size, 3);
  }

  /* Add bottom-of-stack flag */
  (*pos)[-1] |= BGP_MPLS_BOS;

  *pxlen += 24 * lnum;
}

static void
bgp_decode_mpls_labels(struct bgp_parse_state *s, byte **pos, uint *len, uint *pxlen, rta *a)
{
  u32 labels[BGP_MPLS_MAX], label;
  uint lnum = 0;

  do {
    if (*pxlen < 24)
      bgp_parse_error(s, 1);

    label = get_u24(*pos);
    labels[lnum++] = label >> 4;
    ADVANCE(*pos, *len, 3);
    *pxlen -= 24;

    /* RFC 8277 2.4 - withdraw does not have variable-size MPLS stack but
       fixed-size 24-bit Compatibility field, which MUST be ignored */
    if (!a && !s->err_withdraw)
      return;
  }
  while (!(label & BGP_MPLS_BOS));

  if (!a)
    return;

  /* Attach MPLS attribute unless we already have one */
  if (!s->mpls_labels)
  {
    s->mpls_labels = lp_alloc_adata(s->pool, 4*BGP_MPLS_MAX);
    bgp_set_attr_ptr(&(a->eattrs), s->pool, BA_MPLS_LABEL_STACK, 0, s->mpls_labels);
  }

  /* Overwrite data in the attribute */
  s->mpls_labels->length = 4*lnum;
  memcpy(s->mpls_labels->data, labels, 4*lnum);

  /* Update next hop entry in rta */
  bgp_apply_mpls_labels(s, a, labels, lnum);

  /* Attributes were changed, invalidate cached entry */
  rta_free(s->cached_rta);
  s->cached_rta = NULL;

  return;
}

static uint
bgp_encode_nlri_ip4(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= BGP_NLRI_MAX))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_ip4 *net = (void *) px->net;

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    /* Encode prefix length */
    *pos = net->pxlen;
    ADVANCE(pos, size, 1);

    /* Encode MPLS labels */
    if (s->mpls)
      bgp_encode_mpls_labels(s, s->mpls_labels, &pos, &size, pos - 1);

    /* Encode prefix body */
    ip4_addr a = ip4_hton(net->prefix);
    uint b = (net->pxlen + 7) / 8;
    memcpy(pos, &a, b);
    ADVANCE(pos, size, b);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_ip4(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    net_addr_ip4 net;
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 5)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    /* Decode prefix length */
    uint l = *pos;
    ADVANCE(pos, len, 1);

    if (len < ((l + 7) / 8))
      bgp_parse_error(s, 1);

    /* Decode MPLS labels */
    if (s->mpls)
      bgp_decode_mpls_labels(s, &pos, &len, &l, a);

    if (l > IP4_MAX_PREFIX_LENGTH)
      bgp_parse_error(s, 10);

    /* Decode prefix body */
    ip4_addr addr = IP4_NONE;
    uint b = (l + 7) / 8;
    memcpy(&addr, pos, b);
    ADVANCE(pos, len, b);

    net = NET_ADDR_IP4(ip4_ntoh(addr), l);
    net_normalize_ip4(&net);

    // XXXX validate prefix

    bgp_rte_update(s, (net_addr *) &net, path_id, a);
  }
}


static uint
bgp_encode_nlri_ip6(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= BGP_NLRI_MAX))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_ip6 *net = (void *) px->net;

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    /* Encode prefix length */
    *pos = net->pxlen;
    ADVANCE(pos, size, 1);

    /* Encode MPLS labels */
    if (s->mpls)
      bgp_encode_mpls_labels(s, s->mpls_labels, &pos, &size, pos - 1);

    /* Encode prefix body */
    ip6_addr a = ip6_hton(net->prefix);
    uint b = (net->pxlen + 7) / 8;
    memcpy(pos, &a, b);
    ADVANCE(pos, size, b);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_ip6(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    net_addr_ip6 net;
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 5)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    /* Decode prefix length */
    uint l = *pos;
    ADVANCE(pos, len, 1);

    if (len < ((l + 7) / 8))
      bgp_parse_error(s, 1);

    /* Decode MPLS labels */
    if (s->mpls)
      bgp_decode_mpls_labels(s, &pos, &len, &l, a);

    if (l > IP6_MAX_PREFIX_LENGTH)
      bgp_parse_error(s, 10);

    /* Decode prefix body */
    ip6_addr addr = IP6_NONE;
    uint b = (l + 7) / 8;
    memcpy(&addr, pos, b);
    ADVANCE(pos, len, b);

    net = NET_ADDR_IP6(ip6_ntoh(addr), l);
    net_normalize_ip6(&net);

    // XXXX validate prefix

    bgp_rte_update(s, (net_addr *) &net, path_id, a);
  }
}

static uint
bgp_encode_nlri_vpn4(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= BGP_NLRI_MAX))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_vpn4 *net = (void *) px->net;

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    /* Encode prefix length */
    *pos = 64 + net->pxlen;
    ADVANCE(pos, size, 1);

    /* Encode MPLS labels */
    if (s->mpls)
      bgp_encode_mpls_labels(s, s->mpls_labels, &pos, &size, pos - 1);

    /* Encode route distinguisher */
    put_u64(pos, net->rd);
    ADVANCE(pos, size, 8);

    /* Encode prefix body */
    ip4_addr a = ip4_hton(net->prefix);
    uint b = (net->pxlen + 7) / 8;
    memcpy(pos, &a, b);
    ADVANCE(pos, size, b);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_vpn4(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    net_addr_vpn4 net;
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 5)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    /* Decode prefix length */
    uint l = *pos;
    ADVANCE(pos, len, 1);

    if (len < ((l + 7) / 8))
      bgp_parse_error(s, 1);

    /* Decode MPLS labels */
    if (s->mpls)
      bgp_decode_mpls_labels(s, &pos, &len, &l, a);

    /* Decode route distinguisher */
    if (l < 64)
      bgp_parse_error(s, 1);

    u64 rd = get_u64(pos);
    ADVANCE(pos, len, 8);
    l -= 64;

    if (l > IP4_MAX_PREFIX_LENGTH)
      bgp_parse_error(s, 10);

    /* Decode prefix body */
    ip4_addr addr = IP4_NONE;
    uint b = (l + 7) / 8;
    memcpy(&addr, pos, b);
    ADVANCE(pos, len, b);

    net = NET_ADDR_VPN4(ip4_ntoh(addr), l, rd);
    net_normalize_vpn4(&net);

    // XXXX validate prefix

    bgp_rte_update(s, (net_addr *) &net, path_id, a);
  }
}


static uint
bgp_encode_nlri_vpn6(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= BGP_NLRI_MAX))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_vpn6 *net = (void *) px->net;

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    /* Encode prefix length */
    *pos = 64 + net->pxlen;
    ADVANCE(pos, size, 1);

    /* Encode MPLS labels */
    if (s->mpls)
      bgp_encode_mpls_labels(s, s->mpls_labels, &pos, &size, pos - 1);

    /* Encode route distinguisher */
    put_u64(pos, net->rd);
    ADVANCE(pos, size, 8);

    /* Encode prefix body */
    ip6_addr a = ip6_hton(net->prefix);
    uint b = (net->pxlen + 7) / 8;
    memcpy(pos, &a, b);
    ADVANCE(pos, size, b);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_vpn6(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    net_addr_vpn6 net;
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 5)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    /* Decode prefix length */
    uint l = *pos;
    ADVANCE(pos, len, 1);

    if (len < ((l + 7) / 8))
      bgp_parse_error(s, 1);

    /* Decode MPLS labels */
    if (s->mpls)
      bgp_decode_mpls_labels(s, &pos, &len, &l, a);

    /* Decode route distinguisher */
    if (l < 64)
      bgp_parse_error(s, 1);

    u64 rd = get_u64(pos);
    ADVANCE(pos, len, 8);
    l -= 64;

    if (l > IP6_MAX_PREFIX_LENGTH)
      bgp_parse_error(s, 10);

    /* Decode prefix body */
    ip6_addr addr = IP6_NONE;
    uint b = (l + 7) / 8;
    memcpy(&addr, pos, b);
    ADVANCE(pos, len, b);

    net = NET_ADDR_VPN6(ip6_ntoh(addr), l, rd);
    net_normalize_vpn6(&net);

    // XXXX validate prefix

    bgp_rte_update(s, (net_addr *) &net, path_id, a);
  }
}


static uint
bgp_encode_nlri_flow4(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= 4))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_flow4 *net = (void *) px->net;
    uint flen = net->length - sizeof(net_addr_flow4);

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    if (flen > size)
      break;

    /* Copy whole flow data including length */
    memcpy(pos, net->data, flen);
    ADVANCE(pos, size, flen);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_flow4(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 4)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    if (len < 2)
      bgp_parse_error(s, 1);

    /* Decode flow length */
    uint hlen = flow_hdr_length(pos);
    uint dlen = flow_read_length(pos);
    uint flen = hlen + dlen;
    byte *data = pos + hlen;

    if (len < flen)
      bgp_parse_error(s, 1);

    /* Validate flow data */
    enum flow_validated_state r = flow4_validate(data, dlen);
    if (r != FLOW_ST_VALID)
    {
      log(L_REMOTE "%s: Invalid flow route: %s", s->proto->p.name, flow_validated_state_str(r));
      bgp_parse_error(s, 1);
    }

    ip4_addr px = IP4_NONE;
    uint pxlen = 0;

    /* Decode dst prefix */
    if (data[0] == FLOW_TYPE_DST_PREFIX)
    {
      px = flow_read_ip4_part(data);
      pxlen = flow_read_pxlen(data);
    }

    /* Prepare the flow */
    net_addr *n = alloca(sizeof(struct net_addr_flow4) + flen);
    net_fill_flow4(n, px, pxlen, pos, flen);
    ADVANCE(pos, len, flen);

    bgp_rte_update(s, n, path_id, a);
  }
}


static uint
bgp_encode_nlri_flow6(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, uint size)
{
  byte *pos = buf;

  while (!EMPTY_LIST(buck->prefixes) && (size >= 4))
  {
    struct bgp_prefix *px = HEAD(buck->prefixes);
    struct net_addr_flow6 *net = (void *) px->net;
    uint flen = net->length - sizeof(net_addr_flow6);

    /* Encode path ID */
    if (s->add_path)
    {
      put_u32(pos, px->path_id);
      ADVANCE(pos, size, 4);
    }

    if (flen > size)
      break;

    /* Copy whole flow data including length */
    memcpy(pos, net->data, flen);
    ADVANCE(pos, size, flen);

    bgp_free_prefix(s->channel, px);
  }

  return pos - buf;
}

static void
bgp_decode_nlri_flow6(struct bgp_parse_state *s, byte *pos, uint len, rta *a)
{
  while (len)
  {
    u32 path_id = 0;

    /* Decode path ID */
    if (s->add_path)
    {
      if (len < 4)
	bgp_parse_error(s, 1);

      path_id = get_u32(pos);
      ADVANCE(pos, len, 4);
    }

    if (len < 2)
      bgp_parse_error(s, 1);

    /* Decode flow length */
    uint hlen = flow_hdr_length(pos);
    uint dlen = flow_read_length(pos);
    uint flen = hlen + dlen;
    byte *data = pos + hlen;

    if (len < flen)
      bgp_parse_error(s, 1);

    /* Validate flow data */
    enum flow_validated_state r = flow6_validate(data, dlen);
    if (r != FLOW_ST_VALID)
    {
      log(L_REMOTE "%s: Invalid flow route: %s", s->proto->p.name, flow_validated_state_str(r));
      bgp_parse_error(s, 1);
    }

    ip6_addr px = IP6_NONE;
    uint pxlen = 0;

    /* Decode dst prefix */
    if (data[0] == FLOW_TYPE_DST_PREFIX)
    {
      px = flow_read_ip6_part(data);
      pxlen = flow_read_pxlen(data);
    }

    /* Prepare the flow */
    net_addr *n = alloca(sizeof(struct net_addr_flow6) + flen);
    net_fill_flow6(n, px, pxlen, pos, flen);
    ADVANCE(pos, len, flen);

    bgp_rte_update(s, n, path_id, a);
  }
}


static const struct bgp_af_desc bgp_af_table[] = {
  {
    .afi = BGP_AF_IPV4,
    .net = NET_IP4,
    .name = "ipv4",
    .encode_nlri = bgp_encode_nlri_ip4,
    .decode_nlri = bgp_decode_nlri_ip4,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_IPV4_MC,
    .net = NET_IP4,
    .name = "ipv4-mc",
    .encode_nlri = bgp_encode_nlri_ip4,
    .decode_nlri = bgp_decode_nlri_ip4,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_IPV4_MPLS,
    .net = NET_IP4,
    .mpls = 1,
    .name = "ipv4-mpls",
    .encode_nlri = bgp_encode_nlri_ip4,
    .decode_nlri = bgp_decode_nlri_ip4,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_IPV6,
    .net = NET_IP6,
    .name = "ipv6",
    .encode_nlri = bgp_encode_nlri_ip6,
    .decode_nlri = bgp_decode_nlri_ip6,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_IPV6_MC,
    .net = NET_IP6,
    .name = "ipv6-mc",
    .encode_nlri = bgp_encode_nlri_ip6,
    .decode_nlri = bgp_decode_nlri_ip6,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_IPV6_MPLS,
    .net = NET_IP6,
    .mpls = 1,
    .name = "ipv6-mpls",
    .encode_nlri = bgp_encode_nlri_ip6,
    .decode_nlri = bgp_decode_nlri_ip6,
    .encode_next_hop = bgp_encode_next_hop_ip,
    .decode_next_hop = bgp_decode_next_hop_ip,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_VPN4_MPLS,
    .net = NET_VPN4,
    .mpls = 1,
    .name = "vpn4-mpls",
    .encode_nlri = bgp_encode_nlri_vpn4,
    .decode_nlri = bgp_decode_nlri_vpn4,
    .encode_next_hop = bgp_encode_next_hop_vpn,
    .decode_next_hop = bgp_decode_next_hop_vpn,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_VPN6_MPLS,
    .net = NET_VPN6,
    .mpls = 1,
    .name = "vpn6-mpls",
    .encode_nlri = bgp_encode_nlri_vpn6,
    .decode_nlri = bgp_decode_nlri_vpn6,
    .encode_next_hop = bgp_encode_next_hop_vpn,
    .decode_next_hop = bgp_decode_next_hop_vpn,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_VPN4_MC,
    .net = NET_VPN4,
    .name = "vpn4-mc",
    .encode_nlri = bgp_encode_nlri_vpn4,
    .decode_nlri = bgp_decode_nlri_vpn4,
    .encode_next_hop = bgp_encode_next_hop_vpn,
    .decode_next_hop = bgp_decode_next_hop_vpn,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_VPN6_MC,
    .net = NET_VPN6,
    .name = "vpn6-mc",
    .encode_nlri = bgp_encode_nlri_vpn6,
    .decode_nlri = bgp_decode_nlri_vpn6,
    .encode_next_hop = bgp_encode_next_hop_vpn,
    .decode_next_hop = bgp_decode_next_hop_vpn,
    .update_next_hop = bgp_update_next_hop_ip,
  },
  {
    .afi = BGP_AF_FLOW4,
    .net = NET_FLOW4,
    .no_igp = 1,
    .name = "flow4",
    .encode_nlri = bgp_encode_nlri_flow4,
    .decode_nlri = bgp_decode_nlri_flow4,
    .encode_next_hop = bgp_encode_next_hop_none,
    .decode_next_hop = bgp_decode_next_hop_none,
    .update_next_hop = bgp_update_next_hop_none,
  },
  {
    .afi = BGP_AF_FLOW6,
    .net = NET_FLOW6,
    .no_igp = 1,
    .name = "flow6",
    .encode_nlri = bgp_encode_nlri_flow6,
    .decode_nlri = bgp_decode_nlri_flow6,
    .encode_next_hop = bgp_encode_next_hop_none,
    .decode_next_hop = bgp_decode_next_hop_none,
    .update_next_hop = bgp_update_next_hop_none,
  },
};

const struct bgp_af_desc *
bgp_get_af_desc(u32 afi)
{
  uint i;
  for (i = 0; i < ARRAY_SIZE(bgp_af_table); i++)
    if (bgp_af_table[i].afi == afi)
      return &bgp_af_table[i];

  return NULL;
}

static inline uint
bgp_encode_nlri(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, byte *end)
{
  return s->channel->desc->encode_nlri(s, buck, buf, end - buf);
}

static inline uint
bgp_encode_next_hop(struct bgp_write_state *s, eattr *nh, byte *buf)
{
  return s->channel->desc->encode_next_hop(s, nh, buf, 255);
}

void
bgp_update_next_hop(struct bgp_export_state *s, eattr *a, ea_list **to)
{
  s->channel->desc->update_next_hop(s, a, to);
}

#define MAX_ATTRS_LENGTH (end-buf+BGP_HEADER_LENGTH - 1024)

static byte *
bgp_create_ip_reach(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, byte *end)
{
  /*
   *	2 B	Withdrawn Routes Length (zero)
   *	---	IPv4 Withdrawn Routes NLRI (unused)
   *	2 B	Total Path Attribute Length
   *	var	Path Attributes
   *	var	IPv4 Network Layer Reachability Information
   */

  int lr, la;

  la = bgp_encode_attrs(s, buck->eattrs, buf+4, buf + MAX_ATTRS_LENGTH);
  if (la < 0)
  {
    /* Attribute list too long */
    bgp_withdraw_bucket(s->channel, buck);
    return NULL;
  }

  put_u16(buf+0, 0);
  put_u16(buf+2, la);

  lr = bgp_encode_nlri(s, buck, buf+4+la, end);

  return buf+4+la+lr;
}

static byte *
bgp_create_mp_reach(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, byte *end)
{
  /*
   *	2 B	IPv4 Withdrawn Routes Length (zero)
   *	---	IPv4 Withdrawn Routes NLRI (unused)
   *	2 B	Total Path Attribute Length
   *	1 B	MP_REACH_NLRI hdr - Attribute Flags
   *	1 B	MP_REACH_NLRI hdr - Attribute Type Code
   *	2 B	MP_REACH_NLRI hdr - Length of Attribute Data
   *	2 B	MP_REACH_NLRI data - Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Subsequent Address Family Identifier
   *	1 B	MP_REACH_NLRI data - Length of Next Hop Network Address
   *	var	MP_REACH_NLRI data - Network Address of Next Hop
   *	1 B	MP_REACH_NLRI data - Reserved (zero)
   *	var	MP_REACH_NLRI data - Network Layer Reachability Information
   *	var	Rest of Path Attributes
   *	---	IPv4 Network Layer Reachability Information (unused)
   */

  int lh, lr, la;	/* Lengths of next hop, NLRI and attributes */

  /* Begin of MP_REACH_NLRI atribute */
  buf[4] = BAF_OPTIONAL | BAF_EXT_LEN;
  buf[5] = BA_MP_REACH_NLRI;
  put_u16(buf+6, 0);		/* Will be fixed later */
  put_af3(buf+8, s->channel->afi);
  byte *pos = buf+11;

  /* Encode attributes to temporary buffer */
  byte *abuf = alloca(MAX_ATTRS_LENGTH);
  la = bgp_encode_attrs(s, buck->eattrs, abuf, abuf + MAX_ATTRS_LENGTH);
  if (la < 0)
  {
    /* Attribute list too long */
    bgp_withdraw_bucket(s->channel, buck);
    return NULL;
  }

  /* Encode the next hop */
  lh = bgp_encode_next_hop(s, s->mp_next_hop, pos+1);
  *pos = lh;
  pos += 1+lh;

  /* Reserved field */
  *pos++ = 0;

  /* Encode the NLRI */
  lr = bgp_encode_nlri(s, buck, pos, end - la);
  pos += lr;

  /* End of MP_REACH_NLRI atribute, update data length */
  put_u16(buf+6, pos-buf-8);

  /* Copy remaining attributes */
  memcpy(pos, abuf, la);
  pos += la;

  /* Initial UPDATE fields */
  put_u16(buf+0, 0);
  put_u16(buf+2, pos-buf-4);

  return pos;
}

#undef MAX_ATTRS_LENGTH

static byte *
bgp_create_ip_unreach(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, byte *end)
{
  /*
   *	2 B	Withdrawn Routes Length
   *	var	IPv4 Withdrawn Routes NLRI
   *	2 B	Total Path Attribute Length (zero)
   *	---	Path Attributes (unused)
   *	---	IPv4 Network Layer Reachability Information (unused)
   */

  uint len = bgp_encode_nlri(s, buck, buf+2, end);

  put_u16(buf+0, len);
  put_u16(buf+2+len, 0);

  return buf+4+len;
}

static byte *
bgp_create_mp_unreach(struct bgp_write_state *s, struct bgp_bucket *buck, byte *buf, byte *end)
{
  /*
   *	2 B	Withdrawn Routes Length (zero)
   *	---	IPv4 Withdrawn Routes NLRI (unused)
   *	2 B	Total Path Attribute Length
   *	1 B	MP_UNREACH_NLRI hdr - Attribute Flags
   *	1 B	MP_UNREACH_NLRI hdr - Attribute Type Code
   *	2 B	MP_UNREACH_NLRI hdr - Length of Attribute Data
   *	2 B	MP_UNREACH_NLRI data - Address Family Identifier
   *	1 B	MP_UNREACH_NLRI data - Subsequent Address Family Identifier
   *	var	MP_UNREACH_NLRI data - Network Layer Reachability Information
   *	---	IPv4 Network Layer Reachability Information (unused)
   */

  uint len = bgp_encode_nlri(s, buck, buf+11, end);

  put_u16(buf+0, 0);
  put_u16(buf+2, 7+len);

  /* Begin of MP_UNREACH_NLRI atribute */
  buf[4] = BAF_OPTIONAL | BAF_EXT_LEN;
  buf[5] = BA_MP_UNREACH_NLRI;
  put_u16(buf+6, 3+len);
  put_af3(buf+8, s->channel->afi);

  return buf+11+len;
}

static byte *
bgp_create_update(struct bgp_channel *c, byte *buf)
{
  struct bgp_proto *p = (void *) c->c.proto;
  struct bgp_bucket *buck;
  byte *end = buf + (bgp_max_packet_length(p->conn) - BGP_HEADER_LENGTH);
  byte *res = NULL;

again: ;

  /* Initialize write state */
  struct bgp_write_state s = {
    .proto = p,
    .channel = c,
    .pool = bgp_linpool,
    .mp_reach = (c->afi != BGP_AF_IPV4) || c->ext_next_hop,
    .as4_session = p->as4_session,
    .add_path = c->add_path_tx,
    .mpls = c->desc->mpls,
  };

  /* Try unreachable bucket */
  if ((buck = c->withdraw_bucket) && !EMPTY_LIST(buck->prefixes))
  {
    res = (c->afi == BGP_AF_IPV4) && !c->ext_next_hop ?
      bgp_create_ip_unreach(&s, buck, buf, end):
      bgp_create_mp_unreach(&s, buck, buf, end);

    goto done;
  }

  /* Try reachable buckets */
  if (!EMPTY_LIST(c->bucket_queue))
  {
    buck = HEAD(c->bucket_queue);

    /* Cleanup empty buckets */
    if (EMPTY_LIST(buck->prefixes))
    {
      bgp_free_bucket(c, buck);
      goto again;
    }

    res = !s.mp_reach ?
      bgp_create_ip_reach(&s, buck, buf, end):
      bgp_create_mp_reach(&s, buck, buf, end);

    if (EMPTY_LIST(buck->prefixes))
      bgp_free_bucket(c, buck);
    else
      bgp_defer_bucket(c, buck);

    if (!res)
      goto again;

    goto done;
  }

  /* No more prefixes to send */
  return NULL;

done:
  BGP_TRACE_RL(&rl_snd_update, D_PACKETS, "Sending UPDATE");
  p->stats.tx_updates++;
  lp_flush(s.pool);

  return res;
}

static byte *
bgp_create_ip_end_mark(struct bgp_channel *c UNUSED, byte *buf)
{
  /* Empty update packet */
  put_u32(buf, 0);

  return buf+4;
}

static byte *
bgp_create_mp_end_mark(struct bgp_channel *c, byte *buf)
{
  put_u16(buf+0, 0);
  put_u16(buf+2, 6);		/* length 4--9 */

  /* Empty MP_UNREACH_NLRI atribute */
  buf[4] = BAF_OPTIONAL;
  buf[5] = BA_MP_UNREACH_NLRI;
  buf[6] = 3;			/* Length 7--9 */
  put_af3(buf+7, c->afi);

  return buf+10;
}

static byte *
bgp_create_end_mark(struct bgp_channel *c, byte *buf)
{
  struct bgp_proto *p = (void *) c->c.proto;

  BGP_TRACE(D_PACKETS, "Sending END-OF-RIB");
  p->stats.tx_updates++;

  return (c->afi == BGP_AF_IPV4) ?
    bgp_create_ip_end_mark(c, buf):
    bgp_create_mp_end_mark(c, buf);
}

static inline void
bgp_rx_end_mark(struct bgp_parse_state *s, u32 afi)
{
  struct bgp_proto *p = s->proto;
  struct bgp_channel *c = bgp_get_channel(p, afi);

  BGP_TRACE(D_PACKETS, "Got END-OF-RIB");

  if (!c)
    DISCARD(BAD_AFI, BGP_AFI(afi), BGP_SAFI(afi));

  if (c->load_state == BFS_LOADING)
    c->load_state = BFS_NONE;

  if (p->p.gr_recovery)
    channel_graceful_restart_unlock(&c->c);

  if (c->gr_active)
    bgp_graceful_restart_done(c);
}

static inline void
bgp_decode_nlri(struct bgp_parse_state *s, u32 afi, byte *nlri, uint len, ea_list *ea, byte *nh, uint nh_len)
{
  struct bgp_channel *c = bgp_get_channel(s->proto, afi);
  rta *a = NULL;

  if (!c)
    DISCARD(BAD_AFI, BGP_AFI(afi), BGP_SAFI(afi));

  s->channel = c;
  s->add_path = c->add_path_rx;
  s->mpls = c->desc->mpls;

  s->last_id = 0;
  s->last_src = s->proto->p.main_source;

  /*
   * IPv4 BGP and MP-BGP may be used together in one update, therefore we do not
   * add BA_NEXT_HOP in bgp_decode_attrs(), but we add it here independently for
   * IPv4 BGP and MP-BGP. We undo the attribute (and possibly others attached by
   * decode_next_hop hooks) by restoring a->eattrs afterwards.
   */

  if (ea)
  {
    a = allocz(RTA_MAX_SIZE);

    a->source = RTS_BGP;
    a->scope = SCOPE_UNIVERSE;
    a->from = s->proto->remote_ip;
    a->eattrs = ea;

    c->desc->decode_next_hop(s, nh, nh_len, a);
    bgp_finish_attrs(s, a);

    /* Handle withdraw during next hop decoding */
    if (s->err_withdraw)
      a = NULL;
  }

  c->desc->decode_nlri(s, nlri, len, a);

  rta_free(s->cached_rta);
  s->cached_rta = NULL;
}

static void
bgp_rx_update(struct bgp_conn *conn, byte *pkt, uint len)
{
  struct bgp_proto *p = conn->bgp;
  ea_list *ea = NULL;

  BGP_TRACE_RL(&rl_rcv_update, D_PACKETS, "Got UPDATE");
  p->last_rx_update = current_time();
  p->stats.rx_updates++;

  /* Workaround for some BGP implementations that skip initial KEEPALIVE */
  if (conn->state == BS_OPENCONFIRM)
    bgp_conn_enter_established_state(conn);

  if (conn->state != BS_ESTABLISHED)
  { bgp_error(conn, 5, fsm_err_subcode[conn->state], NULL, 0); return; }

  bgp_start_timer(conn->hold_timer, conn->hold_time);

  /* Initialize parse state */
  struct bgp_parse_state s = {
    .proto = p,
    .pool = bgp_linpool,
    .as4_session = p->as4_session,
  };

  /* Parse error handler */
  if (setjmp(s.err_jmpbuf))
  {
    bgp_error(conn, 3, s.err_subcode, NULL, 0);
    goto done;
  }

  /* Check minimal length */
  if (len < 23)
  { bgp_error(conn, 1, 2, pkt+16, 2); return; }

  /* Skip fixed header */
  uint pos = 19;

  /*
   *	UPDATE message format
   *
   *	2 B	IPv4 Withdrawn Routes Length
   *	var	IPv4 Withdrawn Routes NLRI
   *	2 B	Total Path Attribute Length
   *	var	Path Attributes
   *	var	IPv4 Reachable Routes NLRI
   */

  s.ip_unreach_len = get_u16(pkt + pos);
  s.ip_unreach_nlri = pkt + pos + 2;
  pos += 2 + s.ip_unreach_len;

  if (pos + 2 > len)
    bgp_parse_error(&s, 1);

  s.attr_len = get_u16(pkt + pos);
  s.attrs = pkt + pos + 2;
  pos += 2 + s.attr_len;

  if (pos > len)
    bgp_parse_error(&s, 1);

  s.ip_reach_len = len - pos;
  s.ip_reach_nlri = pkt + pos;


  if (s.attr_len)
    ea = bgp_decode_attrs(&s, s.attrs, s.attr_len);
  else
    ea = NULL;

  /* Check for End-of-RIB marker */
  if (!s.attr_len && !s.ip_unreach_len && !s.ip_reach_len)
  { bgp_rx_end_mark(&s, BGP_AF_IPV4); goto done; }

  /* Check for MP End-of-RIB marker */
  if ((s.attr_len < 8) && !s.ip_unreach_len && !s.ip_reach_len &&
      !s.mp_reach_len && !s.mp_unreach_len && s.mp_unreach_af)
  { bgp_rx_end_mark(&s, s.mp_unreach_af); goto done; }

  if (s.ip_unreach_len)
    bgp_decode_nlri(&s, BGP_AF_IPV4, s.ip_unreach_nlri, s.ip_unreach_len, NULL, NULL, 0);

  if (s.mp_unreach_len)
    bgp_decode_nlri(&s, s.mp_unreach_af, s.mp_unreach_nlri, s.mp_unreach_len, NULL, NULL, 0);

  if (s.ip_reach_len)
    bgp_decode_nlri(&s, BGP_AF_IPV4, s.ip_reach_nlri, s.ip_reach_len,
		    ea, s.ip_next_hop_data, s.ip_next_hop_len);

  if (s.mp_reach_len)
    bgp_decode_nlri(&s, s.mp_reach_af, s.mp_reach_nlri, s.mp_reach_len,
		    ea, s.mp_next_hop_data, s.mp_next_hop_len);

done:
  rta_free(s.cached_rta);
  lp_flush(s.pool);
  return;
}

static uint
bgp_find_update_afi(byte *pos, uint len)
{
  /*
   * This is stripped-down version of bgp_rx_update(), bgp_decode_attrs() and
   * bgp_decode_mp_[un]reach_nlri() used by MRT code in order to find out which
   * AFI/SAFI is associated with incoming UPDATE. Returns 0 for framing errors.
   */
  if (len < 23)
    return 0;

  /* Assume there is no withrawn NLRI, read lengths and move to attribute list */
  uint wlen = get_u16(pos + 19);
  uint alen = get_u16(pos + 21);
  ADVANCE(pos, len, 23);

  /* Either non-zero withdrawn NLRI, non-zero reachable NLRI, or IPv4 End-of-RIB */
  if ((wlen != 0) || (alen < len) || !alen)
    return BGP_AF_IPV4;

  if (alen > len)
    return 0;

  /* Process attribute list (alen == len) */
  while (len)
  {
    if (len < 2)
      return 0;

    uint flags = pos[0];
    uint code = pos[1];
    ADVANCE(pos, len, 2);

    uint ll = !(flags & BAF_EXT_LEN) ? 1 : 2;
    if (len < ll)
      return 0;

    /* Read attribute length and move to attribute body */
    alen = (ll == 1) ? get_u8(pos) : get_u16(pos);
    ADVANCE(pos, len, ll);

    if (len < alen)
      return 0;

    /* Found MP NLRI */
    if ((code == BA_MP_REACH_NLRI) || (code == BA_MP_UNREACH_NLRI))
    {
      if (alen < 3)
	return 0;

      return BGP_AF(get_u16(pos), pos[2]);
    }

    /* Move to the next attribute */
    ADVANCE(pos, len, alen);
  }

  /* No basic or MP NLRI, but there are some attributes -> error */
  return 0;
}


/*
 *	ROUTE-REFRESH
 */

static inline byte *
bgp_create_route_refresh(struct bgp_channel *c, byte *buf)
{
  struct bgp_proto *p = (void *) c->c.proto;

  BGP_TRACE(D_PACKETS, "Sending ROUTE-REFRESH");

  /* Original route refresh request, RFC 2918 */
  put_af4(buf, c->afi);
  buf[2] = BGP_RR_REQUEST;

  return buf+4;
}

static inline byte *
bgp_create_begin_refresh(struct bgp_channel *c, byte *buf)
{
  struct bgp_proto *p = (void *) c->c.proto;

  BGP_TRACE(D_PACKETS, "Sending BEGIN-OF-RR");

  /* Demarcation of beginning of route refresh (BoRR), RFC 7313 */
  put_af4(buf, c->afi);
  buf[2] = BGP_RR_BEGIN;

  return buf+4;
}

static inline byte *
bgp_create_end_refresh(struct bgp_channel *c, byte *buf)
{
  struct bgp_proto *p = (void *) c->c.proto;

  BGP_TRACE(D_PACKETS, "Sending END-OF-RR");

  /* Demarcation of ending of route refresh (EoRR), RFC 7313 */
  put_af4(buf, c->afi);
  buf[2] = BGP_RR_END;

  return buf+4;
}

static void
bgp_rx_route_refresh(struct bgp_conn *conn, byte *pkt, uint len)
{
  struct bgp_proto *p = conn->bgp;

  if (conn->state != BS_ESTABLISHED)
  { bgp_error(conn, 5, fsm_err_subcode[conn->state], NULL, 0); return; }

  if (!conn->local_caps->route_refresh)
  { bgp_error(conn, 1, 3, pkt+18, 1); return; }

  if (len < (BGP_HEADER_LENGTH + 4))
  { bgp_error(conn, 1, 2, pkt+16, 2); return; }

  if (len > (BGP_HEADER_LENGTH + 4))
  { bgp_error(conn, 7, 1, pkt, MIN(len, 2048)); return; }

  struct bgp_channel *c = bgp_get_channel(p, get_af4(pkt+19));
  if (!c)
  {
    log(L_WARN "%s: Got ROUTE-REFRESH subtype %u for AF %u.%u, ignoring",
	p->p.name, pkt[21], get_u16(pkt+19), pkt[22]);
    return;
  }

  /* RFC 7313 redefined reserved field as RR message subtype */
  uint subtype = p->enhanced_refresh ? pkt[21] : BGP_RR_REQUEST;

  switch (subtype)
  {
  case BGP_RR_REQUEST:
    BGP_TRACE(D_PACKETS, "Got ROUTE-REFRESH");
    channel_request_feeding(&c->c);
    break;

  case BGP_RR_BEGIN:
    BGP_TRACE(D_PACKETS, "Got BEGIN-OF-RR");
    bgp_refresh_begin(c);
    break;

  case BGP_RR_END:
    BGP_TRACE(D_PACKETS, "Got END-OF-RR");
    bgp_refresh_end(c);
    break;

  default:
    log(L_WARN "%s: Got ROUTE-REFRESH message with unknown subtype %u, ignoring",
	p->p.name, subtype);
    break;
  }
}

static inline struct bgp_channel *
bgp_get_channel_to_send(struct bgp_proto *p, struct bgp_conn *conn)
{
  uint i = conn->last_channel;

  /* Try the last channel, but at most several times */
  if ((conn->channels_to_send & (1 << i)) &&
      (conn->last_channel_count < 16))
    goto found;

  /* Find channel with non-zero channels_to_send */
  do
  {
    i++;
    if (i >= p->channel_count)
      i = 0;
  }
  while (! (conn->channels_to_send & (1 << i)));

  /* Use that channel */
  conn->last_channel = i;
  conn->last_channel_count = 0;

found:
  conn->last_channel_count++;
  return p->channel_map[i];
}

static inline int
bgp_send(struct bgp_conn *conn, uint type, uint len)
{
  sock *sk = conn->sk;
  byte *buf = sk->tbuf;

  conn->bgp->stats.tx_messages++;
  conn->bgp->stats.tx_bytes += len;

  memset(buf, 0xff, 16);		/* Marker */
  put_u16(buf+16, len);
  buf[18] = type;

  return sk_send(sk, len);
}

/**
 * bgp_fire_tx - transmit packets
 * @conn: connection
 *
 * Whenever the transmit buffers of the underlying TCP connection
 * are free and we have any packets queued for sending, the socket functions
 * call bgp_fire_tx() which takes care of selecting the highest priority packet
 * queued (Notification > Keepalive > Open > Update), assembling its header
 * and body and sending it to the connection.
 */
static int
bgp_fire_tx(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;
  struct bgp_channel *c;
  byte *buf, *pkt, *end;
  uint s;

  if (!conn->sk)
    return 0;

  buf = conn->sk->tbuf;
  pkt = buf + BGP_HEADER_LENGTH;
  s = conn->packets_to_send;

  if (s & (1 << PKT_SCHEDULE_CLOSE))
  {
    /* We can finally close connection and enter idle state */
    bgp_conn_enter_idle_state(conn);
    return 0;
  }
  if (s & (1 << PKT_NOTIFICATION))
  {
    conn->packets_to_send = 1 << PKT_SCHEDULE_CLOSE;
    end = bgp_create_notification(conn, pkt);
    return bgp_send(conn, PKT_NOTIFICATION, end - buf);
  }
  else if (s & (1 << PKT_OPEN))
  {
    conn->packets_to_send &= ~(1 << PKT_OPEN);
    end = bgp_create_open(conn, pkt);
    return bgp_send(conn, PKT_OPEN, end - buf);
  }
  else if (s & (1 << PKT_KEEPALIVE))
  {
    conn->packets_to_send &= ~(1 << PKT_KEEPALIVE);
    BGP_TRACE(D_PACKETS, "Sending KEEPALIVE");
    bgp_start_timer(conn->keepalive_timer, conn->keepalive_time);
    return bgp_send(conn, PKT_KEEPALIVE, BGP_HEADER_LENGTH);
  }
  else while (conn->channels_to_send)
  {
    c = bgp_get_channel_to_send(p, conn);
    s = c->packets_to_send;

    if (s & (1 << PKT_ROUTE_REFRESH))
    {
      c->packets_to_send &= ~(1 << PKT_ROUTE_REFRESH);
      end = bgp_create_route_refresh(c, pkt);
      return bgp_send(conn, PKT_ROUTE_REFRESH, end - buf);
    }
    else if (s & (1 << PKT_BEGIN_REFRESH))
    {
      /* BoRR is a subtype of RR, but uses separate bit in packets_to_send */
      c->packets_to_send &= ~(1 << PKT_BEGIN_REFRESH);
      end = bgp_create_begin_refresh(c, pkt);
      return bgp_send(conn, PKT_ROUTE_REFRESH, end - buf);
    }
    else if (s & (1 << PKT_UPDATE))
    {
      end = bgp_create_update(c, pkt);
      if (end)
	return bgp_send(conn, PKT_UPDATE, end - buf);

      /* No update to send, perhaps we need to send End-of-RIB or EoRR */
      c->packets_to_send = 0;
      conn->channels_to_send &= ~(1 << c->index);

      if (c->feed_state == BFS_LOADED)
      {
	c->feed_state = BFS_NONE;
	end = bgp_create_end_mark(c, pkt);
	return bgp_send(conn, PKT_UPDATE, end - buf);
      }

      else if (c->feed_state == BFS_REFRESHED)
      {
	c->feed_state = BFS_NONE;
	end = bgp_create_end_refresh(c, pkt);
	return bgp_send(conn, PKT_ROUTE_REFRESH, end - buf);
      }
    }
    else if (s)
      bug("Channel packets_to_send: %x", s);

    c->packets_to_send = 0;
    conn->channels_to_send &= ~(1 << c->index);
  }

  return 0;
}

/**
 * bgp_schedule_packet - schedule a packet for transmission
 * @conn: connection
 * @c: channel
 * @type: packet type
 *
 * Schedule a packet of type @type to be sent as soon as possible.
 */
void
bgp_schedule_packet(struct bgp_conn *conn, struct bgp_channel *c, int type)
{
  ASSERT(conn->sk);

  DBG("BGP: Scheduling packet type %d\n", type);

  if (c)
  {
    if (! conn->channels_to_send)
    {
      conn->last_channel = c->index;
      conn->last_channel_count = 0;
    }

    c->packets_to_send |= 1 << type;
    conn->channels_to_send |= 1 << c->index;
  }
  else
    conn->packets_to_send |= 1 << type;

  if ((conn->sk->tpos == conn->sk->tbuf) && !ev_active(conn->tx_ev))
    ev_schedule(conn->tx_ev);
}
void
bgp_kick_tx(void *vconn)
{
  struct bgp_conn *conn = vconn;

  DBG("BGP: kicking TX\n");
  uint max = 1024;
  while (--max && (bgp_fire_tx(conn) > 0))
    ;

  if (!max && !ev_active(conn->tx_ev))
    ev_schedule(conn->tx_ev);
}

void
bgp_tx(sock *sk)
{
  struct bgp_conn *conn = sk->data;

  DBG("BGP: TX hook\n");
  uint max = 1024;
  while (--max && (bgp_fire_tx(conn) > 0))
    ;

  if (!max && !ev_active(conn->tx_ev))
    ev_schedule(conn->tx_ev);
}


static struct {
  byte major, minor;
  byte *msg;
} bgp_msg_table[] = {
  { 1, 0, "Invalid message header" },
  { 1, 1, "Connection not synchronized" },
  { 1, 2, "Bad message length" },
  { 1, 3, "Bad message type" },
  { 2, 0, "Invalid OPEN message" },
  { 2, 1, "Unsupported version number" },
  { 2, 2, "Bad peer AS" },
  { 2, 3, "Bad BGP identifier" },
  { 2, 4, "Unsupported optional parameter" },
  { 2, 5, "Authentication failure" },
  { 2, 6, "Unacceptable hold time" },
  { 2, 7, "Required capability missing" }, /* [RFC5492] */
  { 2, 8, "No supported AFI/SAFI" }, /* This error msg is nonstandard */
  { 3, 0, "Invalid UPDATE message" },
  { 3, 1, "Malformed attribute list" },
  { 3, 2, "Unrecognized well-known attribute" },
  { 3, 3, "Missing mandatory attribute" },
  { 3, 4, "Invalid attribute flags" },
  { 3, 5, "Invalid attribute length" },
  { 3, 6, "Invalid ORIGIN attribute" },
  { 3, 7, "AS routing loop" },		/* Deprecated */
  { 3, 8, "Invalid NEXT_HOP attribute" },
  { 3, 9, "Optional attribute error" },
  { 3, 10, "Invalid network field" },
  { 3, 11, "Malformed AS_PATH" },
  { 4, 0, "Hold timer expired" },
  { 5, 0, "Finite state machine error" }, /* Subcodes are according to [RFC6608] */
  { 5, 1, "Unexpected message in OpenSent state" },
  { 5, 2, "Unexpected message in OpenConfirm state" },
  { 5, 3, "Unexpected message in Established state" },
  { 6, 0, "Cease" }, /* Subcodes are according to [RFC4486] */
  { 6, 1, "Maximum number of prefixes reached" },
  { 6, 2, "Administrative shutdown" },
  { 6, 3, "Peer de-configured" },
  { 6, 4, "Administrative reset" },
  { 6, 5, "Connection rejected" },
  { 6, 6, "Other configuration change" },
  { 6, 7, "Connection collision resolution" },
  { 6, 8, "Out of Resources" },
  { 7, 0, "Invalid ROUTE-REFRESH message" }, /* [RFC7313] */
  { 7, 1, "Invalid ROUTE-REFRESH message length" } /* [RFC7313] */
};

/**
 * bgp_error_dsc - return BGP error description
 * @code: BGP error code
 * @subcode: BGP error subcode
 *
 * bgp_error_dsc() returns error description for BGP errors
 * which might be static string or given temporary buffer.
 */
const char *
bgp_error_dsc(uint code, uint subcode)
{
  static char buff[32];
  uint i;

  for (i=0; i < ARRAY_SIZE(bgp_msg_table); i++)
    if (bgp_msg_table[i].major == code && bgp_msg_table[i].minor == subcode)
      return bgp_msg_table[i].msg;

  bsprintf(buff, "Unknown error %u.%u", code, subcode);
  return buff;
}

/* RFC 8203 - shutdown communication message */
static int
bgp_handle_message(struct bgp_proto *p, byte *data, uint len, byte **bp)
{
  byte *msg = data + 1;
  uint msg_len = data[0];
  uint i;

  /* Handle zero length message */
  if (msg_len == 0)
    return 1;

  /* Handle proper message */
  if (msg_len + 1 > len)
    return 0;

  /* Some elementary cleanup */
  for (i = 0; i < msg_len; i++)
    if (msg[i] < ' ')
      msg[i] = ' ';

  proto_set_message(&p->p, msg, msg_len);
  *bp += bsprintf(*bp, ": \"%s\"", p->p.message);
  return 1;
}

void
bgp_log_error(struct bgp_proto *p, u8 class, char *msg, uint code, uint subcode, byte *data, uint len)
{
  byte argbuf[256+16], *t = argbuf;
  uint i;

  /* Don't report Cease messages generated by myself */
  if (code == 6 && class == BE_BGP_TX)
    return;

  /* Reset shutdown message */
  if ((code == 6) && ((subcode == 2) || (subcode == 4)))
    proto_set_message(&p->p, NULL, 0);

  if (len)
    {
      /* Bad peer AS - we would like to print the AS */
      if ((code == 2) && (subcode == 2) && ((len == 2) || (len == 4)))
	{
	  t += bsprintf(t, ": %u", (len == 2) ? get_u16(data) : get_u32(data));
	  goto done;
	}

      /* RFC 8203 - shutdown communication */
      if (((code == 6) && ((subcode == 2) || (subcode == 4))))
	if (bgp_handle_message(p, data, len, &t))
	  goto done;

      *t++ = ':';
      *t++ = ' ';
      if (len > 16)
	len = 16;
      for (i=0; i<len; i++)
	t += bsprintf(t, "%02x", data[i]);
    }

done:
  *t = 0;
  const byte *dsc = bgp_error_dsc(code, subcode);
  log(L_REMOTE "%s: %s: %s%s", p->p.name, msg, dsc, argbuf);
}

static void
bgp_rx_notification(struct bgp_conn *conn, byte *pkt, uint len)
{
  struct bgp_proto *p = conn->bgp;

  if (len < 21)
  { bgp_error(conn, 1, 2, pkt+16, 2); return; }

  uint code = pkt[19];
  uint subcode = pkt[20];
  int err = (code != 6);

  bgp_log_error(p, BE_BGP_RX, "Received", code, subcode, pkt+21, len-21);
  bgp_store_error(p, conn, BE_BGP_RX, (code << 16) | subcode);

  bgp_conn_enter_close_state(conn);
  bgp_schedule_packet(conn, NULL, PKT_SCHEDULE_CLOSE);

  if (err)
  {
    bgp_update_startup_delay(p);
    bgp_stop(p, 0, NULL, 0);
  }
  else
  {
    uint subcode_bit = 1 << ((subcode <= 8) ? subcode : 0);
    if (p->cf->disable_after_cease & subcode_bit)
    {
      log(L_INFO "%s: Disabled after Cease notification", p->p.name);
      p->startup_delay = 0;
      p->p.disabled = 1;
    }
  }
}

static void
bgp_rx_keepalive(struct bgp_conn *conn)
{
  struct bgp_proto *p = conn->bgp;

  BGP_TRACE(D_PACKETS, "Got KEEPALIVE");
  bgp_start_timer(conn->hold_timer, conn->hold_time);

  if (conn->state == BS_OPENCONFIRM)
  { bgp_conn_enter_established_state(conn); return; }

  if (conn->state != BS_ESTABLISHED)
    bgp_error(conn, 5, fsm_err_subcode[conn->state], NULL, 0);
}


/**
 * bgp_rx_packet - handle a received packet
 * @conn: BGP connection
 * @pkt: start of the packet
 * @len: packet size
 *
 * bgp_rx_packet() takes a newly received packet and calls the corresponding
 * packet handler according to the packet type.
 */
static void
bgp_rx_packet(struct bgp_conn *conn, byte *pkt, uint len)
{
  byte type = pkt[18];

  DBG("BGP: Got packet %02x (%d bytes)\n", type, len);
  conn->bgp->stats.rx_messages++;
  conn->bgp->stats.rx_bytes += len;

  if (conn->bgp->p.mrtdump & MD_MESSAGES)
    bgp_dump_message(conn, pkt, len);

  switch (type)
  {
  case PKT_OPEN:		return bgp_rx_open(conn, pkt, len);
  case PKT_UPDATE:		return bgp_rx_update(conn, pkt, len);
  case PKT_NOTIFICATION:	return bgp_rx_notification(conn, pkt, len);
  case PKT_KEEPALIVE:		return bgp_rx_keepalive(conn);
  case PKT_ROUTE_REFRESH:	return bgp_rx_route_refresh(conn, pkt, len);
  default:			bgp_error(conn, 1, 3, pkt+18, 1);
  }
}

/**
 * bgp_rx - handle received data
 * @sk: socket
 * @size: amount of data received
 *
 * bgp_rx() is called by the socket layer whenever new data arrive from
 * the underlying TCP connection. It assembles the data fragments to packets,
 * checks their headers and framing and passes complete packets to
 * bgp_rx_packet().
 */
int
bgp_rx(sock *sk, uint size)
{
  struct bgp_conn *conn = sk->data;
  byte *pkt_start = sk->rbuf;
  byte *end = pkt_start + size;
  uint i, len;

  DBG("BGP: RX hook: Got %d bytes\n", size);
  while (end >= pkt_start + BGP_HEADER_LENGTH)
    {
      if ((conn->state == BS_CLOSE) || (conn->sk != sk))
	return 0;
      for(i=0; i<16; i++)
	if (pkt_start[i] != 0xff)
	  {
	    bgp_error(conn, 1, 1, NULL, 0);
	    break;
	  }
      len = get_u16(pkt_start+16);
      if ((len < BGP_HEADER_LENGTH) || (len > bgp_max_packet_length(conn)))
	{
	  bgp_error(conn, 1, 2, pkt_start+16, 2);
	  break;
	}
      if (end < pkt_start + len)
	break;
      bgp_rx_packet(conn, pkt_start, len);
      pkt_start += len;
    }
  if (pkt_start != sk->rbuf)
    {
      memmove(sk->rbuf, pkt_start, end - pkt_start);
      sk->rpos = sk->rbuf + (end - pkt_start);
    }
  return 0;
}

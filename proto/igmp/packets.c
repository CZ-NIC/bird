/*
 *  BIRD --IGMP protocol
 *
 *  (c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "igmp.h"
#include "lib/checksum.h"

struct igmp_pkt {
  u8 type;
  u8 resp_time;
  u16 checksum;
  u32 addr;
};

#define IGMP_TP_MS_QUERY	0x11
#define IGMP_TP_V1_MS_REPORT	0x12
#define IGMP_TP_V2_MS_REPORT	0x16
#define IGMP_TP_LEAVE		0x17

#define DROP(args...) do { TRACE(D_PACKETS, "Dropping packet: " args); goto drop; } while(0)
int
igmp_accept(struct igmp_iface *ifa, ip4_addr from, struct igmp_pkt *pkt)
{
  struct igmp_proto *p = ifa->proto;

  if (pkt->type == IGMP_TP_MS_QUERY)
    return igmp_query_received(ifa, from);

  ip4_addr addr = get_ip4(&pkt->addr);
  struct igmp_grp *grp = igmp_grp_find(ifa, &addr);

  if (pkt->type == IGMP_TP_LEAVE)
    return igmp_leave(grp, pkt->resp_time);

  if (!grp)
    grp = igmp_grp_new(ifa, &addr);

  switch (pkt->type) {
    case IGMP_TP_V1_MS_REPORT:
	igmp_membership_report(grp, 1, 10);
	break;

    case IGMP_TP_V2_MS_REPORT:
	igmp_membership_report(grp, 2, pkt->resp_time);
	break;

    default:
	DROP("Unknown type");
	break;
  }

drop:
  return 0;
}

int
igmp_rx_hook(sock *sk, int len)
{
  struct igmp_iface *ifa = sk->data;
  struct igmp_proto *p = ifa->proto;

  struct igmp_pkt *pkt = (struct igmp_pkt *) sk_rx_buffer(sk, &len);

  if (len < sizeof(struct igmp_pkt))
    DROP("Shorter than 8 bytes");

  /* Longer packets are in IGMPv3 */
  if (len != 8)
    DROP("Expected pkt length 8, not %i (probably newer IGMP)", len);

  if (!ipsum_verify(pkt, len, NULL))
    DROP("Invalid checksum");

  return igmp_accept(sk->data, ipa_to_ip4(sk->faddr), pkt);

drop:
  return 0;
}

void
igmp_err_hook(sock *sk, int err)
{
  struct igmp_iface *ifa = sk->data;
  struct igmp_proto *p = ifa->proto;

  TRACE(D_EVENTS, "IGMP err %m", err);
}

int
igmp_tx_query(struct igmp_iface *ifa, ip4_addr addr)
{
  struct igmp_proto *p = ifa->proto;
  struct igmp_pkt *pkt = (struct igmp_pkt *) ifa->sk->tbuf;

  pkt->type = IGMP_TP_MS_QUERY;
  pkt->resp_time = (ifa->cf->query_response_int TO_MS) / 100;
  put_ip4(&pkt->addr, addr);

  pkt->checksum = 0;
  pkt->checksum = ipsum_calculate(pkt, sizeof(struct igmp_pkt), NULL);

  ifa->sk->daddr = ip4_zero(addr) ? IP4_ALL_NODES : ipa_from_ip4(addr);

  if (ip4_zero(addr))
    TRACE(D_PACKETS, "Sending general query on iface %s", ifa->iface->name);
  else
    TRACE(D_PACKETS, "Sending query to grp %I4 on iface %s", addr, ifa->iface->name);

  sk_send(ifa->sk, 8);
  return 0;
}

int
igmp_sk_open(struct igmp_iface *ifa)
{
  sock *sk = sk_new(ifa->proto->p.pool);
  sk->type = SK_IGMP;
  sk->saddr = ifa->iface->addr->ip;
  sk->iface = ifa->iface;

  sk->data = ifa;
  sk->ttl = 1;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->rx_hook = igmp_rx_hook;
  sk->err_hook = igmp_err_hook;

  sk->tbsize = ifa->iface->mtu;

  if (sk_open(sk) < 0)
    goto err;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_join_group(sk, IP4_IGMP_ROUTERS) < 0)
    goto err;

  if (sk_join_group(sk, IP4_ALL_ROUTERS) < 0)
    goto err;

  ifa->sk = sk;
  return 0;

err:
  log(L_ERR "%s: Socket error: %s%#m", ifa->proto->p.name, sk->err);
  rfree(sk);
  return -1;
}

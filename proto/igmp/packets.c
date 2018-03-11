/*
 *	BIRD -- Internet Group Management Protocol (IGMP)
 *
 *	(c) 2016 Ondrej Hlavaty <aearsis@eideo.cz>
 *	(c) 2018 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2018 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "igmp.h"
#include "lib/checksum.h"

#include <linux/mroute.h>


struct igmp_packet
{
  u8 type;
  u8 resp_time;
  u16 checksum;
  u32 addr;
} PACKED;

#define IGMP_MSG_QUERY		0x11
#define IGMP_MSG_V1_REPORT	0x12
#define IGMP_MSG_V2_REPORT	0x16
#define IGMP_MSG_LEAVE		0x17


#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)

#define LOG_PKT(msg, args...) \
  log_rl(&p->log_pkt_tbf, L_REMOTE "%s: " msg, p->p.name, args)

int
igmp_rx_hook(sock *sk, uint len)
{
  struct igmp_iface *ifa = sk->data;
  struct igmp_proto *p = ifa->proto;
  const char *err_dsc = NULL;
  uint err_val = 0;

  struct igmp_packet *pkt = (void *) sk_rx_buffer(sk, &len);

  if (pkt == NULL)
    DROP("bad IP header", len);

  if (len < sizeof(struct igmp_packet))
    DROP("too short", len);

  if (!ipsum_verify(pkt, len, NULL))
    DROP("invalid checksum", pkt->checksum);

  ip4_addr from = ipa_to_ip4(sk->faddr);
  ip4_addr addr = get_ip4(&pkt->addr);

  switch (pkt->type)
  {
  case IGMP_MSG_QUERY:
    TRACE(D_PACKETS, "Query received from %I4 on %s", from, ifa->iface->name);
    /* FIXME: Warning if resp_time == 0 */
    igmp_handle_query(ifa, addr, from, pkt->resp_time * (btime) 100000);
    break;

  case IGMP_MSG_V1_REPORT:
    TRACE(D_PACKETS, "Report (v1) received from %I4 on %s for %I4", from, ifa->iface->name, addr);
    igmp_handle_report(ifa, addr, 1);
    break;

  case IGMP_MSG_V2_REPORT:
    TRACE(D_PACKETS, "Report (v2) received from %I4 on %s for %I4", from, ifa->iface->name, addr);
    igmp_handle_report(ifa, addr, 2);
    break;

  case IGMP_MSG_LEAVE:
    TRACE(D_PACKETS, "Leave received from %I4 on %s for %I4", from, ifa->iface->name, addr);
    igmp_handle_leave(ifa, addr);
    break;

  default:
    TRACE(D_PACKETS, "Unknown IGMP packet (0x%x) from %I4 on %s", pkt->type, from, ifa->iface->name);
    break;
  }
  return 1;

drop:
  LOG_PKT("Bad packet from %I on %s - %s (%u)",
	  sk->faddr, sk->iface->name, err_dsc, err_val);

  return 1;
}

void
igmp_err_hook(sock *sk, int err)
{
  struct igmp_iface *ifa = sk->data;
  struct igmp_proto *p = ifa->proto;

  log(L_ERR "%s: Socket error on %s: %M", p->p.name, ifa->iface->name, err);
}

void
igmp_send_query(struct igmp_iface *ifa, ip4_addr addr, btime resp_time)
{
  struct igmp_proto *p = ifa->proto;
  struct igmp_packet *pkt = (void *) ifa->sk->tbuf;

  pkt->type = IGMP_MSG_QUERY;
  pkt->resp_time = resp_time / 100000;
  put_ip4(&pkt->addr, addr);

  pkt->checksum = 0;
  pkt->checksum = ipsum_calculate(pkt, sizeof(struct igmp_packet), NULL);

  ifa->sk->daddr = ip4_zero(addr) ? IP4_ALL_NODES : ipa_from_ip4(addr);

  if (ip4_zero(addr))
    TRACE(D_PACKETS, "Sending query on %s", ifa->iface->name);
  else
    TRACE(D_PACKETS, "Sending query on %s for %I4", ifa->iface->name, addr);

  sk_send(ifa->sk, sizeof(struct igmp_packet));
}

int
igmp_open_socket(struct igmp_iface *ifa)
{
  struct igmp_proto *p = ifa->proto;

  sock *sk = sk_new(p->p.pool);
  sk->type = SK_IP;
  sk->dport = IGMP_PROTO;
  sk->saddr = ifa->iface->addr4->ip;
  sk->iface = ifa->iface;

  sk->rx_hook = igmp_rx_hook;
  sk->err_hook = igmp_err_hook;
  sk->data = ifa;

  sk->tbsize = ifa->iface->mtu;
  sk->tos = IP_PREC_INTERNET_CONTROL;
  sk->ttl = 1;

  if (sk_open(sk) < 0)
    goto err;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_setup_igmp(sk, p->mif_group, ifa->mif) < 0)
    goto err;

  if (sk_join_group(sk, IP4_IGMP_ROUTERS) < 0)
    goto err;

  if (sk_join_group(sk, IP4_ALL_ROUTERS) < 0)
    goto err;

  ifa->sk = sk;
  return 1;

err:
  log(L_ERR "%s: Socket error: %s%#m", ifa->proto->p.name, sk->err);
  rfree(sk);
  return 0;
}

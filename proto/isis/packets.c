/*
 *	BIRD -- IS-IS Packet Processing
 *
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */


#include <stdlib.h>
#include "isis.h"


/*
 * IS-IS common packet header
 *
 * 1B	Protocol ID,		constant
 * 1B	Fixed header length	depends on packet type
 * 1B	Version 1		fixed 1
 * 1B	System ID length	fixed 0 or 6
 * 1B	Packet type		0xe0 bits reserved
 * 1B	Version 2		fixed 1
 * 1B	Reserved		ignored
 * 1B	Max area addrs		fixed 0 or 3
 *
 *
 * IS-IS Hello header
 *
 * 8B	Common header
 * 1B	Circuit type		levels (1, 2 or 1+2), 0xfc bits reserved
 * 6B	System ID
 * 2B	Hold time
 * 2B	Packet length		hdr + data
 * LAN:
 * 1B	Priority		0x80 bit reserved
 * 7B	LAN ID			for DR selection
 * PTP:
 * 1B	Circuit ID		we could ignore this (?)
 *
 *
 *
 * IS-IS LSP header
 *
 * 8B	Common header
 * 2B	Packet length		hdr + data
 * 2B	LSP lifetime
 * 8B	LSP ID
 * 4B	LSP sequence number
 * 2B	LSP checksum
 * 1B	LSP flags
 *
 *
 * IS-IS CSNP header
 *
 * 8B	Common header
 * 2B	Packet length		hdr + data
 * 7B	System ID
 * 8B	Start LSP ID
 * 8B	End LSP ID
 *
 *
 * IS-IS PSNP header
 *
 * 8B	Common header
 * 2B	Packet length		hdr + data
 * 7B	System ID
 */



#define ISIS_PROTO_ID		0x83

#define ISIS_L1_HELLO		15
#define ISIS_L2_HELLO		16
#define ISIS_PTP_HELLO		17
#define ISIS_L1_LSP		18
#define ISIS_L2_LSP		20
#define ISIS_L1_CSNP		24
#define ISIS_L2_CSNP		25
#define ISIS_L1_PSNP		26
#define ISIS_L2_PSNP		27

#define ISIS_COMMON_HLEN	8
#define ISIS_LHELLO_HLEN	27
#define ISIS_PHELLO_HLEN	20
#define ISIS_LSP_HLEN		27
#define ISIS_CSNP_HLEN		33
#define ISIS_PSNP_HLEN		17

#define ISIS_TYPE_MASK		0x1f


IntradomainRouteingPD

static inline byte * isis_tx_buffer(struct isis_iface *ifa) { return ifa->sk->tbuf; }

static void
isis_fill_hdr(byte *pkt, u8 pdu_type, u8 hdr_len)
{
  pkt[0] = ISIS_PROTO_ID;
  pkt[1] = hdr_len;
  pkt[2] = 1;		// Version 1
  pkt[3] = 6;		// System ID length
  pkt[4] = pdu_type;
  pkt[5] = 1;		// Version 2
  pkt[6] = 0;		// Reserved
  pkt[7] = 3;		// Max area addresses
}

static inline byte *
put_lsp_hdr(byte *buf, struct isis_lsp_hdr *hdr)
{
  put_u16(buf+ 0, hdr->lifetime);
  put_u64(buf+ 2, hdr->id);
  put_u32(buf+10, hdr->seqnum);
  put_u16(buf+14, hdr->checksum);
  return buf+16;
}

static byte *
isis_put_tlv_areas(struct isis_proto *p, byte *buf)
{
  byte *bp = buf + 2;
  int i;

  for (i = 0; i < ISIS_AREAS; i++)
    if (cf->areas[i])
    {
      int alen = 1 + cf->areas[i]->length;
      memcpy(bp, cf->areas[i], alen);
      bp += alen;
    }

  buf[0] = ISIS_TLV_AREAS;
  buf[1] = bp - (buf + 2);

  return bp;
}

static byte *
isis_put_tlv_protocols(struct isis_proto *p, byte *buf)
{
  buf[0] = ISIS_TLV_PROTOCOLS;
  buf[1] = 1;
  buf[2] = ISIS_NLPID_IPv4;

  return buf + 3;
}

static byte *
isis_put_tlv_ip4_iface_addrs(struct isis_iface *ifa, byte *buf)
{
  struct ifa *a;
  byte *bp = buf + 2;
  int i;

  WALK_LIST(a, ifa->iface->addrs)
  {
    bp = ipa_put_addr(bp, a);
  }

  buf[0] = ISIS_TLV_IP4_IFACE_ADDRS;
  buf[1] = bp - (buf + 2);

  return bp;
}


void
isis_send_lan_hello(struct isis_iface *ifa, int level)
{
  struct isis_proto *p = ifa->p;

  byte *pkt = isis_tx_buffer(ifa);
  isis_fill_hdr(pkt, !level ? ISIS_L1_HELLO : ISIS_L2_HELLO, ISIS_LHELLO_HLEN);
  put_u8 (pkt+ 8, ifa->levels);
  put_id6(pkt+ 9, p->system_id);
  put_u16(pkt+15, ifa->hold_int);
  // put_u16(pkt+17, ISIS_ + en->blen);
  put_u8 (pkt+19, ifa->priority);
  put_id7(pkt+20, 0); // xxx DR
}

void
isis_send_ptp_hello(struct isis_iface *ifa)
{
  struct isis_proto *p = ifa->p;

  byte *pkt = isis_tx_buffer(ifa);
  byte *bp = pkt + ISIS_PHELLO_HLEN;
  byte *be = isis_tx_buffer_end(ifa);

  isis_fill_hdr(pkt, ISIS_PTP_HELLO, ISIS_PHELLO_HLEN);
  put_u8 (pkt+ 8, ifa->levels);
  put_id6(pkt+ 9, p->system_id);
  put_u16(pkt+15, ifa->hold_int);
  // put_u16(pkt+17, 0);	/* Length postponed */
  put_u8 (pkt+19, 0);		/* Fake circuit-id */

  bp = isis_put_tlv_areas(p, bp, be);
  bp = isis_put_tlv_protocols(p, bp, be);
  bp = isis_put_tlv_ip4_iface_addrs(ifa, bp, be);
  
  put_u16(pkt+17, bp - pkt);	/* Packet length */
}

void
isis_send_lsp(struct isis_iface *ifa, struct isis_lsp *lsp)
{
  struct isis_proto *p = ifa->p;

  byte *pkt = isis_tx_buffer(ifa);
  isis_fill_hdr(pkt, xxx ? ISIS_L1_LSP : ISIS_L2_LSP, ISIS_LSP_HLEN);
  put_u16(pkt+ 8, ISIS_LSP_HLEN - 1 + lsp->blen);
  put_lsp_hdr(pkt+10, &lsp->hdr);

  if (lsp->body)
    memcpy(pkt+26, lsp->body, lsp->blen);

  ISIS_TRACE(D_PACKETS, "Sending LSP via %s", ifa->iface->name);
  // xxx sk_send_to(ifa->sk, ifa->plen, AllNodes, 0);
}

void
isis_process_lsp(struct isis_iface *ifa, int level, byte *pkt, int len)
{
  struct isis_proto *p = ifa->p;

  if ((pkt[ISIS_HLEN_POS] != ISIS_LSP_HLEN) || (pkt[8] != len))
    XXX;

  put_u16(pkt+ 8, ISIS_LSP_HLEN - 1 + lsp->blen);
  get_lsp_hdr(pkt+10, &hdr);
  isis_lsp_received(db, ifa, &hdr, pkt+26, len-26)

  if (lsp->body)
    memcpy(pkt+26, lsp->body, lsp->blen);

}


static byte *
isis_put_tlv_lsp_entries(struct isis_iface *ifa, byte *buf, byte *be,
			 struct isis_lsdb *db, struct isis_lsp **lspp, int psnp)
{
  struct isis_lsp *lsp = *lspp;
  byte *bp = buf + 2;
  int i = 0;

  be -= 2 + 16;	/* TLV header + sizeof(struct isis_lsp_hdr) */

  while (lsp && bp <= be)
  {
    if (i == 15)
    {
      buf[0] = ISIS_TLV_LSP_ENTRIES;
      buf[1] = i * 16;
      i = 0;
      buf = bp;
      bp += 2;
    }

    bp = put_lsp_hdr(bp, &lsp->hdr);

    if (psnp)
    {
      // XXX check
      isis_lsdb_clear_ssn(db, lsp, ifa);
      lsp = isis_lsdb_next_ssn(db, lsp, ifa);
    }
    else
      lsp = isis_lsdb_next(db, lsp); 

  }
  buf[0] = ISIS_TLV_LSP_ENTRIES;
  buf[1] = i * 16;
  *lspp = lsp;
}

void
isis_send_csnp(struct isis_iface *ifa, int level, struct isis_lsp **lspp, int first)
{
  struct isis_proto *p = ifa->p;

  byte *pkt = isis_tx_buffer(ifa);
  byte *bp = pkt + ISIS_CSNP_HLEN;
  byte *be = isis_tx_buffer_end(ifa);

  /* First put TLVs */
  u64 start_id = first ? ISIS_MIN_LSP_ID : (*lspp)->hdr.id;
  bp = isis_put_tlv_lsp_entries(p, bp, be, p->lsdb[level], lspp, 0);
  u64 end_id = *lspp ? (*lspp)->hdr.id - 1 : ISIS_MAX_LSP_ID;

  /* Then put header */
  isis_fill_hdr(pkt, !level ? ISIS_L1_CSNP : ISIS_L2_CSNP, ISIS_CSNP_HLEN);
  put_u16(pkt+08, bp - pkt);
  put_id7(pkt+10, p->system_id);
  put_u64(pkt+17, start_id);
  put_u64(pkt+25, end_id);

  ISIS_TRACE(D_PACKETS, "Sending CSNP via %s", ifa->iface->name);
  // xxx sk_send_to(ifa->sk, ifa->plen, AllNodes, 0);
}

void
isis_send_psnp(struct isis_iface *ifa, int level, struct isis_lsp **lspp)
{
  struct isis_proto *p = ifa->p;

  byte *pkt = isis_tx_buffer(ifa);
  byte *bp = pkt + ISIS_PSNP_HLEN;
  byte *be = isis_tx_buffer_end(ifa);

  /* First put TLVs */
  bp = isis_put_tlv_lsp_entries(p, bp, be, p->lsdb[level], lspp, 1);

  /* Then put header */
  isis_fill_hdr(pkt, !level ? ISIS_L1_PSNP : ISIS_L2_PSNP, ISIS_PSNP_HLEN);
  put_u16(pkt+08, bp - pkt);
  put_id7(pkt+10, p->system_id);

  ISIS_TRACE(D_PACKETS, "Sending PSNP via %s", ifa->iface->name);
  // xxx sk_send_to(ifa->sk, ifa->plen, AllNodes, 0);
}

static inline void
isis_process_tlv_lsp_entries(struct isis_iface *ifa, byte *tlv, byte *te, struct isis_lsdb *db)
{
  struct isis_proto *p = ifa->p;
  struct isis_lsp_hdr hdr;
  byte *bp = tlv + 2;

  while (bp + 16 <= te)
  {
    bp = get_lsp_hdr(bp, &hdr);
    isis_snp_received(db, ifa, &hdr);
  }

  if (bp < te)
    XXX;
}


static void
isis_process_csnp(struct isis_iface *ifa, int level, byte *pkt, int len)
{
  struct isis_proto *p = ifa->p;

  if ((pkt[ISIS_HLEN_POS] != ISIS_CSNP_HLEN) || (pkt[8] != len))
    XXX;

  u64 start_id = get_u64(pkt+17);
  u64 end_id = get_u64(pkt+25);
  XXX;

  byte *pe = pkt + len;
  byte *tlv = pkt + ISIS_CSNP_HLEN;

  while (tlv < pe)
  {
    byte *te = tlv + 2 + tlv[1];
    if (te > pe)
      XXX;

    if (tlv[0] == ISIS_TLV_LSP_ENTRIES)
      isis_process_tlv_lsp_entries(ifa, tlv, te, p->lsdb[level]);

    tlv = te;
  }

}

static void
isis_process_psnp(struct isis_iface *ifa, int level, byte *pkt, int len)
{
  struct isis_proto *p = ifa->p;

  if ((pkt[ISIS_HLEN_POS] != ISIS_PSNP_HLEN) || (pkt[8] != len))
    XXX;

  byte *pe = pkt + len;
  byte *tlv = pkt + ISIS_PSNP_HLEN;

  while (tlv < pe)
  {
    byte *te = tlv + 2 + tlv[1];
    if (te > pe)
      XXX;

    if (tlv[0] == ISIS_TLV_LSP_ENTRIES)
      isis_process_tlv_lsp_entries(ifa, tlv, te, p->lsdb[level]);

    tlv = te;
  }

}



#define DROP(DSC,VAL) do { err_dsc = DSC; err_val = VAL; goto drop; } while(0)

static int
isis_rx_hook(sock *sk, int len)
{
  struct isis_iface *ifa = sk->data;
  struct isis_proto *p = ifa->p;
  const char *err_dsc = NULL;
  unsigned err_val = 0;

  if (sk->lifindex != sk->iface->index)
    return 1;

  DBG("ISIS: RX hook called (iface %s, src %I, dst %I)\n",
      sk->iface->name, sk->faddr, sk->laddr); // XXX

  // XXX check src addr

  // XXX skip eth header
  byte *pkt = ip_skip_header(sk->rbuf, &len);
  if (pkt == NULL)
    DROP("too short", len);

  if ((len < ISIS_COMMON_HLEN) || (len < pkt[ISIS_HLEN_POS]))
    DROP("too short", len);

  if (len > sk->rbsize)  // XXX
    DROP("too large", len);

  if (pkt[0] != ISIS_PROTO_ID)
    DROP("protocol ID mismatch", pkt[0]);

  if (pkt[2] != 1)
    DROP("version1 mismatch", pkt[2]);

  if (pkt[3] != 0 && pkt[3] != 6)
    DROP("id_length mismatch", pkt[3]);

  if (pkt[5] != 1)
    DROP("version2 mismatch", pkt[5]);

  if (pkt[7] != 0 && pkt[7] != 3)
    DROP("max_area_addrs mismatch", pkt[7]);


  // XXX find neighbor?

  int type = pkt[4] & ISIS_TYPE_MASK;
  int level = ISIS_L1;
  switch (type)
  {
    // XXX ptp
    // case ISIS_PTP_HELLO:

  case ISIS_L2_HELLO:
    level = ISIS_L2;
  case ISIS_L1_HELLO:
    ISIS_TRACE(D_PACKETS, "Received Hello from xxx via %s", ifa->iface->name);
    isis_lan_hello_rx(pkt, ifa, n, level);
    break;

  case ISIS_L2_LSP:
    level = ISIS_L2;
  case ISIS_L1_LSP:
    ISIS_TRACE(D_PACKETS, "Received LSP from xxx via %s", ifa->iface->name);
    isis_lsp_rx(pkt, ifa, n, level);
    break;

  case ISIS_L2_CSNP:
    level = ISIS_L2;
  case ISIS_L1_CSNP:
    ISIS_TRACE(D_PACKETS, "Received CSNP from xxx via %s", ifa->iface->name);
    isis_process_csnp(pkt, ifa, n, level);
    break;

  case ISIS_L2_PSNP:
    level = ISIS_L2;
  case ISIS_L1_PSNP:
    ISIS_TRACE(D_PACKETS, "Received PSNP from xxx via %s", ifa->iface->name);
    isis_psnp_received(pkt, ifa, n, level);
    break;

  default:
    DROP("unknown type", type);
  };
  return 1;

 drop:
  log(L_WARN "%s: Bad packet from %I - %s (%u)", p->p.name, sk->faddr, err_dsc, err_val);
  return 1;
}

static void
isis_tx_hook(sock *sk)
{
  struct isis_iface *ifa = sk->data;
  log(L_WARN "%s: TX hook called", ifa->p->p.name);
}

static void
isis_err_hook(sock *sk, int err)
{
  struct isis_iface *ifa = sk->data;
  log(L_ERR "%s: Socket error: %m", ifa->p->p.name, err);
}

int
isis_sk_open(struct isis_iface *ifa)
{
  sock *sk = sk_new(ifa->pool);
  sk->type = SK_IP;
  sk->dport = ISIS_PROTO;
  sk->saddr = IPA_NONE;

  sk->ttl = 0;
  sk->rx_hook = isis_rx_hook;
  sk->tx_hook = isis_tx_hook;
  sk->err_hook = isis_err_hook;
  sk->iface = ifa->iface;
  sk->rbsize = p->rx_buffer_size + 64; // XXX
  sk->tbsize = p->tx_buffer_size + 64; // XXX
  sk->data = ifa;
  sk->flags = SKF_LADDR_RX;

  if (sk_open(sk) != 0)
    goto err;

  sk->saddr = ifa->addr->ip;

  if (sk_setup_multicast(sk) < 0)
    goto err;

  if (sk_join_group(sk, AllRouters) < 0)
    goto err;

  ifa->sk = sk;
  return 1;

 err:
  rfree(sk);
  return 0;
}


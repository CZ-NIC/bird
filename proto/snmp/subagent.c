/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#include "lib/unaligned.h"
#include "subagent.h"

static int parse_response(struct snmp_proto *p, byte *buf, uint size);
static void header_update_len(byte *buf, u32 len);
static uint oid_size(struct oid* o);

static const char * const snmp_errs[] = {
  #define SNMP_ERR_SHIFT 256
  [AGENTX_RES_OPEN_FAILED - SNMP_ERR_SHIFT] = "Open failed",
  [AGENTX_RES_NOT_OPEN - SNMP_ERR_SHIFT] = "Not open",
  [AGENTX_RES_INDEX_WRONG_TYPE - SNMP_ERR_SHIFT] = "Index wrong type",
  [AGENTX_RES_INDEX_ALREADY_ALLOC - SNMP_ERR_SHIFT] = "Index already allocated",
  [AGENTX_RES_INDEX_NONE_AVAIL - SNMP_ERR_SHIFT] = "Index none availlable",
  [AGENTX_RES_NOT_ALLOCATED - SNMP_ERR_SHIFT] = "Not allocated",
  [AGENTX_RES_UNSUPPORTED_CONTEXT - SNMP_ERR_SHIFT] = "Unsupported contex",
  [AGENTX_RES_DUPLICATE_REGISTR - SNMP_ERR_SHIFT] = "Duplicate registration",
  [AGENTX_RES_UNKNOWN_REGISTR - SNMP_ERR_SHIFT] = "Unknown registration",
  [AGENTX_RES_UNKNOWN_AGENT_CAPS - SNMP_ERR_SHIFT] = "Unknown agent caps",
  [AGENTX_RES_PARSE_ERROR - SNMP_ERR_SHIFT] = "Parse error",
  [AGENTX_RES_REQUEST_DENIED - SNMP_ERR_SHIFT] = "Request denied",
  [AGENTX_RES_PROCESSING_ERR - SNMP_ERR_SHIFT] = "Processing error",
};

static int
put_str(byte *buf, const char *str, uint *size)
{
  uint len = strlen(str);
  uint pkt_len = BIRD_ALIGN(len, 4);

  if (len > MAX_STR)
    return -1;

  put_u32(buf, len);
 
  memcpy(buf + 4, str, len);

  // make the value 32-bit aligned
  for (uint i = 0; i < pkt_len - len; i++)
    buf[len + i] = 0x00;  // PADDING

  *size += (4 + pkt_len);

  return 0;
}

static void
put_blank(byte *buf, uint *size)
{
  buf[0] = buf[1] = buf[2] = buf[3] = 0; 
  *size += 4;
}

static void
put_oid(byte *buf, struct oid *oid, uint *size)
{
  put_u8(buf, oid->n_subid);
  put_u8(buf + 1, oid->prefix);
  put_u8(buf + 2, oid->include);
  put_u8(buf + 3, 0);  // PADDING

  put_u32s(buf + 4, oid->subid.ids, oid->subid.len); 

  *size += (4 + oid->subid.len);
}

/* paste data at first byte in message 
 *   with 3B of padding
 */
static void
paste_fbyte(byte *buf, u8 data, uint *size)
{
  buf[0] = data;
  buf[1] = buf[2] = buf[3] = 0x00; // PADDING  
  *size += 4;
}

static u32
store_in_order(u32 val, int order)
{
  /* AGENTX_BIG_ENDIAN */
  if (order)
  {
  }
  else
  {
  } 
  return 0;
}

static void
open_pdu(struct snmp_proto *p, struct oid *oid)
{
  sock *sk = p->sock;
  byte *buf, *pkt, *end;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;

  // should be configurable
  const char *str = "bird";

  uint pkt_size = 0;
  uint slen = BIRD_ALIGN(strlen(str), 4);

  /* +8 - header of oid (4) and octet string length (4) */
  if (size > AGENTX_HEADER_SIZE + oid->subid.len + slen + 8)
  {
    log(L_INFO "open_pdu() sufficient size nw order: %u",
AGENTX_NETWORK_BYTE_ORDER);
    PASTE_HEADER(pkt, AGENTX_OPEN_PDU, AGENTX_NETWORK_BYTE_ORDER, size);

    // use random num instead
    put_u32(&h->session_id, 1);
    put_u32(&h->transaction_id, 1);
    put_u32(&h->packet_id, 1);

    paste_fbyte(pkt, p->timeout, &pkt_size);
    ADVANCE(pkt, size, 4);
  
    put_oid(pkt, oid, &pkt_size);
    ADVANCE(pkt, size, oid_size(oid)); 

    /* paste description */
    put_str(pkt, str, &pkt_size);
    ADVANCE(pkt, size, slen);

    header_update_len(buf, pkt_size);
   
    log(L_INFO "sk_send()-ing %u", AGENTX_HEADER_SIZE + pkt_size); 
    int ret = sk_send(sk, AGENTX_HEADER_SIZE + pkt_size);
    if (ret == 0)
      log(L_INFO "sleep");
    else if (ret < 0)
      log(L_INFO "err %d", ret);
    else
      log(L_INFO "ok !!! ");
  }

  else
    log(L_INFO "open_pdu() insufficient size, %u <= %u ",
	size, AGENTX_HEADER_SIZE + oid->subid.len + slen + 8);
}

static void
close_pdu(struct snmp_proto *p, u8 reason)
{
  sock *sk = p->sock;
  byte *buf, *pkt;
  buf = pkt = sk->tbuf;
  uint size = sk->tbsize;
  log(L_INFO "close_pdu() size: %u %c %u", size, (size > AGENTX_HEADER_SIZE + 4)
? '>':'<', AGENTX_HEADER_SIZE);

  /* +4B for reason */
  if (size > AGENTX_HEADER_SIZE + 4)
  {
    PASTE_HEADER(buf, AGENTX_CLOSE_PDU, AGENTX_NETWORK_BYTE_ORDER, size);

    log(L_INFO "session_id %u", p->session_id);
    h->session_id = p->session_id;
    p->transaction_id++;
    p->transaction_id = get_u32(&p->transaction_id); 
    put_u32(&h->transaction_id, p->transaction_id);
    put_u32(&h->packet_id, 1);

    ADVANCE(pkt, size, sizeof(struct agentx_header));
    
    paste_fbyte(pkt, reason, &size);
    ADVANCE(pkt, size, 4);

    /* 4 - reason size */
    header_update_len(sk->tbuf, 4);

    int ret = sk_send(sk, sizeof(struct agentx_header) + 4);

    if (ret == 0)
      log(L_INFO "sleep");
    else if (ret < 0)
      log(L_INFO "err");
    else 
      log(L_INFO, "ok !! ");
  }
}

static int
parse_pkt(struct snmp_proto *p, byte *buf, uint size)
{
  if (size < AGENTX_HEADER_SIZE)
    return 0;

  struct agentx_header *h = (void *) buf;
  switch (h->type)
  {
    case AGENTX_RESPONSE_PDU:
      return parse_response(p, buf, size);
      break;

    /* should not happen */
    default:
      die("unknown packet type");
  }
}

static int
parse_response(struct snmp_proto *p, byte *buf, uint size)
{
  if (size < sizeof(struct agentx_response))
    return 0;

  struct agentx_response *r = (void *) buf;
  struct agentx_header *h = &r->h;

  log(L_INFO "endianity: %s, session %u", (h->flags & AGENTX_NETWORK_BYTE_ORDER) ? "big end":
"little end", h->session_id);
  p->session_id = h->session_id;
  p->transaction_id = h->transaction_id;
  p->packet_id = h->packet_id;

  log(L_INFO "size %u", get_u32(&h->payload));
  log(L_INFO "uptime: %u s", get_u32(&r->uptime)); 
  switch (r->err)
  {
    case AGENTX_RES_NO_ERROR:
      break;
    default:
      log(L_INFO "an error occured: '%s'", snmp_errs[get_u16(&r->err) -
SNMP_ERR_SHIFT]);
      break;
  }
  proto_notify_state(&p->p, PS_UP);

  return 1;
}

static void
header_update_len(byte *buf, u32 len)
{
  struct agentx_header *h = (void *) buf;
  put_u32(&h->payload, len);
  log(L_INFO "header_update_len() %d 0x%02X 0x%02X 0x%02X 0x%02X", len, *((unsigned char
*) &h->payload), *(((unsigned char *) &h->payload) + 1), *(((unsigned char *)
&h->payload) + 2), *(((unsigned char *) &h->payload) + 3));

}

void
snmp_start_subagent(struct snmp_proto *p)
{
  log(L_INFO "snmp_start_subagent() starting subagent");

  /* blank oid means unsupported */
  struct oid *o = mb_allocz(p->p.pool, sizeof(struct oid));
  open_pdu(p, o);
  mb_free(o);
}

void
snmp_stop_subagent(struct snmp_proto *p)
{
  sock *sk = p->sock;

  close_pdu(p, AGENTX_CLOSE_SHUTDOWN);

  sk->rx_hook = snmp_stop_ack;
}

static uint
oid_size(struct oid *o)
{
  return 4 + o->subid.len;
}

int
snmp_rx(sock *sk, uint size)
{ 
  log(L_INFO "snmp_rx()");
  struct snmp_proto *p = sk->data;
  byte *pkt = sk->rbuf;
  byte *end = pkt + size;

  parse_pkt(p, pkt, size);
  /* 
  while (end >= ptk + AGENTX_HEADER_SIZE)
  {
    parse_header(p);
    parse_pkt(p, );
  }
  */ 
  return 0;
  // 1 means all done 
}

void 
ping_pdu(struct snmp_proto *p)
{
  /* this does not support non-default context */ 
  sock *sk = p->sock;
  byte *buf = sk->tbuf;
  uint size = sk->tbsize;

  PASTE_HEADER(buf, AGENTX_PING_PDU, AGENTX_NETWORK_BYTE_ORDER, size);

  put_u32(&h->session_id, p->session_id);
  p->transaction_id++;
  put_u32(&h->transaction_id, p->transaction_id);
  put_u32(&h->packet_id, 1);
  put_u32(&h->payload, 0);

  sk_send(sk, AGENTX_HEADER_SIZE);
}

/* 
 * cont is optional context 
 * upp_b is upper_bond
 */
int
snmp_register_oid(sock *sk, struct oid *subtree, u8 range, const char *cont, u32 upp_b)
{
  struct snmp_proto *p = sk->data;
  byte *buf = sk->tbuf;
  uint size = sk->tbsize; 
  log(L_INFO "snmp_register_oid() ");

  u8 flags = AGENTX_NETWORK_BYTE_ORDER | ((cont) ? AGENTX_NON_DEFAULT_CONTEXT :
0);
  PASTE_HEADER(buf, AGENTX_REGISTER_PDU, flags, size);

  if (cont)
    put_str(buf, cont, &size);

  put_u8(buf, p->timeout);
  put_u8(buf + 1, AGENTX_PRIORITY);
  put_u8(buf + 2, range);
  put_u8(buf + 3, 0); // PADDING
  ADVANCE(buf, size, 4);

  put_oid(buf, subtree, &size);
  ADVANCE(buf, size, oid_size(subtree));

  if (upp_b)
  {
    put_u32(buf, upp_b);
    ADVANCE(buf, size, 4);
  }

  header_update_len(sk->tbuf, buf - sk->tbuf + AGENTX_HEADER_SIZE);

  sk_send(sk, buf - sk->tbuf);
}

/*
 * cont is optional context nullable
 * upp_b is upper_bond
 */
int
snmp_unregister_oid(sock *sk, struct oid *subtree, const char *cont, u32 upp_b)
{
  byte *buf = sk->tbuf;
  uint size = sk->tbsize;
  log(L_INFO "snmp_unregister_oid()");

  u8 flags = AGENTX_NETWORK_BYTE_ORDER | ((cont) ? AGENTX_NON_DEFAULT_CONTEXT :
0);
  PASTE_HEADER(buf, AGENTX_UNREGISTER_PDU, flags, size);
  
  if (cont)
  {
    put_str(buf, cont, &size);
    ADVANCE(buf, size, strlen(cont) + 4);
  }

  put_oid(buf, subtree, &size);
  ADVANCE(buf, size, oid_size(subtree));

  if (upp_b)
  {
    put_u32(buf, upp_b);
    ADVANCE(buf, size, 4);
  }

  sk_send(sk, buf - sk->tbuf);  
}

static void
snmp_stop_ack(sock *sk, uint size)
{
  struct snmp_proto *p = sk->data;
  byte *buf = sk->rbuf;
  
  if (size < AGENTX_HEADER_SIZE)
    return 0; 

  if (parse_response(p, buf, size))
  {
    p->p.disabled = 1;
    proto_notify_state(&p->p, PS_DOWN);
  }
}
/*
void
snmp_agent_reconfigure(void)
{

}
*/

#undef SNMP_ERR_SHIFT

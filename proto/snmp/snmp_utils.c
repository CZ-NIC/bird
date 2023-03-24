/*
 *	BIRD -- Simple Network Management Protocol (SNMP) helper functions
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 */

#include "snmp_utils.h"

/**
 * snmp_is_oid_empty - check if oid is null-valued
 * @oid: object identifier to check
 *
 * Test if the oid header is full of zeroes. For @oid NULL returns 0.
 */
int
snmp_is_oid_empty(struct oid *oid)
{
  if (oid != NULL)
    return oid->n_subid == 0 && oid->prefix == 0 && oid->include == 0;
  else
    return 0;
}

/**
 * snmp_pkt_len - returns size of SNMP packet payload (without header)
 * @buf: packet first byte
 * @pkt: first byte past packet end
 */
size_t
snmp_pkt_len(byte *buf, byte *pkt)
{
  return (pkt - buf) - AGENTX_HEADER_SIZE;
}

/**
 * create new null oid (blank)
 * @p: pool hodling snmp_proto structure
 */
struct oid *
snmp_oid_blank(struct snmp_proto *p)
{
  return mb_allocz(p->p.pool, sizeof(struct oid));
}

/**
 * snmp_str_size - return in packet size of supplied string
 * @str: measured string
 *
 * Returned value is string length aligned to 4 byte with 32bit length
 * annotation included.
 */
size_t
snmp_str_size(const char *str)
{
  return 4 + BIRD_ALIGN(strlen(str), 4);
}

/**
 * snmp_oid_size - measure size of oid in bytes
 * @o: object identifier to use
 */
uint
snmp_oid_size(struct oid *o)
{
  return 4 + (o->n_subid * 4);
}

/**
 * snmp_get_size - calculate size for allocation
 * @n_subid: number of ids in oid
 */
inline size_t
snmp_oid_sizeof(uint n_subid)
{
  return sizeof(struct oid) + n_subid * sizeof(u32);
}

/**
 * snmp_vb_size - measure size of varbind in bytes
 * @vb: variable binding to use
 */
uint
snmp_varbind_size(struct agentx_varbind *vb)
{
  return snmp_oid_size(&vb->name) + 4;
}

struct agentx_varbind *
snmp_create_varbind(byte *buf, struct oid *oid)
{
  struct agentx_varbind *vb = (void*) buf;
  memcpy(&vb->name, oid, snmp_oid_size(oid));
  return vb;
}

byte *snmp_fix_varbind(struct agentx_varbind *vb, struct oid *new)
{
  memcpy(&vb->name, new, snmp_oid_size(new));
  return (void *) vb + snmp_varbind_size(vb);
}

/**
 * snmp_oid_ip4_index - check IPv4 address validity in oid
 * @o: object identifier holding ip address
 * @start: index of first address id
 */
int
snmp_valid_ip4_index(struct oid *o, uint start)
{
  if (start + 3 < o->n_subid)
    return snmp_valid_ip4_index_unsafe(o, start);
  else
    return 0; // false
}

/**
 * snmp_valid_ip4_index_unsafe - check validity of IPv4 address in oid
 * @o: object identifier holding ip address
 * @start: index of first address id
 *
 * This function is unsafe - no checks of object identifier ids
 * length sufficiency is done.
 */
int
snmp_valid_ip4_index_unsafe(struct oid *o, uint start)
{
  for (int i = 0; i < 4; i++)
    if (o->ids[start + i] >= 256)
      return 0;	// false

  return 1; // true
}

/**
 * snmp_put_str - put string into SNMP PDU transcieve buffer
 * @buf: pointer to first unoccupied buffer byte
 * @str: string to place
 *
 * Handles all conditions specified by RFC, namely string length annotation
 * and padding 4 byte alignment with zeroes. Return NULL if string is too large
 * for SNMP message.
 */
byte *
snmp_put_str(byte *buf, const char *str)
{
  uint len = strlen(str);
  uint slen = BIRD_ALIGN(len, 4);

  if (len > MAX_STR)
    return NULL;

  STORE_PTR(buf, len);

  memcpy(buf + 4, str, len);

  for (uint i = 0; i < slen - len; i++)
    buf[len + i] = 0x00;  // PADDING

  return buf + snmp_str_size(str);
}

byte *
snmp_put_ip4(byte *buf, ip_addr addr)
{
  /* octet string has size 4 bytes */
  STORE_PTR(buf, 4);

  put_u32(buf+4, ipa_to_u32(addr));

  return buf + 8;
}

byte *
snmp_put_blank(byte *buf)
{
  STORE_PTR(buf, 0);
  return buf + 4;
}

/**
 * snmp_put_oid - put oid into SNMP PDU transcieve buffer
 * @buf: pointer to first free buffer byte
 * @oid: object identifier to use
 */
byte *
snmp_put_oid(byte *buf, struct oid *oid)
{
  put_u8(buf, oid->n_subid);
  put_u8(++buf, oid->prefix);
  put_u8(++buf, oid->include);
  put_u8(++buf, 0);  // PADDING

  /* last increment */
  ++buf;

  /* copy OID data */
#ifdef SNMP_NATIVE
  for (uint i = 0; i < oid->n_subid; i++)
    *(((u32 *) buf) + i) = oid->ids[i];
#else
  put_u32s(buf, oid->ids, oid->n_subid * 4);
#endif

  return buf + oid->n_subid * 4;
}

/**
 * snmp_put_fbyte - put one padded byte to SNMP PDU transcieve buffer
 * @buf: pointer to free buffer byte
 * @data: byte to use
 *
 * Put @data into buffer @buf with 3B zeroed padding.
 */
/* paste data at first byte in message
 *   with 3B of padding
 */
byte *
snmp_put_fbyte(byte *buf, u8 data)
{
  // log(L_INFO "paste_fbyte()");
  put_u8(buf, data);
  put_u24(++buf, 0);  // PADDING
  return buf + 3;
}

void
snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr)
{
  u32 temp = ip4_to_u32(addr);
  STORE(o->ids[start], temp >> 24);
  STORE(o->ids[start + 1], (temp >> 16) & 0xFF);
  STORE(o->ids[start + 2], (temp >>  8) & 0xFF);
  STORE(o->ids[start + 3], temp & 0xFF);
}

void snmp_oid_dump(struct oid *oid)
{
  log(L_WARN "OID DUMP ========");

  if (oid == NULL)
  {
    log(L_WARN "is eqaul to NULL");
    log(L_WARN "OID DUMP END ====");
    log(L_WARN ".");
    return;
  }

  else if (snmp_is_oid_empty(oid))
  {
    log(L_WARN "is empty");
    log(L_WARN "OID DUMP END ====");
    log(L_WARN ".");
    return;
  }

  log(L_WARN "  #ids: %4u  prefix %3u  include: %5s",
    oid->n_subid, oid->prefix, (oid->include)? "true" : "false");
  log(L_WARN "IDS -------------");

  for (int i = 0; i < oid->n_subid; i++)
    log(L_WARN "  %2u:  %11u  ~ 0x%08X", i, oid->ids[i], oid->ids[i]);

  log(L_WARN "OID DUMP END ====");
  log(L_WARN);
}

/** snmp_oid_compare - find the lexicographical order relation between @left and @right
 * both @left and @right has to be non-blank.
 * @left: left object id relation operant
 * @right: right object id relation operant
 *
 * function returns 0 if left == right,
 *   -1 if left < right,
 *   and 1 otherwise
 */
int
snmp_oid_compare(struct oid *left, struct oid *right)
{
  const u32 INTERNET_PREFIX[] = {1, 3, 6, 1};

  /*
  if (snmp_is_oid_empty(left) && snmp_is_oid_empty(right))
    return 0;

  if (snmp_is_oid_empty(right))
    return -1;

  if (snmp_is_oid_empty(left))
    return 1;
  */

  if (left->prefix == 0 && right->prefix == 0)
    goto test_ids;

  if (right->prefix == 0)
    return (-1) * snmp_oid_compare(right, left);

  if (left->prefix == 0)
  {
    for (int i = 0; i < 4; i++)
      if (left->ids[i] < INTERNET_PREFIX[i])
	return -1;
      else if (left->ids[i] > INTERNET_PREFIX[i])
	return 1;

    for (int i = 0; i < MIN(left->n_subid - 4, right->n_subid); i++)
      if (left->ids[i + 4] < right->ids[i])
	return -1;
      else if (left->ids[i + 4] > right->ids[i])
	return 1;

    goto all_same;
  }

  if (left->prefix < right->prefix)
    return -1;
  else if (left->prefix > right->prefix)
    return 1;

test_ids:
  for (int i = 0; i < MIN(left->n_subid, right->n_subid); i++)
    if (left->ids[i] < right->ids[i])
      return -1;
    else if (left->ids[i] > right->ids[i])
      return 1;

all_same:
  /* shorter sequence is before longer in lexicografical order  */
  if (left->n_subid < right->n_subid)
    return -1;
  else if (left->n_subid > right->n_subid)
    return 1;
  else
    return 0;
}

struct snmp_register *
snmp_register_create(struct snmp_proto *p, u8 mib_class)
{
  struct snmp_register *r = mb_alloc(p->p.pool, sizeof(struct snmp_register));

  r->n.prev = r->n.next = NULL;

  r->session_id = p->session_id;
  r->transaction_id = p->transaction_id;
  r->packet_id = p->packet_id;

  r->mib_class = mib_class;

  return r;
}

int
snmp_register_same(struct snmp_register *r, struct agentx_header *h, u8 class)
{
  return
    (r->mib_class == class) &&
    (r->session_id == h->session_id) &&
    (r->transaction_id == h->transaction_id) &&
    (r->packet_id == h->packet_id);
}

void
snmp_register_ack(struct snmp_proto *p, struct agentx_header *h)
{
  snmp_log("snmp_register_ack()");

  struct snmp_register *reg;
  WALK_LIST(reg, p->register_queue)
  {
    // TODO add support for more mib trees (other than BGP)
    if (snmp_register_same(reg, h, SNMP_BGP4_MIB))
    {
      struct snmp_registered_oid *ro = \
	 mb_alloc(p->p.pool, sizeof(struct snmp_registered_oid));

      ro->n.prev = ro->n.next = NULL;

      ro->oid = reg->oid;

      rem_node(&reg->n);
      mb_free(reg);
      p->register_to_ack--;

      add_tail(&p->bgp_registered, &ro->n);

      snmp_log("  register note find %u", list_length(&p->bgp_registered));
      return;
    }
  }

  snmp_log("unknown registration");
}

void
snmp_dump_packet(byte *pkt, uint size)
{
  snmp_log("dump");
  for (uint i = 0; i < size; i += 4)
    snmp_log("pkt [%d]  0x%02x%02x%02x%02x", i, pkt[i],pkt[i+1],pkt[i+2],pkt[i+3]);
  snmp_log("end dump");
}

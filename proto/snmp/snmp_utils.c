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
  //return 4 + o->n_subid * 4;
  return 4 + (o->n_subid << 2);
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
  put_u32s(buf, oid->ids, oid->n_subid << 2);
#endif

  return buf + (oid->n_subid << 2);
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
  log(L_INFO "paste_fbyte()");
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
    log(L_WARN);
    return;
  }

  else if (snmp_is_oid_empty(oid))
  {
    log(L_WARN "is empty");
    log(L_WARN "OID DUMP END ====");
    log(L_WARN);
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

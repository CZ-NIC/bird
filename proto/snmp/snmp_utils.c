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

inline void
snmp_pdu_context(struct snmp_pdu *pdu, sock *sk)
{
  pdu->buffer = sk->tpos;
  pdu->size = sk->tbuf + sk->tbsize - sk->tpos;
  pdu->error = AGENTX_RES_NO_ERROR;
  pdu->index = 0;
}

inline void
snmp_session(const struct snmp_proto *p, struct agentx_header *h)
{
  h->session_id = p->session_id;
  h->transaction_id = p->transaction_id;
  h->packet_id = p->packet_id;
}

inline int
snmp_has_context(const struct agentx_header *h)
{
  return h->flags & AGENTX_NON_DEFAULT_CONTEXT;
}

inline byte *
snmp_add_context(struct snmp_proto *p, struct agentx_header *h, uint contid)
{
  h->flags = h->flags | AGENTX_NON_DEFAULT_CONTEXT;
  // TODO append the context after the header
  (void)p;
  (void)contid;
  return (void *)h + AGENTX_HEADER_SIZE;
}

inline void *
snmp_varbind_data(const struct agentx_varbind *vb)
{
  uint name_size = snmp_oid_size(&vb->name);
  return (void *)&vb->name + name_size;
}

/**
 * snmp_is_oid_empty - check if oid is null-valued
 * @oid: object identifier to check
 *
 * Test if the oid header is full of zeroes. For @oid NULL returns 0.
 */
int
snmp_is_oid_empty(const struct oid *oid)
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
uint
snmp_pkt_len(const byte *start, const byte *end)
{
  return (end - start) - AGENTX_HEADER_SIZE;
}

/**
 *
 * used for copying oid to in buffer oid @dest
 */
void
snmp_oid_copy(struct oid *dest, const struct oid *src)
{
  STORE_U8(dest->n_subid, src->n_subid);
  STORE_U8(dest->prefix,  src->prefix);
  STORE_U8(dest->include, src->include ? 1 : 0);
  STORE_U8(dest->pad,	  0);

  for (int i = 0; i < src->n_subid; i++)
    STORE_U32(dest->ids[i], src->ids[i]);
}

/**
 *
 */
struct oid *
snmp_oid_duplicate(pool *pool, const struct oid *oid)
{
  struct oid *res = mb_alloc(pool, snmp_oid_size(oid));
  memcpy(res, oid, snmp_oid_size(oid));
  return res;
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

size_t
snmp_str_size_from_len(uint len)
{
  return 4 + BIRD_ALIGN(len, 4);
}

/**
 * snmp_str_size - return in packet size of supplied string
 * @str: measured string
 *
 * Returned value is string length aligned to 4 byte with 32bit length
 * annotation included.
 */
inline size_t
snmp_str_size(const char *str)
{
  return snmp_str_size_from_len(strlen(str));
}

/**
 * snmp_oid_size - measure size of oid in bytes
 * @o: object identifier to use
 */
uint
snmp_oid_size(const struct oid *o)
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

uint snmp_varbind_hdr_size_from_oid(struct oid *oid)
{
  return snmp_oid_size(oid) + 4;
}

/**
 * snmp_vb_size - measure size of varbind in bytes
 * @vb: variable binding to use
 */
uint
snmp_varbind_header_size(struct agentx_varbind *vb)
{
  return snmp_varbind_hdr_size_from_oid(&vb->name);
}

uint
snmp_varbind_size(struct agentx_varbind *vb)
{
  uint hdr_size = snmp_varbind_header_size(vb);
  int s = agentx_type_size(vb->type);

  if (s >= 0)
    return hdr_size + (uint) s;

  void *data = snmp_varbind_data(vb);

  if (vb->type == AGENTX_OBJECT_ID)
    return hdr_size + snmp_oid_size((struct oid *) data);

  /*
   * Load length of octet string
   * (AGENTX_OCTET_STRING, AGENTX_IP_ADDRESS, AGENTX_OPAQUE)
   */
  return hdr_size + snmp_str_size_from_len(LOAD_PTR(data));
}

/* test if the varbind has valid type */
int
snmp_test_varbind(const struct agentx_varbind *vb)
{
  if (vb->type == AGENTX_INTEGER  ||
      vb->type == AGENTX_OCTET_STRING  ||
      vb->type == AGENTX_NULL  ||
      vb->type == AGENTX_OBJECT_ID  ||
      vb->type == AGENTX_IP_ADDRESS  ||
      vb->type == AGENTX_COUNTER_32  ||
      vb->type == AGENTX_GAUGE_32  ||
      vb->type == AGENTX_TIME_TICKS  ||
      vb->type == AGENTX_OPAQUE  ||
      vb->type == AGENTX_COUNTER_64  ||
      vb->type == AGENTX_NO_SUCH_OBJECT  ||
      vb->type == AGENTX_NO_SUCH_INSTANCE  ||
      vb->type == AGENTX_END_OF_MIB_VIEW)
    return 1;
  else
    return 0;
}

struct agentx_varbind *
snmp_create_varbind(byte *buf, struct oid *oid)
{
  struct agentx_varbind *vb = (void*) buf;
  vb->pad = 0;
  snmp_oid_copy(&vb->name, oid);
  return vb;
}

byte *
snmp_fix_varbind(struct agentx_varbind *vb, struct oid *new)
{
  memcpy(&vb->name, new, snmp_oid_size(new));
  return (void *) vb + snmp_varbind_header_size(vb);
}

/**
 * snmp_oid_ip4_index - check IPv4 address validity in oid
 * @o: object identifier holding ip address
 * @start: index of first address id
 */
int
snmp_valid_ip4_index(const struct oid *o, uint start)
{
  if (start + 3 < o->n_subid)
    return snmp_valid_ip4_index_unsafe(o, start);
  else
    return 0;
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
snmp_valid_ip4_index_unsafe(const struct oid *o, uint start)
{
  for (int i = 0; i < 4; i++)
    if (o->ids[start + i] >= 256)
      return 0;

  return 1;
}

byte *
snmp_put_nstr(byte *buf, const char *str, uint len)
{
  uint alen = BIRD_ALIGN(len, 4);

  STORE_PTR(buf, len);
  buf += 4;
  memcpy(buf, str, len);

  /* Insert zero padding in the gap at the end */
  for (uint i = 0; i < alen - len; i++)
    buf[len + i] = '\0';

  return buf + alen;
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
  return snmp_put_nstr(buf, str, len);
}

byte *
snmp_put_ip4(byte *buf, ip4_addr addr)
{
  /* octet string has size 4 bytes */
  STORE_PTR(buf, 4);

  put_u32(buf+4, ip4_to_u32(addr));

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
  struct oid *oid_buf = (void *) buf;
  snmp_oid_copy(oid_buf, oid);
  return buf + snmp_oid_size(oid);
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
  //log(L_INFO "paste_fbyte()");
  put_u8(buf, data);
  put_u24(++buf, 0);  // PADDING
  return buf + 3;
}

void
snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr)
{
  u32 temp = ip4_to_u32(addr);
  STORE_U32(o->ids[start], temp >> 24);
  STORE_U32(o->ids[start + 1], (temp >> 16) & 0xFF);
  STORE_U32(o->ids[start + 2], (temp >>  8) & 0xFF);
  STORE_U32(o->ids[start + 3], temp & 0xFF);
}

void UNUSED
snmp_oid_dump(const struct oid *oid)
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
snmp_oid_compare(const struct oid *left, const struct oid *right)
{
  const u32 INTERNET_PREFIX[] = {1, 3, 6, 1};


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
  /* will be incremented by snmp_session() macro during packet assembly */
  r->transaction_id = p->transaction_id;
  r->packet_id = p->packet_id + 1;

  r->mib_class = mib_class;

  add_tail(&p->register_queue, &r->n);

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


void UNUSED
snmp_dump_packet(byte UNUSED *pkt, uint size)
{
  snmp_log("dump");
  for (uint i = 0; i < size; i += 4)
    snmp_log("pkt [%d]  0x%02x%02x%02x%02x", i, pkt[i],pkt[i+1],pkt[i+2],pkt[i+3]);
  snmp_log("end dump");
}

/*
 * Returns length of agentx_type @type in bytes.
 * Variable length types result in -1.
 */
int
agentx_type_size(enum agentx_type type)
{
  /*
   * AGENTX_NULL, AGENTX_NO_SUCH_OBJECT, AGENTX_NO_SUCH_INSTANCE,
   * AGENTX_END_OF_MIB_VIEW
   */
  if (type >= AGENTX_NO_SUCH_OBJECT || type == AGENTX_NULL)
    return 0;

  /* AGENTX_INTEGER, AGENTX_COUNTER_32, AGENTX_GAUGE_32, AGENTX_TIME_TICKS */
  if (type >= AGENTX_COUNTER_32 && type <= AGENTX_TIME_TICKS ||
      type == AGENTX_INTEGER)
    return 4;

  /* AGENTX_COUNTER_64 */
  if (type == AGENTX_COUNTER_64)
    return 8;

  /* AGENTX_OBJECT_ID, AGENTX_OCTET_STRING, AGENTX_IP_ADDRESS, AGENTX_OPAQUE */
  else
    return -1;
}

static inline byte *
snmp_varbind_type32(struct agentx_varbind *vb, uint size, enum agentx_type type, u32 val)
{
  ASSUME(agentx_type_size(type) == 4); /* type has 4B representation */

  if (size < (uint) agentx_type_size(type))
    return NULL;

  vb->type = type;
  u32 *data = snmp_varbind_data(vb);
  *data = val;
  return (byte *)(data + 1);
}

inline byte *
snmp_varbind_int(struct agentx_varbind *vb, uint size, u32 val)
{
  return snmp_varbind_type32(vb, size, AGENTX_INTEGER, val);
}


inline byte *
snmp_varbind_counter32(struct agentx_varbind *vb, uint size, u32 val)
{
  return snmp_varbind_type32(vb, size, AGENTX_COUNTER_32, val);
}

inline byte *
snmp_varbind_ticks(struct agentx_varbind *vb, uint size, u32 val)
{
  return snmp_varbind_type32(vb, size, AGENTX_TIME_TICKS, val);
}

inline byte *
snmp_varbind_gauge32(struct agentx_varbind *vb, uint size, s64 val)
{
  return snmp_varbind_type32(vb, size, AGENTX_GAUGE_32,
			     MAX(0, MIN(val, UINT32_MAX)));
}

inline byte *
snmp_varbind_ip4(struct agentx_varbind *vb, uint size, ip4_addr addr)
{
  if (size < snmp_str_size_from_len(4))
    return NULL;

  vb->type = AGENTX_IP_ADDRESS;
  return snmp_put_ip4(snmp_varbind_data(vb), addr);
}

inline byte *
snmp_varbind_nstr(struct agentx_varbind *vb, uint size, const char *str, uint len)
{
  if (size < snmp_str_size_from_len(len))
    return NULL;

  vb->type = AGENTX_OCTET_STRING;
  return snmp_put_nstr(snmp_varbind_data(vb), str, len);
}

inline enum agentx_type
snmp_search_res_to_type(enum snmp_search_res r)
{
  ASSUME(r != SNMP_SEARCH_OK);
  static enum agentx_type type_arr[] = {
    [SNMP_SEARCH_NO_OBJECT]   = AGENTX_NO_SUCH_OBJECT,
    [SNMP_SEARCH_NO_INSTANCE] = AGENTX_NO_SUCH_INSTANCE,
    [SNMP_SEARCH_END_OF_VIEW] = AGENTX_END_OF_MIB_VIEW,
  };

  return type_arr[r];
}


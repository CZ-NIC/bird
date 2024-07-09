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
#include <stdio.h>

inline void
snmp_pdu_context(struct snmp_pdu *pdu, sock *sk)
{
  pdu->error = AGENTX_RES_NO_ERROR;
  pdu->buffer = sk->tpos;
  pdu->size = sk->tbuf + sk->tbsize - sk->tpos;
  pdu->index = 0;
  pdu->sr_vb_start = NULL;
  pdu->sr_o_end = NULL;
}

/**
 * snmp_session - store packet ids from protocol to header
 * @p: source SNMP protocol instance
 * @h: dest PDU header
 */
inline void
snmp_session(const struct snmp_proto *p, struct agentx_header *h)
{
  STORE_U32(h->session_id, p->session_id);
  STORE_U32(h->transaction_id, p->transaction_id);
  STORE_U32(h->packet_id, p->packet_id);
}

inline int
snmp_has_context(const struct agentx_header *h)
{
  return h->flags & AGENTX_NON_DEFAULT_CONTEXT;
}

inline void *
snmp_varbind_data(const struct agentx_varbind *vb)
{
  uint name_size = snmp_oid_size(&vb->name);
  return (void *)&vb->name + name_size;
}

struct oid *
snmp_varbind_set_name_len(struct snmp_proto *p, struct agentx_varbind **vb, u8 len, struct snmp_pdu *c)
{
  struct oid *oid = &(*vb)->name;

  if (LOAD_U8(oid->n_subid) >= len)
  {
    c->size += (LOAD_U8(oid->n_subid) - len) * sizeof(u32);
    STORE_U8(oid->n_subid, len);
    return oid;
  }

  /* We need more space */
  ASSUME(len >= LOAD_U8(oid->n_subid));
  uint diff_size = (len - LOAD_U8(oid->n_subid)) * sizeof(u32);
  if (c->size < diff_size)
  {
    snmp_log("varbind_set_name_len small buffer");
    snmp_manage_tbuf(p, c);
    oid = &(*vb)->name;
  }

  ASSERT(c->size >= diff_size);
  c->size -= diff_size;
  STORE_U8(oid->n_subid, len);
  return &(*vb)->name;
}

void
snmp_varbind_duplicate_hdr(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c)
{
  ASSUME(vb != NULL && *vb != NULL);
  uint hdr_size = snmp_varbind_header_size(*vb);
  if (c->size < hdr_size)
  {
    snmp_log("varbind_duplicate small buffer");
    snmp_manage_tbuf(p, c);
  }

  ASSERT(c->size >= hdr_size);
  byte *buffer = c->buffer;
  ADVANCE(c->buffer, c->size, hdr_size);
  memcpy(buffer, *vb, hdr_size);
  *vb = (struct agentx_varbind *) buffer;
}

/**
 * snmp_is_oid_empty - check if oid is null-valued
 * @oid: object identifier to check
 *
 * Test if the oid header is full of zeroes. For NULL-pointer @oid returns 0.
 * We ignore include field to prevent weird behaviour.
 */
inline int
snmp_is_oid_empty(const struct oid *oid)
{
  /* We intentionaly ignore padding that should be zeroed */
  if (oid != NULL)
    return LOAD_U8(oid->n_subid) == 0 && LOAD_U8(oid->prefix) == 0;
  else
    return 0;
}

/*
 * snmp_oid_is_prefixable - check for prefixed form conversion possibility
 * @oid: object identfier to check
 *
 * Check if it is possible to convert @oid to prefixed form. The condition of
 * that is standart .1.3.6.1 internet prefix and 5-th id that fits in one byte.
 */
inline int
snmp_oid_is_prefixable(const struct oid *oid)
{
  if (oid->n_subid < 5)
    return 0;

  for (int i = 0; i < 4; i++)
    if (LOAD_U32(oid->ids[i]) != snmp_internet[i])
      return 0;

  if (LOAD_U32(oid->ids[4]) >= 256)
    return 0;

  return 1;
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

/*
 * snmp_oid_copy - copy OID from one place to another
 * @dest: destination to use
 * @src: OID to be copied from
 */
void
snmp_oid_copy(struct oid *dest, const struct oid *src)
{
  STORE_U8(dest->n_subid, src->n_subid);
  STORE_U8(dest->prefix, src->prefix);
  STORE_U8(dest->include, src->include ? 1 : 0);
  STORE_U8(dest->reserved, 0);

  for (int i = 0; i < LOAD_U8(src->n_subid); i++)
    STORE_U32(dest->ids[i], src->ids[i]);
}

/* this function assumes enougth space inside dest is allocated */
void
snmp_oid_copy2(struct oid *dest, const struct oid *src)
{
  /* The STORE_U8() and LOAD_U8() cancel out */
  dest->n_subid = src->n_subid;
  dest->prefix = src->prefix;
  dest->include = src->include ? 1 : 0;
  dest->reserved = 0;

  /* The STORE_U32() and LOAD_U32 cancel out */
  memcpy(dest->ids, src->ids, LOAD_U8(src->n_subid) * sizeof(u32));
}

/*
 * snmp_oid_duplicate - duplicate an OID from memory pool
 * @pool: pool to use
 * @oid: OID to be duplicated
 */
struct oid *
snmp_oid_duplicate(pool *pool, const struct oid *oid)
{
  struct oid *res = mb_alloc(pool, snmp_oid_size(oid));
  memcpy(res, oid, snmp_oid_size(oid));
  return res;
}

/**
 * snmp_oid_blank - create new null oid (blank)
 * @p: pool hodling snmp_proto structure
 */
struct oid *
snmp_oid_blank(struct snmp_proto *p)
{
  return mb_allocz(p->p.pool, sizeof(struct oid));
}

/**
 * snmp_str_size_from_len - return in-buffer octet string size
 * @len: length of C-string, returned from strlen()
 */
inline size_t
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
  return 4 + (LOAD_U8(o->n_subid) * 4);
}

/**
 * snmp_get_size - calculate size for allocation
 * @n_subid: number of ids in oid
 */
inline size_t
snmp_oid_size_from_len(uint n_subid)
{
  return sizeof(struct oid) + n_subid * sizeof(u32);
}

/*
 * snmp_varbind_hdr_size_from_oid - return in-buffer size of VarBind
 * @oid: OID used as VarBind's name
 *
 * This function assume @oid to be not NULL.
 */
uint
snmp_varbind_hdr_size_from_oid(const struct oid *oid)
{
  ASSUME(oid);
  return snmp_oid_size(oid) + OFFSETOF(struct agentx_varbind, name);
}

/*
 * snmp_set_varbind_type - set VarBind's type field
 * @vb: Varbind inside TX-buffer
 * @t: a valid type to be set
 *
 * This function assumes valid @t.
 */
inline enum snmp_search_res
snmp_set_varbind_type(struct agentx_varbind *vb, enum agentx_type t)
{
  ASSUME(t != AGENTX_INVALID);
  STORE_U16(vb->type, t);
  STORE_U16(vb->reserved, 0);

  switch (t)
  {
    case AGENTX_END_OF_MIB_VIEW:
      return SNMP_SEARCH_END_OF_VIEW;
    case AGENTX_NO_SUCH_OBJECT:
      return SNMP_SEARCH_NO_OBJECT;
    case AGENTX_NO_SUCH_INSTANCE:
      return SNMP_SEARCH_NO_INSTANCE;

    /* valid varbind types */
    case AGENTX_INTEGER:
    case AGENTX_OCTET_STRING:
    case AGENTX_NULL:
    case AGENTX_OBJECT_ID:
    case AGENTX_IP_ADDRESS:
    case AGENTX_COUNTER_32:
    case AGENTX_GAUGE_32:
    case AGENTX_TIME_TICKS:
    case AGENTX_OPAQUE:
    case AGENTX_COUNTER_64:
      return SNMP_SEARCH_OK;

    default:
      die("invalid varbind type %d", (int) t);
  }
}

/* Internal wrapper */
static inline u16
snmp_load_varbind_type(const struct agentx_varbind *vb)
{
  return LOAD_U16(vb->type);
}

/*
 * snmp_get_varbind_type - loads a VarBind type
 * @vb: VarBind pointer to TX-buffer
 *
 * This function assumes VarBind with valid type, always call snmp_test_varbind
 * for in TX-buffer VarBinds!
 */
inline enum agentx_type
snmp_get_varbind_type(const struct agentx_varbind *vb)
{
  ASSUME(snmp_test_varbind(vb));
  return (enum agentx_type) snmp_load_varbind_type(vb);
}

static inline uint
snmp_get_octet_size(const struct agentx_octet_str *str)
{
  return LOAD_U32(str->length);
}

/**
 * snmp_varbind_header_size - measure size of VarBind without data in bytes
 * @vb: VarBind to use
 *
 * Return size including whole OID as well as the VarBind header.
 */
uint
snmp_varbind_header_size(const struct agentx_varbind *vb)
{
  return snmp_varbind_hdr_size_from_oid(&vb->name);
}

uint
snmp_varbind_size_unsafe(const struct agentx_varbind *vb)
{
  ASSUME(snmp_test_varbind(vb));

  enum agentx_type type = snmp_get_varbind_type(vb);
  int value_size = agentx_type_size(type);

  uint vb_header = snmp_varbind_header_size(vb);

  if (value_size == 0)
    return vb_header;

  if (value_size > 0)
    return vb_header + value_size;

  switch (type)
  {
    case AGENTX_OBJECT_ID:;
      struct oid *oid = snmp_varbind_data(vb);
      return vb_header + snmp_oid_size(oid);

    case AGENTX_OCTET_STRING:
    case AGENTX_IP_ADDRESS:
    case AGENTX_OPAQUE:;
      struct agentx_octet_str *string = snmp_varbind_data(vb);
      return vb_header + snmp_get_octet_size(string);

    default:
      /* Shouldn't happen */
      return 0;
  }
}

/**
 * snmp_varbind_size - get size of in-buffer VarBind
 * @vb: VarBind to measure
 * @limit: upper limit of bytes that can be used
 *
 * This functions assumes valid VarBind type.
 * Return 0 for Varbinds longer than limit, Varbind's size otherwise.
 */
uint
snmp_varbind_size(const struct agentx_varbind *vb, uint limit)
{
  ASSUME(snmp_test_varbind(vb));

  if (limit < sizeof(struct agentx_varbind))
    return 0;

  enum agentx_type type = agentx_type_size(snmp_get_varbind_type(vb));
  int s = agentx_type_size(type);
  uint vb_header = snmp_varbind_header_size(vb);

  if (limit < vb_header)
    return 0;

  if (s == 0)
    return vb_header;

  if (s > 0 && vb_header + s <= limit)
    return vb_header + s;
  else if (s > 0)
    return 0;

  switch (type)
  {
    case AGENTX_OBJECT_ID:;
      struct oid *oid = snmp_varbind_data(vb);
      return vb_header + snmp_oid_size(oid);

    case AGENTX_OCTET_STRING:
    case AGENTX_IP_ADDRESS:
    case AGENTX_OPAQUE:;
      struct agentx_octet_str *os = snmp_varbind_data(vb);
      return vb_header + snmp_get_octet_size(os);

    default:
      /* This should not happen */
      return 0;
  }
}

/**
 * snmp_varbind_size_from_len - get size in-buffer VarBind for known OID and data
 * @n_subid: number of subidentifiers of the VarBind's OID name
 * @type: type of VarBind
 * @len: length of variably long data
 *
 * For types with fixed size the @len is not used. For types such as Octet
 * String, or OID the @len is used directly.
 *
 * Return number of bytes used by VarBind in specified form.
 */
inline size_t
snmp_varbind_size_from_len(uint n_subid, enum agentx_type type, uint len)
{
  size_t sz = snmp_oid_size_from_len(n_subid)
    + sizeof(struct agentx_varbind) - sizeof(struct oid);

  int data_sz = agentx_type_size(type);
  if (data_sz < 0)
    sz += len;
  else
    sz += data_sz;

  return sz;
}

/*
 * snmp_test_varbind - test validity of VarBind's type
 * @vb: VarBind to test
 */
int
snmp_test_varbind(const struct agentx_varbind *vb)
{
  ASSUME(vb);

  u16 type = snmp_load_varbind_type(vb);
  if (type == AGENTX_INTEGER  ||
      type == AGENTX_OCTET_STRING  ||
      type == AGENTX_NULL  ||
      type == AGENTX_OBJECT_ID  ||
      type == AGENTX_IP_ADDRESS  ||
      type == AGENTX_COUNTER_32  ||
      type == AGENTX_GAUGE_32  ||
      type == AGENTX_TIME_TICKS  ||
      type == AGENTX_OPAQUE  ||
      type == AGENTX_COUNTER_64  ||
      type == AGENTX_NO_SUCH_OBJECT  ||
      type == AGENTX_NO_SUCH_INSTANCE  ||
      type == AGENTX_END_OF_MIB_VIEW)
    return 1;
  else
    return 0;
}

/*
 * snmp_create_varbind - create a null-typed VarBind in buffer
 * @buf: buffer to use
 */
struct agentx_varbind *
snmp_create_varbind_null(byte *buf)
{
  struct oid o = { 0 };
  struct agentx_varbind *vb = snmp_create_varbind(buf, &o);
  snmp_set_varbind_type(vb, AGENTX_NULL);
  return vb;
}

/*
 * snmp_create_varbind - initialize in-buffer non-typed VarBind
 * @buf: pointer to first unused buffer byte
 * @oid: OID to use as VarBind name
 */
struct agentx_varbind *
snmp_create_varbind(byte *buf, struct oid *oid)
{
  struct agentx_varbind *vb = (void *) buf;
  STORE_U16(vb->reserved, 0);
  snmp_oid_copy(&vb->name, oid);
  return vb;
}

/**
 * snmp_oid_ip4_index - check IPv4 address validity in oid
 * @o: object identifier holding ip address
 * @start: index of first address id
 */
int
snmp_valid_ip4_index(const struct oid *o, uint start)
{
  if (start + 3 < LOAD_U8(o->n_subid))
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
    if (LOAD_U32(o->ids[start + i]) >= 256)
      return 0;

  return 1;
}

/*
 * snmp_put_nstr - copy c-string into buffer with limit
 * @buf: destination buffer
 * @str: string to use
 * @len: number of characters to use from string
 */
byte *
snmp_put_nstr(byte *buf, const char *str, uint len)
{
  uint alen = BIRD_ALIGN(len, 4);

  struct agentx_octet_str *octet = (void *) buf;
  STORE_U32(octet->length, len);
  memcpy(&octet->data, str, len);
  buf += len + sizeof(octet->length);

  /* Insert zero padding in the gap at the end */
  for (uint i = 0; i < alen - len; i++)
    STORE_U8(buf[i], '\0');

  return buf + (alen - len);
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
  STATIC_ASSERT(sizeof(ip4_addr) == sizeof(u32));
  STORE_PTR(buf, sizeof(ip4_addr));

  /* Always use Network byte order */
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
byte *
snmp_put_fbyte(byte *buf, u8 data)
{
  STORE_U8(*buf++, data);
  memset(buf, 0, 3); /* we fill the 24bit padding with zeros */
  return buf + 3;
}

/*
 * snmp_oid_ip4_index - OID append IPv4 index
 * @o: OID to use
 * @start: index of IP addr's MSB
 * @addr: IPv4 address to use
 *
 * The indices from start to (inclusive) start+3 are overwritten by @addr bytes.
 */
void
snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr)
{
  u32 temp = ip4_to_u32(addr);
  STORE_U32(o->ids[start], temp >> 24);
  STORE_U32(o->ids[start + 1], (temp >> 16) & 0xFF);
  STORE_U32(o->ids[start + 2], (temp >>  8) & 0xFF);
  STORE_U32(o->ids[start + 3], temp & 0xFF);
}


/**
 * snmp_oid_compare - find the lexicographical order relation between @left and @right
 * @left: left object id relation operant
 * @right: right object id relation operant
 *
 * both @left and @right has to be non-blank.
 * function returns 0 if left == right,
 *   -1 if left < right,
 *   and 1 otherwise
 */
int
snmp_oid_compare(const struct oid *left, const struct oid *right)
{
  const u8 left_subids = LOAD_U8(left->n_subid);
  u8 right_subids = LOAD_U8(right->n_subid); /* see hack for more info */

  const u8 left_prefix = LOAD_U8(left->prefix);
  const u8 right_prefix = LOAD_U8(right->prefix);

  if (left_prefix == 0 && right_prefix == 0)
    goto test_ids;

  if (right_prefix == 0)
    return (-1) * snmp_oid_compare(right, left);

  if (left_prefix == 0)
  {
    uint bound = MIN((uint) left_subids, (uint) ARRAY_SIZE(snmp_internet));
    for (uint idx = 0; idx < bound; idx++)
    {
      u32 id = LOAD_U32(left->ids[idx]);
      if (id < snmp_internet[idx])
	return -1;
      else if (id > snmp_internet[idx])
	return 1;
    }

    if (left_subids <= ARRAY_SIZE(snmp_internet))
      return -1;

    /* check prefix */
    if (LOAD_U32(left->ids[4]) < (u32) right_prefix)
      return -1;
    else if (LOAD_U32(left->ids[4]) > (u32) right_prefix)
      return 1;

    /* the right prefix is already checked (+1) */
    int limit = MIN(left_subids - (int) (ARRAY_SIZE(snmp_internet) + 1),
      (int) right_subids);
    for (int i = 0; i < limit; i++)
    {
      u32 left_id = LOAD_U32(left->ids[i + ARRAY_SIZE(snmp_internet) + 1]);
      u32 right_id = LOAD_U32(right->ids[i]);
      if (left_id < right_id)
	return -1;
      else if (left_id > right_id)
	return 1;
    }

    /* hack: we known at this point that right has >= 5 subids
     *   (implicit in snmp_internet and oid->prefix), so
     *   we simplify to common case by altering left_subids */
    right_subids += 5;
    goto all_same;
  }

  if (left_prefix < right_prefix)
    return -1;
  else if (left_prefix > right_prefix)
    return 1;

test_ids:
  for (int i = 0; i < MIN(left->n_subid, right->n_subid); i++)
  {
    u32 left_id = LOAD_U32(left->ids[i]);
    u32 right_id = LOAD_U32(right->ids[i]);
    if (left_id < right_id)
      return -1;
    else if (left_id > right_id)
      return 1;
  }

all_same:
  /* shorter sequence is before longer in lexicografical order  */
  if (left_subids < right_subids)
    return -1;
  else if (left_subids > right_subids)
    return 1;
  else
    return 0;
}

struct snmp_registration *
snmp_registration_create(struct snmp_proto *p, u8 mib_class)
{
  struct snmp_registration *r;
  r = mb_alloc(p->p.pool, sizeof(struct snmp_registration));

  r->n.prev = r->n.next = NULL;

  r->session_id = p->session_id;
  /* will be incremented by snmp_session() macro during packet assembly */
  r->transaction_id = p->transaction_id;
  r->packet_id = p->packet_id + 1;
  snmp_log("using registration packet_id %u", r->packet_id);

  r->mib_class = mib_class;

  add_tail(&p->registration_queue, &r->n);

  return r;
}

int
snmp_registration_match(struct snmp_registration *r, struct agentx_header *h, u8 class)
{
  snmp_log("snmp_reg_same() r->packet_id %u p->packet_id %u", r->packet_id, h->packet_id);
  return
    (r->mib_class == class) &&
    (r->session_id == h->session_id) &&
    (r->transaction_id == h->transaction_id) &&
    (r->packet_id == h->packet_id);
}


void UNUSED
snmp_dump_packet(byte UNUSED *pkt, uint size)
{
  DBG("dump");
  for (uint i = 0; i < size; i += 4)
    DBG("pkt [%d]  0x%02x%02x%02x%02x", i, pkt[i],pkt[i+1],pkt[i+2],pkt[i+3]);
  DBG("end dump");
}

/*
 * agentx_type_size - get in packet VarBind type size
 * @type: VarBind type
 *
 * Returns length of agentx_type @type in bytes, Variable length types result in
 * -1.
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

  if (type == AGENTX_COUNTER_64)
    return 8;

  if (AGENTX_IP_ADDRESS)
    return snmp_str_size_from_len(4);

  /* AGENTX_OBJECT_ID, AGENTX_OCTET_STRING, AGENTX_OPAQUE */
  else
    return -1;
}

static inline void
snmp_varbind_type32(struct agentx_varbind *vb, struct snmp_pdu *c, enum agentx_type type, u32 val)
{
  ASSUME(agentx_type_size(type) == 4); /* type as 4B representation */

  snmp_set_varbind_type(vb, type);
  u32 *data = snmp_varbind_data(vb);
  STORE_PTR(data, val);
  data++;
  c->buffer = (byte *) data;
}

inline void
snmp_varbind_int(struct snmp_pdu *c, u32 val)
{
  snmp_varbind_type32(c->sr_vb_start, c, AGENTX_INTEGER, val);
}

inline void
snmp_varbind_counter32(struct snmp_pdu *c, u32 val)
{
  snmp_varbind_type32(c->sr_vb_start, c, AGENTX_COUNTER_32, val);
}

inline void
snmp_varbind_ticks(struct snmp_pdu *c, u32 val)
{
  snmp_varbind_type32(c->sr_vb_start, c, AGENTX_TIME_TICKS, val);
}

inline void
snmp_varbind_gauge32(struct snmp_pdu *c, s64 time)
{
  snmp_varbind_type32(c->sr_vb_start, c,
    AGENTX_GAUGE_32, MAX(0, MIN(time, UINT32_MAX)));
}

inline void
snmp_varbind_ip4(struct snmp_pdu *c, ip4_addr addr)
{
  snmp_set_varbind_type(c->sr_vb_start, AGENTX_IP_ADDRESS);
  c->buffer = snmp_put_ip4(snmp_varbind_data(c->sr_vb_start), addr);
}

inline byte *
snmp_varbind_nstr2(struct snmp_pdu *c, uint size, const char *str, uint len)
{
  if (size < snmp_str_size_from_len(len))
    return NULL;

  snmp_set_varbind_type(c->sr_vb_start, AGENTX_OCTET_STRING);
  return snmp_put_nstr(snmp_varbind_data(c->sr_vb_start), str, len);
}

/*
 * snmp_varbind_nstr - fill varbind context with octet string
 * @vb: VarBind to use
 * @c: PDU information
 * @str: C-string to put as the VarBind data
 * @len: length of the string @str
 *
 * Beware: this function assumes there is enough space in the underlaying
 * TX-buffer. The caller has to provide that, see snmp_str_size_from_len() for
 * more info.
 */
void
snmp_varbind_nstr(struct snmp_pdu *c, const char *str, uint len)
{
  snmp_set_varbind_type(c->sr_vb_start, AGENTX_OCTET_STRING);
  c->buffer = snmp_put_nstr(snmp_varbind_data(c->sr_vb_start), str, len);
}

inline enum agentx_type
snmp_search_res_to_type(enum snmp_search_res r)
{
  ASSUME(r != SNMP_SEARCH_OK);
  enum agentx_type type_arr[] = {
    [SNMP_SEARCH_NO_OBJECT]   = AGENTX_NO_SUCH_OBJECT,
    [SNMP_SEARCH_NO_INSTANCE] = AGENTX_NO_SUCH_INSTANCE,
    [SNMP_SEARCH_END_OF_VIEW] = AGENTX_END_OF_MIB_VIEW,
  };

  return type_arr[r];
}

inline int
snmp_test_close_reason(byte value)
{
  if (value >= (byte) AGENTX_CLOSE_OTHER &&
      value <= (byte) AGENTX_CLOSE_BY_MANAGER)
    return 1;
  else
    return 0;
}


/*
 *  Debugging
 */

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

void UNUSED
snmp_oid_log(const struct oid *oid)
{
  char buf[1024] = { };
  char *pos = buf;

  if (snmp_oid_is_prefixed(oid))
  {
    for (uint i = 0; i < ARRAY_SIZE(snmp_internet); i++)
      pos += snprintf(pos, buf + 1024 - pos, ".%u", snmp_internet[i]);

    pos += snprintf(pos, buf + 1024 - pos, ".%u", oid->prefix);
  }

  for (int id = 0; id < oid->n_subid; id++)
    pos += snprintf(pos, buf + 1024 - pos, ".%u", oid->ids[id]);

  snmp_log("%s", buf);
}


/*
 * snmp_oid_common_ancestor - find a common ancestor
 * @left: first OID
 * @right: second OID
 * @out: buffer for result
 *
 * The @out must be large enough to always fit the resulting OID, a safe value
 * is minimum between number of left subids and right subids. The result might
 * be NULL OID in cases where there is no common subid. The result could be also
 * viewed as longest common prefix. Note that if both @left and @right are
 * prefixable but not prefixed the result in @out will also not be prefixed.
 */
void
snmp_oid_common_ancestor(const struct oid *left, const struct oid *right, struct oid *out)
{
  ASSERT(left && right && out);

  STORE_U8(out->include, 0);
  STORE_U8(out->reserved, 0);
  STORE_U8(out->prefix, 0);

  u32 offset = 0;
  u8 left_ids = LOAD_U8(left->n_subid), right_ids = LOAD_U8(right->n_subid);

  int l = snmp_oid_is_prefixed(left), r = snmp_oid_is_prefixed(right);
  if (l && r)
  {
    if (LOAD_U8(left->prefix) != LOAD_U8(right->prefix))
    {
      STORE_U8(out->n_subid, 4);

      for (uint id = 0; id < ARRAY_SIZE(snmp_internet); id++)
	STORE_U32(out->ids[id], snmp_internet[id]);

      return;
    }

    STORE_U8(out->prefix, LOAD_U8(left->prefix));
  }
  else if (!l && r)
  {
    if (left_ids == 0)
    {
      /* finish creating NULL OID */
      STORE_U8(out->n_subid, 0);
      return;
    }

    for (uint id = 0; id < MIN(ARRAY_SIZE(snmp_internet), left_ids); id++)
    {
      if (LOAD_U32(left->ids[id]) != snmp_internet[id])
      {
	STORE_U8(out->n_subid, id);
	return;
      }

      STORE_U32(out->ids[id], snmp_internet[id]);
    }

    if (left_ids <= ARRAY_SIZE(snmp_internet))
    {
      STORE_U8(out->n_subid, left_ids);
      return;
    }

    /* index 4 is conresponding to the prefix in prefixed OID */
    if (LOAD_U32(left->ids[4]) != (u32) LOAD_U8(right->prefix))
    {
      STORE_U8(out->n_subid, ARRAY_SIZE(snmp_internet));
      return;
    }

    /* delete snmp_internet from out->ids and store OID prefix */
    offset = ARRAY_SIZE(snmp_internet) + 1;
    STORE_U8(out->n_subid, LOAD_U8(out->n_subid) - ARRAY_SIZE(snmp_internet));
    STORE_U8(out->prefix, LOAD_U8(right->prefix));
  }
  else if (l && !r)
  {
    snmp_oid_common_ancestor(right, left, out);
    return;
  }

  ASSERT(offset <= left_ids);

  u8 subids = 0;
  for (u32 id = 0; id < MIN(left_ids - offset, right_ids); id++)
  {
    if (left->ids[offset + id] == right->ids[id])
    {
      subids++;
      STORE_U32(out->ids[id], LOAD_U32(right->ids[id]));
    }
    else
      break;
  }
  STORE_U8(out->n_subid, subids);
}

/*
 * SNMP MIB tree walking
 */
struct mib_leaf *
snmp_walk_init(struct mib_tree *tree, struct mib_walk_state *walk, const struct oid *oid, struct snmp_data *data)
{
  mib_tree_walk_init(walk, tree);

  snmp_vb_to_tx(data->p, oid, data->c);

  mib_node_u *node = mib_tree_find(tree, walk, &data->c->sr_vb_start->name);

  // TODO hide me in mib_tree code
  /* mib_tree_find() returns NULL if the oid is longer than existing any path */
  if (node == NULL && walk->stack_pos > 0)
    node = walk->stack[walk->stack_pos - 1];

  return (!node || !mib_node_is_leaf(node)) ? NULL : &node->leaf;
}

// TODO alter the varbind
struct mib_leaf *
snmp_walk_next(struct mib_tree *tree, struct mib_walk_state *walk, struct snmp_data *data)
{
  ASSUME(tree && walk);

  if (!walk->stack_pos)
    return NULL;

  mib_node_u *node = walk->stack[walk->stack_pos - 1];

  int found = 0;
  struct mib_leaf *leaf = &node->leaf;

  if (mib_node_is_leaf(node) && leaf->call_next)
  {
    const struct oid *oid = &data->c->sr_vb_start->name;
    if (mib_tree_walk_oid_compare(walk, oid) > 0)
    {
      int old = snmp_oid_size(&data->c->sr_vb_start->name);
      if (mib_tree_walk_to_oid(walk,
	  &data->c->sr_vb_start->name, 20 * sizeof(u32)))
      {
	snmp_log("walk_next copy failed");
	return NULL;
      }

      int new = snmp_oid_size(&data->c->sr_vb_start->name);
      data->c->buffer += (new - old);
    }

    found = !leaf->call_next(walk, data);
  }
  else if (mib_node_is_leaf(node) && LOAD_U8(data->c->sr_vb_start->name.include))
  {
    found = 1;
    STORE_U8(data->c->sr_vb_start->name.include, 0);
  }

  const struct oid *oid = &data->c->sr_vb_start->name;
  u32 skip = (walk->id_pos < LOAD_U8(oid->n_subid)) ?
    LOAD_U32(oid->ids[walk->id_pos]) : 0;
  while (!found && (leaf = mib_tree_walk_next_leaf(tree, walk, skip)) != NULL)
  {
    /* mib_tree_walk_next() forces VarBind's name OID overwriting */
    int old = snmp_oid_size(&data->c->sr_vb_start->name);
    // TODO autogrow
    if (mib_tree_walk_to_oid(walk, &data->c->sr_vb_start->name, 20 * sizeof(u32)))
    {
      snmp_log("walk_next copy failed");
      return NULL;
    }

    int new = snmp_oid_size(&data->c->sr_vb_start->name);
    data->c->buffer += (new - old);

    if (leaf->call_next && !leaf->call_next(walk, data))
      found = 1;
    else if (!leaf->call_next)
      found = 1;

    oid = &data->c->sr_vb_start->name;
    skip = (walk->id_pos < LOAD_U8(oid->n_subid)) ?
      LOAD_U32(oid->ids[walk->id_pos]) : 0;
  }

  if (!found)
    return NULL;

  return leaf;
}

enum snmp_search_res
snmp_walk_fill(struct mib_leaf *leaf, struct mib_walk_state *walk, struct snmp_data *data)
{
  struct agentx_varbind *vb = data->c->sr_vb_start;

  if (!leaf)
    return SNMP_SEARCH_NO_OBJECT;

  uint size = 0;
  if (leaf->size >= 0)
  {
    if (leaf->type == AGENTX_OCTET_STRING || leaf->type == AGENTX_OPAQUE ||
	  leaf->type == AGENTX_OBJECT_ID)
    {
      snmp_set_varbind_type(vb, leaf->type);
      size = leaf->size;
    }
    else if (leaf->type != AGENTX_INVALID)
    {
      snmp_set_varbind_type(vb, leaf->type);
      size = agentx_type_size(leaf->type);
    }
    else
      size = leaf->size;
  }

  snmp_log("walk_fill got size %u based on lt %u ls %u, calling filler()", size, leaf->type, leaf->size);

  if (size >= data->c->size)
  {
    snmp_log("walk_fill small buffer size %d to %d", size, data->c->size);
    snmp_manage_tbuf(data->p, data->c);
  }

  enum snmp_search_res res = leaf->filler(walk, data);

  vb = data->c->sr_vb_start;

  if (res != SNMP_SEARCH_OK)
    snmp_set_varbind_type(vb, snmp_search_res_to_type(res));

  u16 type = snmp_load_varbind_type(vb);
  ASSUME(type == leaf->type || type == AGENTX_END_OF_MIB_VIEW || type == AGENTX_NO_SUCH_OBJECT ||
    type == AGENTX_NO_SUCH_INSTANCE);

  return res;
}


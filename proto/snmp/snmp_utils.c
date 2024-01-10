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
snmp_pdu_context(const struct snmp_proto *p, struct snmp_pdu *pdu, sock *sk)
{
  pdu->error = AGENTX_RES_NO_ERROR;
  if (!snmp_is_partial(p))
  {
    pdu->buffer = sk->tpos;
    pdu->size = sk->tbuf + sk->tbsize - sk->tpos;
    pdu->index = 0;
    return;
  }

  pdu->buffer = sk->tbuf + p->header_offset + p->last_size;
  pdu->size = sk->tbuf + sk->tbsize - pdu->buffer;
  pdu->index = p->last_index;
}

inline void
snmp_session(const struct snmp_proto *p, struct agentx_header *h)
{
  STORE_U32(h->session_id, p->session_id);
  STORE_U32(h->transaction_id, p->transaction_id);
  STORE_U32(h->packet_id, p->packet_id);
  //log(L_INFO "storing packet id %u into the header %p", p->packet_id, h);
}

inline int
snmp_has_context(const struct agentx_header *h)
{
  return h->flags & AGENTX_NON_DEFAULT_CONTEXT;
}

inline byte *
snmp_add_context(struct snmp_proto *p, struct agentx_header *h, uint contid)
{
  u8 flags = LOAD_U8(h->flags);
  STORE_U8(h->flags, flags | AGENTX_NON_DEFAULT_CONTEXT);
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
    return LOAD_U8(oid->n_subid) == 0 && LOAD_U8(oid->prefix) == 0 &&
	LOAD_U8(oid->include) == 0;
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

/*
 * snmp_oid_copy - copy OID from one place to another
 * @dest: destination to use
 * @src: OID to be copied from
 */
void
snmp_oid_copy(struct oid *dest, const struct oid *src)
{
  STORE_U8(dest->n_subid, src->n_subid);
  STORE_U8(dest->prefix,  src->prefix);
  STORE_U8(dest->include, src->include ? 1 : 0);
  STORE_U8(dest->pad,	  0);

  for (int i = 0; i < LOAD_U8(src->n_subid); i++)
    STORE_U32(dest->ids[i], src->ids[i]);
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
 * create new null oid (blank)
 * @p: pool hodling snmp_proto structure
 */
struct oid *
snmp_oid_blank(struct snmp_proto *p)
{
  return mb_allocz(p->p.pool, sizeof(struct oid));
}

/**
 * snmp_str_size_from_len - return in-buffer octet-string size
 * @len: length of C-string, returned from strlen()
 */
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
inline void
snmp_set_varbind_type(struct agentx_varbind *vb, enum agentx_type t)
{
  ASSUME(t != AGENTX_INVALID);
  STORE_U16(vb->type, t);
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
  STORE_U16(vb->pad, 0);
  snmp_oid_copy(&vb->name, oid);
  return vb;
}

#if 0
byte *
snmp_fix_varbind(struct agentx_varbind *vb, struct oid *new)
{
  memcpy(&vb->name, new, snmp_oid_size(new));
  return (void *) vb + snmp_varbind_header_size(vb);
}
#endif

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
  STORE_PTR(buf, 4);

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
  if (left->prefix == 0 && right->prefix == 0)
    goto test_ids;

  if (right->prefix == 0)
    return (-1) * snmp_oid_compare(right, left);

  if (left->prefix == 0)
  {
    for (int i = 0; i < 4; i++)
      if (left->ids[i] < snmp_internet[i])
	return -1;
      else if (left->ids[i] > snmp_internet[i])
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

struct snmp_registration *
snmp_registration_create(struct snmp_proto *p, u8 mib_class)
{
  struct snmp_registration *r;
  r = mb_alloc(p->p.pool, sizeof(struct snmp_registration));

  r->n.prev = r->n.next = NULL;

  r->session_id = p->session_id;
  /* will be incremented by snmp_session() macro during packet assembly */
  r->transaction_id = p->transaction_id;
  // TODO where is incremented? is this valid?
  r->packet_id = p->packet_id + 1;
  log(L_INFO "using registration packet_id %u", r->packet_id);

  r->mib_class = mib_class;

  add_tail(&p->registration_queue, &r->n);

  return r;
}

int
snmp_registration_match(struct snmp_registration *r, struct agentx_header *h, u8 class)
{
  log(L_INFO "snmp_reg_same() r->packet_id %u p->packet_id %u", r->packet_id, h->packet_id);
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

  snmp_set_varbind_type(vb, type);
  u32 *data = snmp_varbind_data(vb);
  STORE_PTR(data, val); /* note that the data has u32 type */
  data++;
  return (byte *) data;
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

  snmp_set_varbind_type(vb, AGENTX_IP_ADDRESS);
  return snmp_put_ip4(snmp_varbind_data(vb), addr);
}

// TODO doc string, we have already the varbind prepared
inline byte *
snmp_varbind_nstr(struct agentx_varbind *vb, uint size, const char *str, uint len)
{
  if (size < snmp_str_size_from_len(len))
    return NULL;

  snmp_set_varbind_type(vb, AGENTX_OCTET_STRING);
  return snmp_put_nstr(snmp_varbind_data(vb), str, len);
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

inline struct agentx_header *
snmp_create_tx_header(struct snmp_proto *p, byte *tbuf)
{
  /* the response is created always in TX-buffer */
  p->header_offset = tbuf - p->sock->tbuf;
  ASSERT(p->header_offset < p->sock->tbsize);
  return (struct agentx_header *) tbuf;
}

/*
 * Partial header manipulation functions
 */

/*
 * snmp_is_partial - check if we have a partially parted packet in TX-buffer
 * @p: SNMP protocol instance
 */
inline int
snmp_is_partial(const struct snmp_proto *p)
{
  return p->last_size > 0;
}

/*
 * snmp_get_header - restore partial packet's header from TX-buffer
 * @p: SNMP protocol instance
 */
inline struct agentx_header *
snmp_get_header(const struct snmp_proto *p)
{
  /* Nonzero last size indicates existence of partial packet */
  ASSERT(p->last_size && p->header_offset < p->sock->tbsize);
  return (struct agentx_header *) (p->sock->tbuf + p->header_offset);
}

/*
 * snmp_set_header - store partial packet's header into protocol
 * @p: SNMP protocol instance
 * @h: header of the currently parsed PDU
 * @c: SNMP PDU context
 *
 * Store the needed values regarding later partial PDU processing.
 */
inline void
snmp_set_header(struct snmp_proto *p, struct agentx_header *h, struct snmp_pdu *c)
{
  sock *sk = p->sock;
  // TODO agentx_headier in last_size or not?
  ASSERT(c->buffer - sk->tpos >= AGENTX_HEADER_SIZE);
  p->last_size = c->buffer - sk->tpos + p->last_size;
  p->header_offset = (((byte *) h) - sk->tbuf);
  p->last_index = c->index;
  log(L_INFO "using p->packet_id %u as a p->last_pkt_id %u", p->packet_id, p->last_pkt_id);
  p->last_pkt_id = p->packet_id;
  log(L_INFO "snmp_set_header() tbuf %p tpos %p buffer %p header %p header2 %p offset %u last_size %u last_index %u last_pkt_id %u",
      sk->tbuf, sk->tpos, c->buffer,h,(byte*)h, p->header_offset, p->last_size,
      p->last_index, p->last_pkt_id);
}

/*
 * snmp_unset_header - clean partial packet's header
 * @p: SNMP protocol instance
 *
 * Clean the partial packet processing fields of protocol when the packet is
 * fully processed.
 */
inline void
snmp_unset_header(struct snmp_proto *p)
{
  p->last_size = 0;
  p->header_offset = 0;
  p->last_index = 0;
  p->last_pkt_id = 0;
}


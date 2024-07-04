#ifndef _BIRD_SNMP_UTILS_H_
#define _BIRD_SNMP_UTILS_H_

#include "subagent.h"
#include "mib_tree.h"

uint snmp_pkt_len(const byte *start, const byte *end);

/*
 *
 *    AgentX Variable Biding (VarBind) utils
 *
 */

/*
 *  AgentX - Variable Binding (VarBind) type utils
 */
enum snmp_search_res snmp_set_varbind_type(struct agentx_varbind *vb, enum agentx_type t);
enum agentx_type snmp_get_varbind_type(const struct agentx_varbind *vb);
int agentx_type_size(enum agentx_type t);

/* type Octet String */
size_t snmp_str_size_from_len(uint len);
size_t snmp_str_size(const char *str);

/* type OID - Object Identifier */
int snmp_is_oid_empty(const struct oid *oid);
int snmp_oid_is_prefixable(const struct oid *oid);
uint snmp_oid_size(const struct oid *o);
size_t snmp_oid_size_from_len(uint n_subid);
void snmp_oid_copy(struct oid *dest, const struct oid *src);
void snmp_oid_copy2(struct oid *dest, const struct oid *src);
int snmp_oid_compare(const struct oid *first, const struct oid *second);
void snmp_oid_common_ancestor(const struct oid *left, const struct oid *right, struct oid *result);

static inline int
snmp_oid_is_prefixed(const struct oid *oid)
{
  return LOAD_U8(oid->prefix) != 0;
}

/* type IPv4 */
int snmp_valid_ip4_index(const struct oid *o, uint start);
int snmp_valid_ip4_index_unsafe(const struct oid *o, uint start);
void snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr);

/*
 *  AgentX - Variable Binding (VarBind) manupulation
 */
uint snmp_varbind_hdr_size_from_oid(const struct oid *oid);
uint snmp_varbind_header_size(const struct agentx_varbind *vb);
uint snmp_varbind_size(const struct agentx_varbind *vb, uint limit);
uint snmp_varbind_size_unsafe(const struct agentx_varbind *vb);
size_t snmp_varbind_size_from_len(uint n_subid, enum agentx_type t, uint len);
int snmp_test_varbind(const struct agentx_varbind *vb);
void *snmp_varbind_data(const struct agentx_varbind *vb);
struct oid *snmp_varbind_set_name_len(struct snmp_proto *p, struct agentx_varbind **vb, u8 len, struct snmp_pdu *c);
void snmp_varbind_duplicate_hdr(struct snmp_proto *p, struct agentx_varbind **vb, struct snmp_pdu *c);

/*
 *  AgentX - PDU headers, types, contexts
 */
void snmp_session(const struct snmp_proto *p, struct agentx_header *h);
int snmp_has_context(const struct agentx_header *h);
void snmp_pdu_context(struct snmp_pdu *pdu, sock *sk);
struct oid *snmp_oid_duplicate(pool *pool, const struct oid *oid);
struct oid *snmp_oid_blank(struct snmp_proto *p);

int snmp_test_close_reason(byte value);

/*
 *  AgentX - TX buffer manipulation
 */

/* Functions filling buffer a typed value */
struct agentx_varbind *snmp_create_varbind(byte *buf, struct oid *oid);
struct agentx_varbind *snmp_create_varbind_null(byte *buf);
void snmp_varbind_int(struct snmp_pdu *c, u32 val);
void snmp_varbind_counter32(struct snmp_pdu *c, u32 val);
void snmp_varbind_gauge32(struct snmp_pdu *c, s64 time);
void snmp_varbind_ticks(struct snmp_pdu *c, u32 val);
void snmp_varbind_ip4(struct snmp_pdu *c, ip4_addr addr);
void snmp_varbind_nstr(struct snmp_pdu *c, const char *str, uint len);

/* Raw */
byte *snmp_no_such_object(byte *buf, struct agentx_varbind *vb, struct oid *oid);
byte *snmp_no_such_instance(byte *buf, struct agentx_varbind *vb, struct oid *oid);
byte *snmp_put_str(byte *buf, const char *str);
byte *snmp_put_nstr(byte *buf, const char *str, uint len);
byte *snmp_put_blank(byte *buf);
byte *snmp_put_oid(byte *buf, struct oid *oid);
byte *snmp_put_ip4(byte *buf, ip4_addr ip4);
byte *snmp_put_fbyte(byte *buf, u8 data);


/*
 *
 *    Helpers, Misc, Debugging
 *
 */
struct snmp_registration *snmp_registration_create(struct snmp_proto *p, u8 mib_class);
int snmp_registration_match(struct snmp_registration *r, struct agentx_header *h, u8 class);

void snmp_dump_packet(byte *pkt, uint size);
void snmp_oid_dump(const struct oid *oid);
void snmp_oid_log(const struct oid *oid);

enum agentx_type snmp_search_res_to_type(enum snmp_search_res res);

#define AGENTX_TYPE_INT_SIZE ((uint) agentx_type_size(AGENTX_INTEGER))
#define AGENTX_TYPE_IP4_SIZE ((uint) agentx_type_size(AGENTX_IP_ADDRESS))
#define AGENTX_TYPE_COUNTER32_SIZE ((uint) agentx_type_size(AGENTX_COUNTER_32))

/*
 * SNMP MIB tree walking
 */
struct mib_leaf *snmp_walk_init(struct mib_tree *tree, struct mib_walk_state *state, const struct oid *start_rx, struct snmp_data *data);
struct mib_leaf *snmp_walk_next(struct mib_tree *tree, struct mib_walk_state *state, struct snmp_data *data);
enum snmp_search_res snmp_walk_fill(struct mib_leaf *leaf, struct mib_walk_state *state, struct snmp_data *data);

#endif

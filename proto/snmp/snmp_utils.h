#ifndef _BIRD_SNMP_UTILS_H_
#define _BIRD_SNMP_UTILS_H_

#include "subagent.h"

uint snmp_pkt_len(const byte *start, const byte *end);
size_t snmp_str_size_from_len(uint len);
size_t snmp_str_size(const char *str);
int snmp_is_oid_empty(const struct oid *oid);
int snmp_valid_ip4_index(const struct oid *o, uint start);
int snmp_valid_ip4_index_unsafe(const struct oid *o, uint start);
uint snmp_oid_size(const struct oid *o);
size_t snmp_oid_sizeof(uint n_subid);
uint snmp_varbind_hdr_size_from_oid(const struct oid *oid);
uint snmp_varbind_header_size(const struct agentx_varbind *vb);
uint snmp_varbind_size(const struct agentx_varbind *vb, uint limit);
uint snmp_varbind_size_unsafe(const struct agentx_varbind *vb);
int snmp_test_varbind(const struct agentx_varbind *vb);
void snmp_session(const struct snmp_proto *p, struct agentx_header *h);
int snmp_has_context(const struct agentx_header *h);
void snmp_pdu_context(const struct snmp_proto *p, struct snmp_pdu *pdu, sock *sk);

void snmp_oid_copy(struct oid *dest, const struct oid *src);

struct oid *snmp_oid_duplicate(pool *pool, const struct oid *oid);
struct oid *snmp_oid_blank(struct snmp_proto *p);

void *snmp_varbind_data(const struct agentx_varbind *vb);
struct agentx_varbind *snmp_create_varbind(byte *buf, struct oid *oid);
struct agentx_varbind *snmp_create_varbind_null(byte *buf);
byte *snmp_fix_varbind(struct agentx_varbind *vb, struct oid *new);

int snmp_oid_compare(const struct oid *first, const struct oid *second);

byte *snmp_no_such_object(byte *buf, struct agentx_varbind *vb, struct oid *oid);
byte *snmp_no_such_instance(byte *buf, struct agentx_varbind *vb, struct oid *oid);

byte *snmp_put_str(byte *buf, const char *str);
byte *snmp_put_nstr(byte *buf, const char *str, uint len);
byte *snmp_put_blank(byte *buf);
byte *snmp_put_oid(byte *buf, struct oid *oid);

byte *snmp_put_ip4(byte *buf, ip4_addr ip4);

byte *snmp_put_fbyte(byte *buf, u8 data);

void snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr);

void snmp_oid_dump(const struct oid *oid);

void snmp_set_varbind_type(struct agentx_varbind *vb, enum agentx_type t);
enum agentx_type snmp_get_varbind_type(const struct agentx_varbind *vb);

//struct oid *snmp_prefixize(struct snmp_proto *p, struct oid *o);

struct snmp_registration *snmp_registration_create(struct snmp_proto *p, u8 mib_class);
int snmp_registration_match(struct snmp_registration *r, struct agentx_header *h, u8 class);

/* Functions filling buffer a typed value */
byte *snmp_varbind_int(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_counter32(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_gauge32(struct agentx_varbind *vb, uint size, s64 val);
byte *snmp_varbind_ticks(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_ip4(struct agentx_varbind *vb, uint size, ip4_addr addr);
byte *snmp_varbind_nstr(struct agentx_varbind *vb, uint size, const char *str, uint len);

void snmp_dump_packet(byte *pkt, uint size);

enum agentx_type snmp_search_res_to_type(enum snmp_search_res res);

int agentx_type_size(enum agentx_type t);

int snmp_test_close_reason(byte value);

struct agentx_header *snmp_create_tx_header(struct snmp_proto *p, byte *rbuf);
int snmp_is_partial(const struct snmp_proto *p);
struct agentx_header *snmp_get_header(const struct snmp_proto *p);
void snmp_set_header(struct snmp_proto *p, struct agentx_header *h, struct snmp_pdu *c);
void snmp_unset_header(struct snmp_proto *p);

#endif

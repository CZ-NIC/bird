#ifndef _BIRD_SNMP_UTILS_H_
#define _BIRD_SNMP_UTILS_H_

#include "subagent.h"

uint snmp_pkt_len(byte *start, byte *end);
size_t snmp_str_size_from_len(uint len);
size_t snmp_str_size(const char *str);
int snmp_is_oid_empty(const struct oid *oid);
int snmp_valid_ip4_index(const struct oid *o, uint start);
int snmp_valid_ip4_index_unsafe(const struct oid *o, uint start);
uint snmp_oid_size(const struct oid *o);
size_t snmp_oid_sizeof(uint n_subid);
uint snmp_varbind_hdr_size_from_oid(struct oid *oid);
uint snmp_varbind_header_size(struct agentx_varbind *vb);
uint snmp_varbind_size(struct agentx_varbind *vb, int byte_ord);
//uint snmp_context_size(struct agentx_context *c);

void snmp_oid_copy(struct oid *dest, const struct oid *src);

struct oid *snmp_oid_duplicate(pool *pool, const struct oid *oid);
struct oid *snmp_oid_blank(struct snmp_proto *p);

struct agentx_varbind *snmp_create_varbind(byte* buf, struct oid *oid);
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

void snmp_oid_dump(struct oid *oid);

//struct oid *snmp_prefixize(struct snmp_proto *p, struct oid *o, int byte_ord);

struct snmp_register *snmp_register_create(struct snmp_proto *p, u8 mib_class);

void snmp_register_ack(struct snmp_proto *p, struct agentx_header *h, u8 class);

byte *snmp_varbind_int(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_counter32(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_gauge32(struct agentx_varbind *vb, uint size, s64 val);
byte *snmp_varbind_ticks(struct agentx_varbind *vb, uint size, u32 val);
byte *snmp_varbind_ip4(struct agentx_varbind *vb, uint size, ip4_addr addr);
byte *snmp_varbind_nstr(struct agentx_varbind *vb, uint size, const char *str, uint len);

void snmp_dump_packet(byte *pkt, uint size);

const struct snmp_context *snmp_cont_find(struct snmp_proto *p, const char *name);
const struct snmp_context *snmp_cont_get(struct snmp_proto *p, uint context_id);
const struct snmp_context *snmp_cont_create(struct snmp_proto *p, const char *name);

enum agentx_type snmp_search_res_to_type(enum snmp_search_res res);

int agentx_type_size(enum agentx_type t);


#endif

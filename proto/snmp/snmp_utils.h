#ifndef _BIRD_SNMP_UTILS_H_
#define _BIRD_SNMP_UTILS_H_

#include "subagent.h"

size_t snmp_pkt_len(byte *buf, byte *pkt);
size_t snmp_str_size(const char *str);
int snmp_is_oid_empty(struct oid *oid);
int snmp_valid_ip4_index(struct oid *o, uint start);
int snmp_valid_ip4_index_unsafe(struct oid *o, uint start);
uint snmp_oid_size(struct oid *o);
size_t snmp_oid_sizeof(uint n_subid);
uint snmp_varbind_size(struct agentx_varbind *vb);

struct oid *snmp_oid_blank(struct snmp_proto *p);

struct agentx_varbind *snmp_create_varbind(byte* buf, struct oid *oid);
byte *snmp_fix_varbind(struct agentx_varbind *vb, struct oid *new);

int snmp_oid_compare(struct oid *first, struct oid *second);

byte *snmp_no_such_object(byte *buf, struct agentx_varbind *vb, struct oid *oid);
byte *snmp_no_such_instance(byte *buf, struct agentx_varbind *vb, struct oid *oid);

byte *snmp_put_str(byte *buf, const char *str);
byte *snmp_put_blank(byte *buf);
byte *snmp_put_oid(byte *buf, struct oid *oid);

byte *snmp_put_fbyte(byte *buf, u8 data);

void snmp_oid_ip4_index(struct oid *o, uint start, ip4_addr addr);

void snmp_oid_dump(struct oid *oid);

int snmp_oid_compare(struct oid *left, struct oid *right);

struct oid *snmp_prefixize(struct snmp_proto *p, struct oid *o, int byte_ord);

struct snmp_register *snmp_register_create(struct snmp_proto *p, u8 mib_class);

void snmp_register_ack(struct snmp_proto *p, struct agentx_header *h);
#endif

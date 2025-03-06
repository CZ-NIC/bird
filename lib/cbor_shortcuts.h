#ifndef CBOR_SHORTCUTS_H
#define CBOR_SHORTCUTS_H

#include "lib/cbor.h"
#include "sysdep/config.h"
#include "lib/birdlib.h"
#include "nest/protocol.h"
#include "lib/ip.h"


void cbor_string_string(struct cbor_writer *writer, char *key, const char *value);

void cbor_string_int(struct cbor_writer *writer, char *key, int64_t value);

void cbor_string_epoch_time(struct cbor_writer *writer, char *key, int64_t time, int shift);
void cbor_string_relativ_time(struct cbor_writer *writer, char *key, int64_t time, int shift);
void cbor_string_uint(struct cbor_writer *writer, char *key, u64 value);
void cbor_string_ip(struct cbor_writer *writer, char *key, ip_addr);
void cbor_string_ipv4(struct cbor_writer *writer, char *key, ip4_addr);
void cbor_string_ipv6(struct cbor_writer *writer, char *key, ip6_addr);
void cbor_named_block_two_ints(struct cbor_writer *writer, char *key, char *name1, int val1, char *name2, int val2);
void cbor_write_to_file(struct cbor_writer *writer, char *filename);

void cbor_add_net(struct cbor_writer *writer, const net_addr *N);

#endif

#ifndef CBOR_H
#define CBOR_H

#include "nest/bird.h"


struct cbor_writer {
  int pt; // where will next byte go
  int capacity;
  int8_t *cbor;
  struct linpool *lp;
};


struct cbor_writer *cbor_init(uint8_t *buff, uint32_t capacity, struct linpool *lp);
  
void cbor_open_block(struct cbor_writer *writer);

void cbor_open_list(struct cbor_writer *writer);

void cbor_close_block_or_list(struct cbor_writer *writer);

void cbor_open_block_with_length(struct cbor_writer *writer, uint32_t length);

void cbor_open_list_with_length(struct cbor_writer *writer, uint32_t length);


void cbor_add_int(struct cbor_writer *writer, int64_t item);

void cbor_add_ipv4(struct cbor_writer *writer, ip4_addr);

void cbor_add_ipv6(struct cbor_writer *writer, ip6_addr);

void cbor_epoch_time(struct cbor_writer *writer, int64_t time, int shift);

void cbor_relativ_time(struct cbor_writer *writer, int64_t time, int shift);

void cbor_add_ipv4_prefix(struct cbor_writer *writer, net_addr_ip4 *n);


void cbor_add_ipv6_prefix(struct cbor_writer *writer, net_addr_ip6 *n);


void cbor_add_uint(struct cbor_writer *writer, uint64_t item);

void cbor_add_tag(struct cbor_writer *writer, int item);

void cbor_add_string(struct cbor_writer *writer, const char *string);

void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint32_t length);

void write_item(struct cbor_writer *writer, uint8_t major, uint64_t num);

void cbor_write_item_with_constant_val_length_4(struct cbor_writer *writer, uint8_t major, uint64_t num);

void rewrite_4bytes_int(struct cbor_writer *writer, int pt, int num);

#endif

#ifndef CBOR_H
#define CBOR_H
#include <stdint.h>


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

void cbor_add_ipv4(struct cbor_writer *writer, uint32_t addr);

void cbor_add_ipv6(struct cbor_writer *writer, uint32_t addr[4]);

void cbor_add_ipv4_prefix(struct cbor_writer *writer, uint32_t addr, uint32_t prefix);


void cbor_add_ipv6_prefix(struct cbor_writer *writer, uint32_t addr[4], uint32_t prefix);


void cbor_add_uint(struct cbor_writer *writer, uint64_t item);

void cbor_add_tag(struct cbor_writer *writer, int item);

void cbor_add_string(struct cbor_writer *writer, const char *string);

void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint32_t length);

#endif

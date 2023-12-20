/**
 *
 */

#ifndef _BIRD_CBOR_H_
#define _BIRD_CBOR_H_

#include "nest/bird.h"
#include "lib/ip.h"

struct cbor_writer {
  int pt;
  int capacity;
  int8_t *cbor;
  struct linpool *lp;
};

void write_item(struct cbor_writer *writer, u8 major, u64 num);
void check_memory(struct cbor_writer *writer, int add_size);

// TODO include header with linpool declaration
struct cbor_writer *cbor_init(byte *buff, uint capacity, struct linpool *lp);
void cbor_open_block(struct cbor_writer *writer);
void cbor_open_list(struct cbor_writer *writer);
void cbor_open_block_with_length(struct cbor_writer *writer, int length);
void cbor_open_list_with_length(struct cbor_writer *writer, int length);
void cbor_add_string(struct cbor_writer *writer, const char *string);
void cbor_named_block_two_ints(struct cbor_writer *writer, char *key, char *name1, int val1, char *name2, int val2);
void cbor_close_block_or_list(struct cbor_writer *writer);
void cbor_write_to_file(struct cbor_writer *writer, char *filename);
void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint length);
void cbor_add_net(struct cbor_writer *writer, const net_addr *N);


/*
 * Shortcuts
 */
void cbor_string_string(struct cbor_writer *writer, char *key, const char *value);
void cbor_string_int(struct cbor_writer *writer, char *key, int64_t value);
void cbor_string_uint(struct cbor_writer *writer, char *key, u64 value);
void cbor_string_ipv4(struct cbor_writer *writer, char *key, u32 value);
void cbor_string_ipv6(struct cbor_writer *wirter, char *key, u64 value);


#endif

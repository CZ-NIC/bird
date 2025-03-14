#include <stdio.h>
#include <stdlib.h>

#include "lib/cbor_shortcuts.h"



void cbor_string_string(struct cbor_writer *writer, char *key, const char *value) {
  cbor_add_string(writer, key);
  cbor_add_string(writer, value);
}

void cbor_string_int(struct cbor_writer *writer, char *key, int64_t value) {
  cbor_add_string(writer, key);
  cbor_add_int(writer, value);
}

void cbor_string_uint(struct cbor_writer *writer, char *key, u64 value) {
  cbor_add_string(writer, key);
  cbor_add_uint(writer, value);
}

void cbor_string_epoch_time(struct cbor_writer *writer, char *key, int64_t time, int shift) {
  cbor_add_string(writer, key);
  cbor_epoch_time(writer, time, shift);
}

void cbor_string_relativ_time(struct cbor_writer *writer, char *key, int64_t time, int shift) {
  cbor_add_string(writer, key);
  cbor_relativ_time(writer, time, shift);
}

void cbor_string_ip(struct cbor_writer *writer, char *key, ip_addr addr) {
  cbor_add_string(writer, key);
  if (ipa_is_ip4(addr))
    cbor_add_ipv4(writer, ipa_to_ip4(addr));
  else
    cbor_add_ipv6(writer, ipa_to_ip6(addr));
}

void cbor_string_ipv4(struct cbor_writer *writer, char *key, ip4_addr addr) {
  cbor_add_string(writer, key);
  cbor_add_ipv4(writer, addr);
}

void cbor_string_ipv6(struct cbor_writer *writer, char *key, ip6_addr addr) {
  cbor_add_string(writer, key);
  cbor_add_ipv6(writer, addr);
}

void cbor_named_block_two_ints(struct cbor_writer *writer, char *key, char *name1, int val1, char *name2, int val2) {
  cbor_add_string(writer, key);
  cbor_open_block_with_length(writer, 2);
  cbor_add_string(writer, name1);
  cbor_add_int(writer, val1);
  cbor_add_string(writer, name2);
  cbor_add_int(writer, val2);
}

void cbor_write_to_file(struct cbor_writer *writer, char *filename) {
  FILE *write_ptr;

  write_ptr = fopen(filename, "wb");

  fwrite(writer->cbor, writer->pt, 1, write_ptr);
  fclose(write_ptr);
}

void cbor_add_net(struct cbor_writer *writer, const net_addr *N) {
  // Original switch comes from lib/net.c and contains more cases.
  net_addr_union *n = (void *) N;

  switch (n->n.type)
  {
  case NET_IP4:
    cbor_add_ipv4_prefix(writer, &n->ip4);
    return;
  case NET_IP6:
    cbor_add_ipv6_prefix(writer, &n->ip6);
    return;
  default:
    bug("net type unsupported by cbor (yet)."); 
  }
}




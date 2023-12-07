#include <stdio.h>
#include <stdlib.h>

#include "nest/cbor.c"


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

void cbor_string_ipv4(struct cbor_writer *writer, char *key, u32 value) {
  cbor_add_string(writer, key);
  cbor_add_ipv4(writer, value);
}

void cbor_string_ipv6(struct cbor_writer *writer, char *key, u64 value) {
  cbor_add_string(writer, key);
  cbor_add_ipv6(writer, value);
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
    cbor_add_ipv4_prefix(writer, ip4_to_u32(n->ip4.prefix), n->ip4.pxlen);
    return;
  case NET_IP6:
    cbor_add_ipv6_prefix(writer, n->ip6.prefix, n->ip6.pxlen);
    return;
  case NET_VPN4:
    cbor_add_ipv4_prefix(writer, ip4_to_u32(n->vpn4.prefix), n->vpn4.pxlen);
    return;
  case NET_VPN6:
    cbor_add_ipv6_prefix(writer, n->vpn6.prefix, n->vpn6.pxlen);
    return;
  default:
    bug("net type unsupported by cbor (yet)."); 
  }
}

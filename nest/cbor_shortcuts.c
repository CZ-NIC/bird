#include <stdio.h>
#include <stdlib.h>

#include "nest/cbor.c"


void cbor_string_string(struct cbor_writer *writer, char *key, const char *value) {
  cbor_add_string(writer, key);
  cbor_add_string(writer, value);
}

void cbor_string_int(struct cbor_writer *writer, char *key, int value) {
  cbor_add_string(writer, key);
  cbor_add_int(writer, value);
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


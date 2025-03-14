#include <stdint.h>
#include <string.h>

#include "lib/cbor.h"


void write_item(struct cbor_writer *writer, uint8_t major, uint64_t num);
void check_memory(struct cbor_writer *writer, int add_size);

struct cbor_writer *cbor_init(uint8_t *buff, uint32_t capacity, struct linpool *lp)
{
  struct cbor_writer *writer = (struct cbor_writer*)lp_alloc(lp, sizeof(struct cbor_writer));
  writer->cbor = buff;
  writer->capacity = capacity;
  writer->pt = 0;
  writer->lp = lp;
  return writer;
}
  
void cbor_open_block(struct cbor_writer *writer) { // We will need to close the block later manualy
  check_memory(writer, 2);
  writer->cbor[writer->pt] = 0xbf;
  writer->pt++;
}

void cbor_open_list(struct cbor_writer *writer)
{
  check_memory(writer, 2);
  writer->cbor[writer->pt] = 0x9f;
  writer->pt++;
}

void cbor_close_block_or_list(struct cbor_writer *writer)
{
  check_memory(writer, 2);
  writer->cbor[writer->pt] = 0xff;
  writer->pt++;
}

void cbor_open_block_with_length(struct cbor_writer *writer, uint32_t length)
{
  write_item(writer, 5, length);
}

void cbor_open_list_with_length(struct cbor_writer *writer, uint32_t length)
{
  write_item(writer, 4, length);
}


void cbor_add_int(struct cbor_writer *writer, int64_t item)
{
  if (item >= 0)
  {
    write_item(writer, 0, item); // 0 is the "major" (three bits) introducing positive int, 1 is for negative
  }
  else
  {
    write_item(writer, 1, -item - 1);
  }
}

void cbor_epoch_time(struct cbor_writer *writer, int64_t time, int shift)
{
  write_item(writer, 6, 1); // 6 is TAG, 1 is tag number for epoch time
  cbor_relativ_time(writer, time, shift);
}

void cbor_relativ_time(struct cbor_writer *writer, int64_t time, int shift)
{
  write_item(writer, 6, 4); // 6 is TAG, 4 is tag number for decimal fraction
  cbor_open_list_with_length(writer, 2);
  cbor_add_int(writer, shift);
  cbor_add_int(writer, time);
}

void cbor_add_ipv4(struct cbor_writer *writer, ip4_addr addr)
{
  write_item(writer, 6, 52); // 6 is TAG, 52 is tag number for ipv4
  write_item(writer, 2, 4); // bytestring of length 4
  put_ip4(&writer->cbor[writer->pt], addr);
  writer->pt += 4;
}

void cbor_add_ipv6(struct cbor_writer *writer, ip6_addr addr)
{
  write_item(writer, 6, 54); // 6 is TAG, 54 is tag number for ipv6
  write_item(writer, 2, 16); // bytestring of length 16
  put_ip6(&writer->cbor[writer->pt], addr);
  writer->pt += 16;
}


void cbor_add_ipv4_prefix(struct cbor_writer *writer, net_addr_ip4 *n)
{
  write_item(writer, 6, 52); // 6 is TAG, 52 is tag number for ipv4
  cbor_open_block_with_length(writer, 2);
  cbor_add_int(writer, n->pxlen);
  write_item(writer, 2, 4); // bytestring of length 4
  put_ip4(&writer->cbor[writer->pt], n->prefix);
  writer->pt += 4;
}


void cbor_add_ipv6_prefix(struct cbor_writer *writer, net_addr_ip6 *n)
{
  write_item(writer, 6, 54); // 6 is TAG, 54 is tag number for ipv6
  cbor_open_block_with_length(writer, 2);
  cbor_add_int(writer, n->pxlen);

  write_item(writer, 2, 16);
  put_ip6(&writer->cbor[writer->pt], n->prefix);
  writer->pt += 16;
}


void cbor_add_uint(struct cbor_writer *writer, uint64_t item)
{
  write_item(writer, 0, item);
}

void cbor_add_tag(struct cbor_writer *writer, int item)
{
  write_item(writer, 6, item);
}

void cbor_add_string(struct cbor_writer *writer, const char *string)
{
  int length = strlen(string);
  write_item(writer, 3, length);  // 3 is major, then goes length of string and string
  check_memory(writer, length);
  memcpy(writer->cbor+writer->pt, string, length);
  writer->pt+=length;
}

void cbor_nonterminated_string(struct cbor_writer *writer, const char *string, uint32_t length)
{
  write_item(writer, 3, length);  // 3 is major, then goes length of string and string
  check_memory(writer, length);
  memcpy(writer->cbor+writer->pt, string, length);
  writer->pt+=length;
}

void write_item(struct cbor_writer *writer, uint8_t major, uint64_t num)
{
  //log("write major %i %li", major, num);
  major = major<<5;
  check_memory(writer, 10);
  if (num > ((uint64_t)1<<(4*8))-1)
  { // We need 8 bytes to encode the num
    major += 0x1b; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 7; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > (1<<(2*8))-1)
  { // We need 4 bytes to encode the num
    major += 0x1a; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 3; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > (1<<(8))-1)
  { // We need 2 bytes to encode the num
    major += 0x19; // reserving those bytes
    writer->cbor[writer->pt] = major;
    writer->pt++;
    for (int i = 1; i>=0; i--)
    { // write n-th byte of num
      uint8_t to_write = (num>>(i*8)) & 0xff;
      writer->cbor[writer->pt] = to_write;
      writer->pt++;
    }
    return;
  }
  if (num > 23)
  { // byte is enough, but aditional value would be too big
    major += 0x18; // reserving that byte
    writer->cbor[writer->pt] = major;
    writer->pt++;
    uint8_t to_write = num & 0xff;
    writer->cbor[writer->pt] = to_write;
    writer->pt++;
    return;
  }
  //log("write item major %i num %i writer->pt %i writer->capacity %i writer %i", major, num, writer->pt, writer->capacity, writer);
  major += num;  // we can store the num as additional value 
  writer->cbor[writer->pt] = major;
  writer->pt++;
}

void cbor_write_item_with_constant_val_length_4(struct cbor_writer *writer, uint8_t major, uint64_t num)
{
// this is only for headers which should be constantly long. 
  major = major<<5;
  check_memory(writer, 10);
  major += 0x1a; // reserving those bytes
  writer->cbor[writer->pt] = major;
  writer->pt++;
  for (int i = 3; i>=0; i--)
  { // write n-th byte of num
    uint8_t to_write = (num>>(i*8)) & 0xff;
    writer->cbor[writer->pt] = to_write;
    writer->pt++;
  }
}


void rewrite_4bytes_int(struct cbor_writer *writer, int pt, int num)
{
  for (int i = 3; i>=0; i--)
  {
    uint8_t to_write = (num>>(i*8)) & 0xff;
    writer->cbor[pt] = to_write;
    pt++;
  }
}

void check_memory(struct cbor_writer *writer, int add_size)
{
  if (writer->capacity - writer->pt-add_size < 0)
  {
    bug("There is not enough space for cbor response in given buffer");
  }
}

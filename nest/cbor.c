#include <stdint.h>



struct cbor_writer {
  int pt; // where will next byte go
  int capacity;
  int8_t *cbor;
  struct linpool *lp;
};

void write_item(struct cbor_writer *writer, int8_t major, int num);
void check_memory(struct cbor_writer *writer, int add_size);



struct cbor_writer *cbor_init(byte *buff, uint capacity, struct linpool *lp)
{
  struct cbor_writer *writer = (struct cbor_writer*)lp_alloc(lp, sizeof(struct cbor_writer));
  writer->cbor = buff;
  writer->capacity = capacity;
  writer->pt =0;
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

void cbor_open_block_with_length(struct cbor_writer *writer, int length)
{
  write_item(writer, 5, length);
}

void cbor_open_list_with_length(struct cbor_writer *writer, int length)
{
  write_item(writer, 4, length);
}


void cbor_add_int(struct cbor_writer *writer, int item)
{
  if (item >= 0)
  {
    write_item(writer, 0, item); // 0 is the "major" (three bits) introducing positive int, 1 is for negative
  }
  else
  {
    write_item(writer, 1, item);
  }
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

void write_item(struct cbor_writer *writer, int8_t major, int num)
{
  major = major<<5;
  check_memory(writer, 10);
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
  major += num;  // we can store the num as additional value 
  writer->cbor[writer->pt] = major;
  writer->pt++;
}

void check_memory(struct cbor_writer *writer, int add_size)
{
  if (writer->capacity - writer->pt-add_size < 0)
  {
    bug("There is not enough space for cbor response in given buffer");
  }
}

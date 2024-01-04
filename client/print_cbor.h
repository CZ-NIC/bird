#ifndef _BIRD_CLIENT_CBOR_H_
#define _BIRD_CLIENT_CBOR_H_

#include "nest/cbor.h"
#include "nest/cbor_parse.h"
#include "nest/cbor_shortcuts.h"

void print_show_memory(struct buff_reader *buf_read);
void print_cbor_response(byte *cbor, int len);

#endif

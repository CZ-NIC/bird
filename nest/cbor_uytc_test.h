#ifndef _BIRD_CBOR_UYTC_TEST_H_
#define _BIRD_CBOR_UYTC_TEST_H_

#include "nest/bird.h"
#include "lib/resource.h"
#include "lib/socket.h"
#include "lib/event.h"

extern pool *uytc_test_pool;

struct uytc_test {
  sock *s;
  event *event;
  void *data;
  byte *buffer;
  uint written;
  uint to_write;
};

void uytc_test_init(void);
void handle_uytc_test_conn(sock *s, uint size);

#endif

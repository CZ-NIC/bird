#ifndef _BIRD_CBOR_PARSE_
#define _BIRD_CBOR_PARSE_

#include "nest/bird.h"
#include "nest/cbor.h"

// TODO incude linpool declaration
uint parse_cbor(uint size, byte *rbuf, byte *tbuf, uint tbsize, struct linpool *lp);

uint detect_down(uint size, byte *rbuf);


#endif

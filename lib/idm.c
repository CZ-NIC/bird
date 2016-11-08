/*
 *	BIRD Library -- ID Map
 *
 *	(c) 2013--2015 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>

#include "nest/bird.h"
#include "lib/idm.h"
#include "lib/resource.h"
#include "lib/string.h"


void
idm_init(struct idm *m, pool *p, uint size)
{
  m->pos = 0;
  m->used = 1;
  m->size = size;
  m->data = mb_allocz(p, m->size * sizeof(u32));

  /* ID 0 is reserved */
  m->data[0] = 1;
}

static inline int u32_cto(uint x) { return ffs(~x) - 1; }

u32
idm_alloc(struct idm *m)
{
  uint i, j;

  for (i = m->pos; i < m->size; i++)
    if (m->data[i] != 0xffffffff)
      goto found;

  /* If we are at least 7/8 full, expand */
  if (m->used > (m->size * 28))
  {
    m->size *= 2;
    m->data = mb_realloc(m->data, m->size * sizeof(u32));
    memset(m->data + i, 0, (m->size - i) * sizeof(u32));
    goto found;
  }

  for (i = 0; i < m->pos; i++)
    if (m->data[i] != 0xffffffff)
      goto found;

  ASSERT(0);

found:
  ASSERT(i < 0x8000000);

  m->pos = i;
  j = u32_cto(m->data[i]);

  m->data[i] |= (1 << j);
  m->used++;
  return 32 * i + j;
}

void
idm_free(struct idm *m, u32 id)
{
  uint i = id / 32;
  uint j = id % 32;

  ASSERT((i < m->size) && (m->data[i] & (1 << j)));
  m->data[i] &= ~(1 << j);
  m->used--;
}

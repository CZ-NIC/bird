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
idm_init(struct idm *m, pool *p, u64 size, u64 max)
{
  m->pos = 0;
  m->used = 1;
  m->size = size;
  m->max = max;
  m->data = mb_allocz(p, m->size * sizeof(u32));

  /* ID 0 is reserved */
  m->data[0] = 1;
}

static inline int u32_cto(uint x) { return ffs(~x) - 1; }

u64
idm_alloc(struct idm *m)
{
  u64 i, j;

  for (i = m->pos; i < m->size; i++)
    if (m->data[i] != 0xffffffff)
      goto found;

  /* If we are at least 7/8 full, expand (if we are allowed to) */
  if ((m->used < m->max) && (m->used > m->size * 28))
  {
    m->size *= 2;
    m->data = mb_realloc(m->data, m->size * sizeof(u32));
    memset(m->data + i, 0, (m->size - i) * sizeof(u32));
    goto found;
  }

  for (i = 0; i < m->pos; i++)
    if (m->data[i] != 0xffffffff)
      goto found;

  return 0;

found:
  m->pos = i;
  j = u32_cto(m->data[i]);

  u64 id = 32 * i + j;

  ASSERT(id < m->max);

  m->data[i] |= (1 << j);
  m->used++;
  return id;
}

void
idm_free(struct idm *m, u64 id)
{
  u64 i = id / 32;
  u64 j = id % 32;

  ASSERT((i < m->size) && (m->data[i] & (1 << j)));
  m->data[i] &= ~(1 << j);
  m->used--;
}

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

static void
idm_grow(struct idm *m, u32 size)
{
  m->data = mb_realloc(m->data, size * sizeof(u32));
  memset(m->data + m->size, 0, (size - m->size) * sizeof(u32));
  m->size = size;
}

int
idm_alloc_given(struct idm *m, u32 val)
{
  uint i = val / 32, j = val % 32;
  if (i >= m->size)
    idm_grow(m, i+1);

  if (m->data[i] & (1 << j))
    return 0;

  m->data[i] |= (1 << j);
  m->used--;
  return 1;
}

/**
 * Allocate a new ID
 * @m: the ID Map to be used
 * @min: minimal value returned
 * @max: maximal value returned
 *
 * Returns the allocated value. Returns 0 if allocation is impossible.
 */
u32
idm_alloc(struct idm *m, u32 min, u32 max)
{
  uint mini = min / 32, maxi = max / 32;

  u32 minmask = ~((1 << (min % 32)) - 1);
  u32 maxmask = ((1ULL << ((max+1) % 32)) - 1);

  u32 mask;

  uint i, j;

  /* Not even allocated data array at mini. */
  if (mini >= m->size)
  {
    i = mini;
    idm_grow(m, mini+1);
    mask = minmask;
    goto found;
  }

  /* Only one u32 contains all possible values. */
  if (mini == maxi)
  {
    mask = (minmask & maxmask);
    if ((m->data[mini] & mask) == (mask))
      return 0;
    i = mini;
    goto found;
  }

  /*
   * a)
   *                   m->pos
   *                    v
   * u32's in m->data: ..............................
   *                          ^           ^
   *                         mini        maxi
   *
   * b)
   *                               m->pos
   *                                v
   * u32's in m->data: ..............................
   *                          ^           ^
   *                         mini        maxi
   *
   * c)
   *                                          m->pos
   *                                           v
   * u32's in m->data: ..............................
   *                          ^           ^
   *                         mini        maxi
   *
   */

  /* Beginning at: mini+1 (a) or m->pos (b,c) m->pos
   * End at last before: MIN(maxi, m->size) ... this skips loop at c)
   */
  for (i = MAX(mini+1, m->pos); i < MIN(maxi, m->size); i++)
    if (m->data[i] != (mask = 0xffffffff))
      goto found;

  /* if maxi points to an allocated value */
  if (maxi < m->size)
    if ((m->data[i = maxi] & maxmask) != (mask = maxmask))
      goto found;

  /* If we have just hit m->size and we are at least 7/8 full, expand */
  if ((i == m->size) && (m->used > (m->size * 28)))
  {
    idm_grow(m, m->size * 2);
    mask = 0xffffffff;
    goto found;
  }

  /* Trying i == mini (skipped before) */
  if ((m->data[i = mini] & minmask) != (mask = minmask))
    goto found;

  /* Beginning at mini+1 in all cases
   * End before m->pos (a,b) or maxi (c), whatever comes earlier. This skips loop at a) */

  for (i = mini+1; i < MIN(maxi, m->pos); i++)
    if (m->data[i] != (mask = 0xffffffff))
      goto found;

  return 0;

 found:
  if (i >= 0x8000000) // Too large value
    return 0;

  m->pos = i;
  j = u32_cto(m->data[i] | ~mask);

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

#ifdef TEST

#include <stdio.h>
#include <string.h>

#include "sysdep/unix/unix.h"

struct idm m;

static void idm_dump(struct idm *m)
{
  int w = 0;
  char b[90];
  for (int i=0; i<m->size; i++) {
    u32 val = m->data[i];
    while (val) {
      u32 n = ffs(val)-1;
      w += sprintf(b + w, "%u,", i*32 + n);
      if (w < 72) {
	b[w++] = ' ';
      }
      else {
	b[w++] = '\n';
	b[w] = 0;
	debug(b);
	w = 0;
      }
      val &= ~(1U<<n);
    }
  }

  if (w) {
    b[w++] = '\n';
    b[w] = 0;
    debug(b);
  }
}

static void bitdump(u32 val)
{
  for (int i=0;i<32;i++)
    debug("%c", "01"[!!(val&(1<<i))]);
}

static void dump(const char *msg)
{
  debug(msg);
  debug("Used: %u, Pos: %u, Size: %u\n", m.used, m.pos, m.size);
  idm_dump(&m);
#if 0
  for (int i=0;i<m.size;i+=2) {
    debug("%3d: ", i*32);
    bitdump(m.data[i]);
    bitdump(m.data[i+1]);
    debug("\n");
  }
#endif
}

#define TA(min, max)  debug("Alloc from (%u, %u): %u\n", min, max, idm_alloc(&m, min, max)); dump("")
#define TF(n)	      debug("Free %u\n", n); idm_free(&m, n); dump("")

int main(void)
{
  log_init_debug(NULL);
  resource_init();
  idm_init(&m, &root_pool, 4);

  TA(20, 40);
  TA(20, 40);
  TA(20, 40);
  TA(20, 40);
  TA(10, 30);
  TA(10, 20);
  TF(10);
  TA(10, 20);
  TF(11);
  TA(65, 65);
  debug("Alloc enough to auto-grow\n");
  for (int i=0; i<105; i++)
    idm_alloc(&m, 0, 200);
  dump("");
  TA(0, 200);
  TA(0, 200);

  TA(513, 513);

  TA(1000, 2000);
  TA(256, 257);
  TA(256, 257);
  TA(256, 257);
  TF(1000);

}

#endif

/*
 *	BIRD Library -- ID Map
 *
 *	(c) 2013--2015 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013--2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_IDM_H_
#define _BIRD_IDM_H_

struct idm
{
  u32 *data;
  u64 pos;
  u64 used;
  u64 size;
  u64 max;
};

void idm_init(struct idm *m, pool *p, u64 size, u64 max);
u64 idm_alloc(struct idm *m);
void idm_free(struct idm *m, u64 id);

#endif

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
  u32 pos;
  u32 used;
  u32 size;
};

void idm_init(struct idm *m, pool *p, uint size);
u32 idm_alloc(struct idm *m);
void idm_free(struct idm *m, u32 id);

#endif

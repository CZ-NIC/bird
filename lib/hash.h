/*
 *	BIRD Library -- Generic Hash Table
 *
 *	(c) 2013 Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2013 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_HASH_H_
#define _BIRD_HASH_H_

enum hash_walk_state {
  NO_WALK,
  WALK,
  WALK_DELSAFE,
  WALK_RESIZABLE,
  NEED_RESIZE
};


#define HASH(type)		struct { type **data; uint count, order; char* is_in_walk; int* deep_of_walks;}
#define HASH_TYPE(v)		typeof(** (v).data)
#define HASH_SIZE(v)		(1U << (v).order)

#define HASH_EQ(v,id,k1,k2...)	(id##_EQ(k1, k2))
#define HASH_FN(v,id,key...)	((u32) (id##_FN(key)) >> (32 - (v).order))


#define HASH_INIT(v,pool,init_order)					\
  ({									\
    (v).count = 0;							\
    (v).order = (init_order);						\
    (v).data = mb_allocz(pool, HASH_SIZE(v) * sizeof(* (v).data));	\
    (v).is_in_walk = mb_allocz(pool, sizeof(char));			\
    *(v).is_in_walk = NO_WALK;						\
    (v).deep_of_walks = mb_allocz(pool, sizeof(char));			\
    *(v).deep_of_walks = 0;						\
  })

#define HASH_FREE(v)							\
  ({									\
    mb_free((v).data);							\
    (v) = (typeof(v)){ };						\
  })

#define HASH_FIND(v,id,key...)						\
  ({									\
    u32 _h = HASH_FN(v, id, key);					\
    HASH_TYPE(v) *_n = (v).data[_h];					\
    while (_n && !HASH_EQ(v, id, id##_KEY(_n), key))			\
      _n = id##_NEXT(_n);						\
    _n;									\
  })

#define HASH_INSERT(v,id,node)						\
  ({									\
    u32 _h = HASH_FN(v, id, id##_KEY((node)));				\
    HASH_TYPE(v) **_nn = (v).data + _h;					\
    id##_NEXT(node) = *_nn;						\
    *_nn = node;							\
    (v).count++;							\
  })

#define HASH_DO_REMOVE(v,id,_nn)					\
  ({									\
    *_nn = id##_NEXT((*_nn));						\
    (v).count--;							\
  })

#define HASH_DELETE(v,id,key...)					\
  ({									\
    if (*(v).is_in_walk == WALK)					\
      bug("HASH_DELETE: Attempt to delete in HASH_WALK");		\
    if (*(v).deep_of_walks > 1)						\
      bug("HASH_DELETE: Attempt to delete inside multiple hash walks");	\
    u32 _h = HASH_FN(v, id, key);					\
    HASH_TYPE(v) *_n, **_nn = (v).data + _h;				\
									\
    while ((*_nn) && !HASH_EQ(v, id, id##_KEY((*_nn)), key))		\
      _nn = &(id##_NEXT((*_nn)));					\
									\
    if (_n = *_nn)							\
      HASH_DO_REMOVE(v,id,_nn);						\
    _n;									\
  })

#define HASH_REMOVE(v,id,node)						\
  ({									\
    if (*(v).is_in_walk == WALK)					\
      bug("HASH_REMOVE: Attempt to remove in HASH_WALK");		\
    if (*(v).deep_of_walks > 1)						\
      bug("HASH_REMOVE: Attempt to remove inside multiple hash walks");	\
    u32 _h = HASH_FN(v, id, id##_KEY((node)));				\
    HASH_TYPE(v) *_n, **_nn = (v).data + _h;				\
									\
    while ((*_nn) && (*_nn != (node)))					\
      _nn = &(id##_NEXT((*_nn)));					\
									\
    if (_n = *_nn)							\
      HASH_DO_REMOVE(v,id,_nn);						\
    _n;									\
  })


#define HASH_REHASH(v,id,pool,step)					\
  ({									\
    HASH_TYPE(v) *_n, *_n2, **_od;					\
    uint _i, _os;							\
									\
    _os = HASH_SIZE(v);							\
    _od = (v).data;							\
    (v).count = 0;							\
    (v).order += (step);						\
    (v).data = mb_allocz(pool, HASH_SIZE(v) * sizeof(* (v).data));	\
									\
    for (_i = 0; _i < _os; _i++)					\
      for (_n = _od[_i]; _n && (_n2 = id##_NEXT(_n), 1); _n = _n2)	\
	HASH_INSERT(v, id, _n);						\
									\
    mb_free(_od);							\
  })

#define REHASH_LO_MARK(a,b,c,d,e,f)	a
#define REHASH_HI_MARK(a,b,c,d,e,f)	b
#define REHASH_LO_STEP(a,b,c,d,e,f)	c
#define REHASH_HI_STEP(a,b,c,d,e,f)	d
#define REHASH_LO_BOUND(a,b,c,d,e,f)	e
#define REHASH_HI_BOUND(a,b,c,d,e,f)	f

#define HASH_DEFINE_REHASH_FN(id,type)					\
  static void id##_REHASH(void *v, pool *p, int step)			\
  { HASH_REHASH(* (HASH(type) *) v, id, p, step); }


#define HASH_MAY_STEP_UP(v,id,pool)	HASH_MAY_STEP_UP_(v,pool, id##_REHASH, id##_PARAMS)
#define HASH_MAY_STEP_DOWN(v,id,pool)	HASH_MAY_STEP_DOWN_(v,pool, id##_REHASH, id##_PARAMS)
#define HASH_MAY_RESIZE_DOWN(v,id,pool)	HASH_MAY_RESIZE_DOWN_(v,pool, id##_REHASH, id##_PARAMS)

#define HASH_MAY_STEP_UP_(v,pool,rehash_fn,args)			\
  ({                                                                    \
    if (((v).count > (HASH_SIZE(v) REHASH_HI_MARK(args))) &&	\
	((v).order <= (REHASH_HI_BOUND(args) - REHASH_HI_STEP(args)))) \
      rehash_fn(&(v), pool, REHASH_HI_STEP(args));			\
  })

#define HASH_MAY_STEP_DOWN_(v,pool,rehash_fn,args)			\
  ({                                                                    \
    if (((v).count < (HASH_SIZE(v) REHASH_LO_MARK(args))) &&	\
	((v).order >= (REHASH_LO_BOUND(args) + REHASH_LO_STEP(args)))) \
      rehash_fn(&(v), pool, -(REHASH_LO_STEP(args)));			\
  })

#define HASH_MAY_RESIZE_DOWN_(v,pool,rehash_fn,args)			\
  ({  									\
    uint _o = (v).order;						\
    while (((v).count < ((1U << _o) REHASH_LO_MARK(args))) &&		\
	   (_o > (REHASH_LO_BOUND(args))))				\
      _o -= (REHASH_LO_STEP(args));					\
    if (_o < (v).order)						\
      rehash_fn(&(v), pool, _o - (v).order);				\
  })


#define HASH_INSERT2(v,id,pool,node)					\
  ({									\
    if (*(v).is_in_walk == WALK || *(v).is_in_walk == WALK_DELSAFE)	\
      bug("HASH_INSERT2: called in hash walk or hash delsafe walk");	\
    HASH_INSERT(v, id, node);						\
    if (*(v).is_in_walk == NO_WALK)					\
      HASH_MAY_STEP_UP(v, id, pool);					\
    else if (*(v).is_in_walk == WALK_RESIZABLE)				\
      *(v).is_in_walk = NEED_RESIZE;					\
  })

#define HASH_DELETE2(v,id,pool,key...)					\
  ({									\
    if (*(v).is_in_walk == WALK || *(v).is_in_walk == WALK_DELSAFE)	\
      bug("HASH_DELETE2 called in hash walk or hash delsafe walk");	\
    HASH_TYPE(v) *_n = HASH_DELETE(v, id, key);				\
    if (*(v).is_in_walk == WALK_RESIZABLE)				\
      *(v).is_in_walk = NEED_RESIZE;					\
    else if (*(v).is_in_walk == NO_WALK)				\
      if (_n) HASH_MAY_STEP_DOWN(v, id, pool);				\
    _n;									\
  })

#define HASH_REMOVE2(v,id,pool,node)					\
  ({									\
    if (*(v).is_in_walk == WALK || *(v).is_in_walk == WALK_DELSAFE)	\
      bug("HASH_REMOVE2 called in hash walk or hash delsafe walk");	\
    HASH_TYPE(v) *_n = HASH_REMOVE(v, id, node);			\
    if (*(v).is_in_walk == WALK_RESIZABLE)				\
      *(v).is_in_walk = NEED_RESIZE;					\
    else if (*(v).is_in_walk == NO_WALK)				\
      if (_n) HASH_MAY_STEP_DOWN(v, id, pool);				\
    _n;									\
  })


#define HASH_WALK(v,next,n)						\
  do {									\
    HASH_TYPE(v) *n;							\
    if (*(v).is_in_walk != WALK && *(v).is_in_walk != NO_WALK)		\
      bug("HASH_WALK can not be called from other walks");		\
    *(v).is_in_walk = WALK;						\
    *(v).deep_of_walks += 1;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (n = (v).data[_i]; n; n = n->next)

#define HASH_WALK_END(v)						\
  if (*(v).is_in_walk != WALK)						\
    bug("HASH_WALK_END called when HASH_WALK is not opened");		\
  *(v).deep_of_walks -= 1;						\
  if (*(v).deep_of_walks == 0)						\
    *(v).is_in_walk = NO_WALK;						\
  } while (0)								\


#define HASH_WALK_DELSAFE(v,next,n)					\
  do {									\
    HASH_TYPE(v) *n, *_next;						\
    if (*(v).is_in_walk != NO_WALK && *(v).is_in_walk != WALK_DELSAFE)	\
      bug("HASH_WALK_DELSAFE can not be called from other walks");	\
    *(v).is_in_walk = WALK_DELSAFE;					\
    *(v).deep_of_walks += 1;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (n = (v).data[_i]; n && (_next = n->next, 1); n = _next)

#define HASH_WALK_DELSAFE_END(v) 					\
  if (*(v).is_in_walk != WALK_DELSAFE)					\
    bug("HASH_WALK_DELSAFE_END called when HASH_WALK_DELSAFE is not opened"); \
  *(v).deep_of_walks -= 1;						\
  if (*(v).deep_of_walks == 0)						\
    *(v).is_in_walk = NO_WALK;						\
  } while (0)


#define HASH_WALK_RESIZABLE(v,next,n)					\
  do {									\
    HASH_TYPE(v) *n, *_next;						\
    if (*(v).is_in_walk == NO_WALK)					\
      *(v).is_in_walk = WALK_RESIZABLE;					\
    else if (*(v).is_in_walk != WALK_RESIZABLE && *(v).is_in_walk != NEED_RESIZE) \
      bug("HASH_WALK_RESIZABLE can not be called from other walks");	\
    *(v).deep_of_walks += 1;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (n = (v).data[_i]; n && (_next = n->next, 1); n = _next)

#define HASH_WALK_RESIZABLE_END(v, id, pool) 				\
  if (*(v).is_in_walk != WALK_RESIZABLE && *(v).is_in_walk != NEED_RESIZE) \
    bug("HASH_WALK_RESIZABLE_END called when HASH_WALK_RESIZABLE is not opened"); \
  *(v).deep_of_walks -= 1;						\
  if (*(v).deep_of_walks == 0)						\
  {									\
    if (*(v).is_in_walk == NEED_RESIZE)					\
    {									\
      *(v).is_in_walk = NO_WALK;					\
      uint order;							\
      do {								\
        order = (v).order;						\
        HASH_MAY_STEP_DOWN(v, id, pool);				\
      } while (order!=(v).order);					\
      do {								\
        order = (v).order;						\
        HASH_MAY_STEP_UP(v, id, pool);					\
      } while (order!=(v).order);					\
    }									\
    *(v).is_in_walk = NO_WALK;						\
  }									\
  } while (0)

#define HASH_WALK_FILTER(v,next,n,nn)					\
  do {									\
    HASH_TYPE(v) *n, **nn;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (nn = (v).data + _i; n = *nn; (*nn == n) ? (nn = &n->next) : NULL)

#define HASH_WALK_FILTER_END } while (0)


static inline void
mem_hash_init(u64 *h)
{
  *h = 0x001047d54778bcafULL;
}

static inline void
mem_hash_mix(u64 *h, const void *p, uint s)
{
  const u64 multiplier = 0xb38bc09a61202731ULL;
  const char *pp = p;
  uint i;

  for (i=0; i<s/4; i++)
    *h = *h * multiplier + ((const u32 *)pp)[i];

  for (i=s & ~0x3; i<s; i++)
    *h = *h * multiplier + pp[i];
}

static inline void
mem_hash_mix_str(u64 *h, const char *s)
{
  const u64 multiplier = 0xb38bc09a61202731ULL;
  while (s)
    *h = *h * multiplier + *s++;
}

static inline void
mem_hash_mix_num(u64 *h, u64 val)
{
  mem_hash_mix(h, &val, sizeof(val));
}

static inline uint
mem_hash_value(u64 *h)
{
  return ((*h >> 32) ^ (*h & 0xffffffff));
}

static inline uint
mem_hash(const void *p, uint s)
{
  static u64 h;
  mem_hash_init(&h);
  mem_hash_mix(&h, p, s);
  return mem_hash_value(&h);
}

static inline uint
ptr_hash(const void *ptr)
{
  uintptr_t p = (uintptr_t) ptr;
  return p ^ (p << 8) ^ (p >> 16);
}

#endif

/*
 *	BIRD Library -- Generic Hash Table
 *
 *	(c) 2013	Ondrej Zajicek <santiago@crfreenet.org>
 *	(c) 2024	Maria Matejka <mq@jmq.cz>
 *	(c) 2013--2024	CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_HASH_H_
#define _BIRD_HASH_H_

/*
 * Regular hash table
 */

#define HASH(type)		struct { type **data; uint count; u8 order; }
#define HASH_TYPE(v)		typeof(** (v).data)
#define HASH_SIZE(v)		(1U << (v).order)

#define HASH_EQ(v,id,k1,k2...)	(id##_EQ(k1, k2))
#define HASH_FN(v,id,key...)	((u32) (id##_FN(key)) >> (32 - (v).order))
#define HASH_FNO(id,key...)	id##_FN(key)

#define HASH_INIT(v,pool,init_order)					\
  ({									\
    (v).count = 0;							\
    (v).order = (init_order);						\
    (v).data = mb_allocz(pool, HASH_SIZE(v) * sizeof(* (v).data));	\
  })

#define HASH_FREE(v)							\
  ({									\
    mb_free((v).data);							\
    (v) = (typeof(v)){ };						\
  })

#define HASH_FIND_CHAIN(v,id,key...)					\
  ({									\
    u32 _h = HASH_FN(v, id, key);					\
    (v).data[_h];							\
  })

#define HASH_FIND(v,id,key...)						\
  ({									\
    HASH_TYPE(v) *_n = HASH_FIND_CHAIN(v, id, key);			\
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
    if (((v).count > (HASH_SIZE(v) REHASH_HI_MARK(args))) &&		\
	((v).order < (REHASH_HI_BOUND(args))))				\
      rehash_fn(&(v), pool, REHASH_HI_STEP(args));			\
  })

#define HASH_MAY_STEP_DOWN_(v,pool,rehash_fn,args)			\
  ({                                                                    \
    if (((v).count < (HASH_SIZE(v) REHASH_LO_MARK(args))) &&		\
	((v).order > (REHASH_LO_BOUND(args))))				\
      rehash_fn(&(v), pool, -(REHASH_LO_STEP(args)));			\
  })

#define HASH_MAY_RESIZE_DOWN_(v,pool,rehash_fn,args)			\
  ({                                                                    \
    {									\
      uint _o = (v).order;						\
      while (((v).count < ((1U << _o) REHASH_LO_MARK(args))) &&		\
	     (_o > (REHASH_LO_BOUND(args))))				\
	_o -= (REHASH_LO_STEP(args));					\
      if (_o < (v).order)						\
	rehash_fn(&(v), pool, _o - (v).order);				\
    }									\
   })


#define HASH_INSERT2(v,id,pool,node)					\
  ({									\
    HASH_INSERT(v, id, node);						\
    HASH_MAY_STEP_UP(v, id, pool);					\
  })

#define HASH_DELETE2(v,id,pool,key...)					\
  ({									\
    HASH_TYPE(v) *_n = HASH_DELETE(v, id, key);				\
    if (_n) HASH_MAY_STEP_DOWN(v, id, pool);				\
    _n;									\
  })

#define HASH_REMOVE2(v,id,pool,node)					\
  ({									\
    HASH_TYPE(v) *_n = HASH_REMOVE(v, id, node);			\
    if (_n) HASH_MAY_STEP_DOWN(v, id, pool);				\
    _n;									\
  })


#define HASH_WALK(v,next,n)						\
  do {									\
    HASH_TYPE(v) *n;							\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (n = (v).data[_i]; n; n = n->next)

#define HASH_WALK_END } while (0)


#define HASH_WALK_DELSAFE(v,next,n)					\
  do {									\
    HASH_TYPE(v) *n, *_next;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (n = (v).data[_i]; n && (_next = n->next, 1); n = _next)

#define HASH_WALK_DELSAFE_END } while (0)


#define HASH_WALK_FILTER(v,next,n,nn)					\
  do {									\
    HASH_TYPE(v) *n, **nn;						\
    uint _i;								\
    uint _s = HASH_SIZE(v);						\
    for (_i = 0; _i < _s; _i++)						\
      for (nn = (v).data + _i; n = *nn; (*nn == n) ? (nn = &n->next) : NULL)

#define HASH_WALK_FILTER_END } while (0)


/*
 * Atomic hash table with data-local spinlocks
 */

#define SPINHASH(type)							\
struct {								\
  _Atomic uint count;							\
  rw_spinlock lock;							\
  uint cur_order, new_order;						\
  struct { type *data; rw_spinlock lock; } *cur, *new;			\
  pool *pool;								\
  event rehash;								\
  event_list *target;							\
}

#define SPINHASH_INIT(v,id,_pool,_target)				\
  ({									\
    atomic_store_explicit(&(v).count, 0, memory_order_relaxed);		\
    (v).cur_order = id##_ORDER;						\
    (v).new_order = 0;							\
    (v).cur = mb_allocz(_pool, (1U << id##_ORDER) * sizeof *(v).cur);	\
    (v).new = NULL;							\
    (v).pool = _pool;							\
    (v).rehash = (event) { .hook = id##_REHASH, .data = &(v), };	\
    (v).target = _target;						\
  })

#define SPINHASH_FREE(v)						\
  ({									\
    ev_postpone(&(v).rehash);						\
    mb_free((v).cur);							\
    ASSERT_DIE((v).new == NULL);					\
    (v).cur = NULL;							\
    (v).cur_order = 0;							\
    (v).pool = NULL;							\
    (v).target = NULL;							\
  })

#define SPINHASH_BEGIN_CHAIN(v,id,rw,n,key...)				\
  do {									\
    typeof (&v) _v = &(v);						\
    rws_read_lock(&_v->lock);						\
    u32 _hh = id##_FN(key);						\
    SPINHASH_BEGIN_CHAIN_INDEX(v,_hh,rw,n);				\

#define SPINHASH_BEGIN_CHAIN_INDEX(v,h,rw,n)				\
    u32 _ch = (h) >> (32 - (v).cur_order);				\
    rw_spinlock *_lock = &(v).cur[_ch].lock;				\
    rws_##rw##_lock(_lock);						\
    typeof (&(v).cur[_ch].data) n = &(v).cur[_ch].data;			\
    if (*n == SPINHASH_REHASH_SENTINEL) {				\
      rws_##rw##_unlock(_lock);						\
      u32 _nh = (h) >> (32 - (v).new_order);				\
      _lock = &(v).new[_nh].lock;					\
      rws_##rw##_lock(_lock);						\
      n = &(v).new[_nh].data;						\
      ASSERT_DIE(*n != SPINHASH_REHASH_SENTINEL);			\
    };

#define SPINHASH_END_CHAIN_INDEX(rw)					\
    rws_##rw##_unlock(_lock);						\

#define SPINHASH_END_CHAIN(rw)						\
    SPINHASH_END_CHAIN_INDEX(rw);					\
    rws_read_unlock(&_v->lock);						\
  } while (0)

#define SPINHASH_FIND(v,id,key...)					\
  ({									\
    typeof ((v).cur[0].data) _n;					\
    SPINHASH_BEGIN_CHAIN(v,id,read,_c,key);				\
    while ((*_c) && !HASH_EQ(v,id,id##_KEY((*_c)), key))		\
      _c = &id##_NEXT((*_c));						\
    _n = *_c;								\
    SPINHASH_END_CHAIN(read);						\
    _n;									\
  })

#define SPINHASH_INSERT(v,id,n)						\
  do {									\
    rws_read_lock(&(v).lock);						\
    uint _h = HASH_FNO(id, id##_KEY(n));				\
    uint _ch = _h >> (32 - (v).cur_order);				\
    rws_write_lock(&(v).cur[_ch].lock);					\
    if ((v).cur[_ch].data == SPINHASH_REHASH_SENTINEL) {		\
      uint _nh = _h >> (32 - (v).new_order);				\
      rws_write_lock(&(v).new[_nh].lock);				\
      ASSERT_DIE((v).new[_nh].data != SPINHASH_REHASH_SENTINEL);	\
      id##_NEXT(n) = (v).new[_nh].data;					\
      (v).new[_nh].data = n;						\
      rws_write_unlock(&(v).new[_nh].lock);				\
    } else {								\
      id##_NEXT(n) = (v).cur[_ch].data;					\
      (v).cur[_ch].data = n;						\
    }									\
    rws_write_unlock(&(v).cur[_ch].lock);				\
    uint count = atomic_fetch_add_explicit(&(v).count, 1, memory_order_relaxed);\
    SPINHASH_REQUEST_REHASH(v,id,count);				\
    rws_read_unlock(&(v).lock);						\
  } while (0)								\

#define SPINHASH_REMOVE(v,id,n)						\
  do {									\
    typeof(n) _n = (n);							\
    SPINHASH_BEGIN_CHAIN(v,id,write,_c,id##_KEY(_n))			\
      for (; *_c; _c = &id##_NEXT((*_c)))				\
	if (_n == *_c) {						\
	  SPINHASH_DO_REMOVE(v,id,_c);					\
	  break;							\
	}								\
    SPINHASH_END_CHAIN(write);						\
    uint count = atomic_load_explicit(&(v).count, memory_order_relaxed);\
    SPINHASH_REQUEST_REHASH(v,id,count);				\
  } while (0)

#define SPINHASH_DO_REMOVE(v,id,c)					\
  atomic_fetch_sub_explicit(&(v).count, 1, memory_order_relaxed);	\
  *c = id##_NEXT((*c));							\

#define SPINHASH_WALK(v,id,n)						\
  SPINHASH_WALK_CHAINS(v,id,read,nn)					\
  for (typeof (*nn) n = *nn; n; n = id##_NEXT(n)) {			\

#define SPINHASH_WALK_END						\
  }									\
  SPINHASH_WALK_CHAINS_END(read)					\

#define SPINHASH_WALK_FILTER(v,id,rw,nn)				\
  SPINHASH_WALK_CHAINS(v,id,rw,nn)					\
  for (; nn && *nn; nn = nn ? &id##_NEXT((*nn)) : NULL)

#define SPINHASH_WALK_FILTER_END(rw) SPINHASH_WALK_CHAINS_END(rw)

#define SPINHASH_WALK_CHAINS(v,id,rw,nn)				\
  do {									\
    typeof (&v) _v = &(v);						\
    rws_read_lock(&_v->lock);						\
    for (uint _h = 0; !(_h >> _v->cur_order); _h++) {			\
      SPINHASH_BEGIN_CHAIN_INDEX(v,_h,rw,nn);				\

#define SPINHASH_WALK_CHAINS_END(rw)					\
      SPINHASH_END_CHAIN_INDEX(rw);					\
    }									\
    rws_read_unlock(&_v->lock);						\
  } while (0)

#define SPINHASH_CHECK_REHASH(v,id,count) SPINHASH_CHECK_REHASH_(v,id,count,id##_PARAMS)

#define SPINHASH_CHECK_REHASH_(v,id,count,args)				\
  ({									\
    uint order = (v).new_order ?: (v).cur_order;			\
    uint size = 1U << order;						\
    ((count > size REHASH_HI_MARK(args)) && (order < REHASH_HI_BOUND(args))) ? \
    REHASH_HI_STEP(args) :						\
    ((count < size REHASH_LO_MARK(args)) && (order > REHASH_LO_BOUND(args))) ? \
    -REHASH_LO_STEP(args) :						\
    0;									\
  })

#define SPINHASH_REQUEST_REHASH(v,id,count)				\
  if (SPINHASH_CHECK_REHASH(v,id,count) && (v).target)			\
      ev_send((v).target, &(v).rehash);

#define SPINHASH_DEFINE_REHASH_FN(id,type)				\
static void id##_REHASH(void *_v) {					\
  SPINHASH(type) *v = _v;						\
  SPINHASH_REHASH_FN_BODY(v,id,type);					\
}

#define SPINHASH_REHASH_FN_BODY(v,id,type)				\
  int step;								\
  SPINHASH_REHASH_PREPARE(v,id,type,step);				\
  if (step) {								\
    if (step > 0) SPINHASH_REHASH_UP(id,type,step);			\
    if (step < 0) SPINHASH_REHASH_DOWN(id,type,-step);			\
    SPINHASH_REHASH_FINISH(v,id);					\
  }									\

#define SPINHASH_REHASH_PREPARE(v,id,type,step)				\
  rws_write_lock(&(v)->lock);						\
  ASSERT_DIE((v)->new_order == 0);					\
  uint _cb = atomic_load_explicit(&(v)->count, memory_order_relaxed);	\
  step = SPINHASH_CHECK_REHASH((*(v)),id,_cb);				\
  if (step) {								\
    (v)->new_order = (v)->cur_order + step;				\
    uint nsz = 1U << (v)->new_order;					\
    (v)->new = mb_alloc((v)->pool, nsz * sizeof *(v)->new);		\
    for (uint i=0; i<nsz; i++) {					\
      (v)->new[i].data = SPINHASH_REHASH_SENTINEL;			\
      (v)->new[i].lock = (rw_spinlock) {};				\
    }									\
  }									\
  rws_write_unlock(&(v)->lock);						\

#define SPINHASH_REHASH_FINISH(v,id)					\
  ASSERT_DIE(step);							\
  rws_write_lock(&(v)->lock);						\
  (v)->cur = (v)->new; (v)->cur_order = (v)->new_order;			\
  (v)->new = NULL; (v)->new_order = 0;					\
  uint _ce = atomic_load_explicit(&(v)->count, memory_order_relaxed);	\
  SPINHASH_REQUEST_REHASH(*(v),id,_ce)					\
  rws_write_unlock(&(v)->lock);						\
  mb_free((v)->new);							\

#define SPINHASH_REHASH_UP(v,id,type,step)				\
  for (uint i=0; !(i >> (v)->cur_order); i++) {				\
    rws_write_lock(&(v)->cur[i].lock);					\
    for (uint p=0; !(p >> step); p++) {					\
      uint ppos = (i << step) | p;					\
      rws_write_lock(&(v)->new[ppos].lock);				\
      ASSERT_DIE((v)->new[ppos].data == SPINHASH_REHASH_SENTINEL);	\
      (v)->new[ppos].data = NULL;					\
    }									\
    for (type *n; n = (v)->cur[i].data; ) {				\
      (v)->cur[i].data = id##_NEXT(n);					\
      uint _h = HASH_FNO(id, id##_KEY(n));				\
      ASSERT_DIE((_h >> (32 - (v)->cur_order)) == i);			\
      uint _nh = _h >> (32 - (v)->new_order);				\
      id##_NEXT(n) = (v)->new[_nh].data;				\
      (v)->new[_nh].data = n;						\
    }									\
    (v)->cur[i].data = SPINHASH_REHASH_SENTINEL;			\
    for (uint p=0; !(p >> step); p++)					\
      rws_write_unlock(&(v)->new[((i+1) << step) - p - 1].lock);	\
    rws_write_unlock(&(v)->cur[i].lock);				\
  }									\

#define SPINHASH_REHASH_DOWN(v,id,type,step)				\
  for (uint i=0; !(i >> (v)->cur_order); i++) {				\
    uint p = i >> step;							\
    rws_write_lock(&(v)->cur[i].lock);					\
    rws_write_lock(&(v)->new[p].lock);					\
    if (i == (p << step)) {						\
      ASSERT_DIE((v)->new[p].data == SPINHASH_REHASH_SENTINEL);		\
      (v)->new[p].data = NULL;						\
    } else								\
      ASSERT_DIE((v)->new[p].data != SPINHASH_REHASH_SENTINEL);		\
    for (type *n; n = (v)->cur[i].data; ) {				\
      (v)->cur[i].data = id##_NEXT(n);					\
      id##_NEXT(n) = (v)->new[p].data;					\
      (v)->new[p].data = n;						\
    }									\
    (v)->cur[i].data = SPINHASH_REHASH_SENTINEL;			\
    rws_write_unlock(&(v)->new[p].lock);				\
    rws_write_unlock(&(v)->cur[i].lock);				\
  }


#define SPINHASH_REHASH_SENTINEL  ((void *) 1)


/*
 * Memory hashing functions
 */

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
ptr_hash(void *ptr)
{
  uintptr_t p = (uintptr_t) ptr;
  return p ^ (p << 8) ^ (p >> 16);
}

#endif



#define HASH(type)		struct { type **data; uint count, order; }
#define HASH_TYPE(v)		typeof(** (v).data)
#define HASH_SIZE(v)		(1 << (v).order)
#define HASH_MASK(v)		((1 << (v).order)-1)


#define HASH_INIT(v,pool,init_order)					\
  ({									\
    (v).count = 0;							\
    (v).order = (init_order);						\
    (v).data = mb_allocz(pool, HASH_SIZE(v) * sizeof(* (v).data));	\
  })

#define HASH_FIND(v,id,key...)						\
  ({									\
    uint _h = id##_FN((key)) & HASH_MASK(v);				\
    HASH_TYPE(v) *_n = (v).data[_h];					\
    while (_n && !id##_EQ(id##_KEY(_n), (key)))				\
      _n = id##_NEXT(_n);						\
    _n;									\
  })

#define HASH_INSERT(v,id,node)						\
  ({									\
    uint _h = id##_FN(id##_KEY((node))) & HASH_MASK(v);			\
    HASH_TYPE(v) **_nn = (v).data + _h;					\
    id##_NEXT(node) = *_nn;						\
    *_nn = node;							\
    (v).count++;							\
  })

#define HASH_DO_REMOVE(v,id,_nn)					\
  ({									\
    HASH_TYPE(v) *_n = *_nn;						\
    if (_n)								\
    {									\
      *_nn = id##_NEXT(_n);						\
      (v).count--;							\
    }									\
    _n;									\
  })

#define HASH_DELETE(v,id,key...)					\
  ({									\
    uint _h = id##_FN((key)) & HASH_MASK(v);				\
    HASH_TYPE(v) **_nn = (v).data + _h;					\
									\
    while ((*_nn) && !id##_EQ(id##_KEY((*_nn)), (key)))			\
      _nn = &(id##_NEXT((*_nn)));					\
									\
    HASH_DO_REMOVE(v,id,_nn);						\
  })

#define HASH_REMOVE(v,id,node)						\
  ({									\
    uint _h = id##_FN(id##_KEY((node))) & HASH_MASK(v);			\
    HASH_TYPE(v) **_nn = (v).data + _h;					\
									\
    while ((*_nn) && (*_nn != (node)))					\
      _nn = &(id##_NEXT((*_nn)));					\
									\
    HASH_DO_REMOVE(v,id,_nn);						\
  })


#define HASH_REHASH(v,id,pool,step)					\
  ({									\
    HASH_TYPE(v) *_n, *_n2, **_od;					\
    uint _i, _s;							\
									\
    _s = HASH_SIZE(v);							\
    _od = (v).data;							\
    (v).count = 0;							\
    (v).order += (step);						\
    (v).data = mb_allocz(pool, HASH_SIZE(v) * sizeof(* (v).data));	\
									\
    for (_i = 0; _i < _s; _i++)						\
      for (_n = _od[_i]; _n && (_n2 = id##_NEXT(_n), 1); _n = _n2)	\
	HASH_INSERT(v, id, _n);						\
									\
    mb_free(_od);							\
  })

#define HASH_DEFINE_REHASH_FN(id, type)					\
  static void id##_REHASH_FN(void *v, pool *p, int step)		\
  { HASH_REHASH(* (HASH(type) *) v, id, p, step); }

#define HASH_TRY_REHASH_UP(v,id,pool)					\
  ({									\
    if (((v).order < id##_REHASH_MAX) && ((v).count > HASH_SIZE(v)))	\
      id##_REHASH_FN(&v, pool, 1);					\
  })

#define HASH_TRY_REHASH_DOWN(v,id,pool)					\
  ({									\
    if (((v).order > id##_REHASH_MIN) && ((v).count < HASH_SIZE(v)/2))	\
      id##_REHASH_FN(&v, pool, -1);					\
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



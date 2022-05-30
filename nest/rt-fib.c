/*
 *	BIRD -- Forwarding Information Base -- Data Structures
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Forwarding Information Base
 *
 * FIB is a data structure designed for storage of routes indexed by their
 * network prefixes. It supports insertion, deletion, searching by prefix,
 * `routing' (in CIDR sense, that is searching for a longest prefix matching
 * a given IP address) and (which makes the structure very tricky to implement)
 * asynchronous reading, that is enumerating the contents of a FIB while other
 * modules add, modify or remove entries.
 *
 * Internally, each FIB is represented as a collection of nodes of type &fib_node
 * indexed using a sophisticated hashing mechanism.
 * We use two-stage hashing where we calculate a 16-bit primary hash key independent
 * on hash table size and then we just divide the primary keys modulo table size
 * to get a real hash key used for determining the bucket containing the node.
 * The lists of nodes in each bucket are sorted according to the primary hash
 * key, hence if we keep the total number of buckets to be a power of two,
 * re-hashing of the structure keeps the relative order of the nodes.
 *
 * To get the asynchronous reading consistent over node deletions, we need to
 * keep a list of readers for each node. When a node gets deleted, its readers
 * are automatically moved to the next node in the table.
 *
 * Basic FIB operations are performed by functions defined by this module,
 * enumerating of FIB contents is accomplished by using the FIB_WALK() macro
 * or FIB_ITERATE_START() if you want to do it asynchronously.
 *
 * For simple iteration just place the body of the loop between FIB_WALK() and
 * FIB_WALK_END(). You can't modify the FIB during the iteration (you can modify
 * data in the node, but not add or remove nodes).
 *
 * If you need more freedom, you can use the FIB_ITERATE_*() group of macros.
 * First, you initialize an iterator with FIB_ITERATE_INIT(). Then you can put
 * the loop body in between FIB_ITERATE_START() and FIB_ITERATE_END(). In
 * addition, the iteration can be suspended by calling FIB_ITERATE_PUT().
 * This'll link the iterator inside the FIB. While suspended, you may modify the
 * FIB, exit the current function, etc. To resume the iteration, enter the loop
 * again. You can use FIB_ITERATE_UNLINK() to unlink the iterator (while
 * iteration is suspended) in cases like premature end of FIB iteration.
 *
 * Note that the iterator must not be destroyed when the iteration is suspended,
 * the FIB would then contain a pointer to invalid memory. Therefore, after each
 * FIB_ITERATE_INIT() or FIB_ITERATE_PUT() there must be either
 * FIB_ITERATE_START() or FIB_ITERATE_UNLINK() before the iterator is destroyed.
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/route.h"
#include "lib/string.h"

/*
 * The FIB rehash values are maintaining FIB count between N/5 and 2N. What
 * does it mean?
 *
 * +------------+--------+---------+-----------+----------+-----------+
 * | Table size | Memory | Min cnt | net + rte |  Max cnt | net + rte |
 * +------------+--------+---------+-----------+----------+-----------+
 * |         1k |     8k |    0    |      0    |       2k |    192  k |
 * |         2k |    16k |  409    |     38.3k |       4k |    384  k |
 * |         4k |    32k |  819    |     76.8k |       8k |    768  k |
 * |         8k |    64k |    1.6k |    153.6k |      16k |      1.5M |
 * |        16k |   128k |    3.2k |    307.1k |      32k |      3  M |
 * |        32k |   256k |    6.4k |    614.3k |      64k |      6  M |
 * |        64k |   512k |   12.8k |      1.2M |     128k |     12  M |
 * |       128k |  1024k |   25.6k |      2.4M |     256k |     24  M |
 * |       256k |     2M |   51.2k |      4.8M |     512k |     48  M |
 * |       512k |     4M |  102.4k |      9.6M |       1M |     96  M |
 * |         1M |     8M |  204.8k |     19.2M |       2M |    192  M |
 * |         2M |    16M |  409.6k |     38.4M |       4M |    384  M |
 * |         4M |    32M |  819.2k |     76.8M |       8M |    768  M |
 * |         8M |    64M |    1.6M |    153.6M | infinity |  infinity |
 * +------------+--------+---------+-----------+----------+-----------+
 *
 * Table size	shows how many slots are in FIB table.
 * Memory	shows how much memory is eaten by FIB table.
 * Min cnt	minimal number of nets in table of given size
 * Max cnt	maximal number of nets in table of given size
 * net + rte	memory eaten by 1 net and one route in it for min cnt and max cnt
 *
 * Example: If we have 750,000 network entries in a table:
 * * the table size may be 512k if we have never had more
 * * the table size may be 1M or 2M if we at least happened to have more
 * * 256k is too small, 8M is too big
 *
 * When growing, rehash is done on demand so we do it on every power of 2.
 * When shrinking, rehash is done on delete which is done (in global tables)
 * in a scheduled event. Rehashing down 2 steps.
 *
 */


#define HASH_DEF_ORDER 10
#define HASH_HI_MARK * 2
#define HASH_HI_STEP 1
#define HASH_HI_MAX 24
#define HASH_LO_MARK / 5
#define HASH_LO_STEP 2
#define HASH_LO_MIN 10


static void
fib_ht_alloc(struct fib *f)
{
  f->hash_size = 1 << f->hash_order;
  f->hash_shift = 32 - f->hash_order;
  if (f->hash_order > HASH_HI_MAX - HASH_HI_STEP)
    f->entries_max = ~0;
  else
    f->entries_max = f->hash_size HASH_HI_MARK;
  if (f->hash_order < HASH_LO_MIN + HASH_LO_STEP)
    f->entries_min = 0;
  else
    f->entries_min = f->hash_size HASH_LO_MARK;
  DBG("Allocating FIB hash of order %d: %d entries, %d low, %d high\n",
      f->hash_order, f->hash_size, f->entries_min, f->entries_max);
  f->hash_table = mb_alloc(f->fib_pool, f->hash_size * sizeof(struct fib_node *));
}

static inline void
fib_ht_free(struct fib_node **h)
{
  mb_free(h);
}


static inline u32 fib_hash(struct fib *f, const net_addr *a);

/**
 * fib_init - initialize a new FIB
 * @f: the FIB to be initialized (the structure itself being allocated by the caller)
 * @p: pool to allocate the nodes in
 * @node_size: node size to be used (each node consists of a standard header &fib_node
 * followed by user data)
 * @hash_order: initial hash order (a binary logarithm of hash table size), 0 to use default order
 * (recommended)
 * @init: pointer a function to be called to initialize a newly created node
 *
 * This function initializes a newly allocated FIB and prepares it for use.
 */
void
fib_init(struct fib *f, pool *p, uint addr_type, uint node_size, uint node_offset, uint hash_order, fib_init_fn init)
{
  uint addr_length = net_addr_length[addr_type];

  if (!hash_order)
    hash_order = HASH_DEF_ORDER;
  f->fib_pool = p;
  f->fib_slab = addr_length ? sl_new(p, node_size + addr_length) : NULL;
  f->addr_type = addr_type;
  f->node_size = node_size;
  f->node_offset = node_offset;
  f->hash_order = hash_order;
  fib_ht_alloc(f);
  bzero(f->hash_table, f->hash_size * sizeof(struct fib_node *));
  f->entries = 0;
  f->entries_min = 0;
  f->init = init;
}

static void
fib_rehash(struct fib *f, int step)
{
  unsigned old, new, oldn, newn, ni, nh;
  struct fib_node **n, *e, *x, **t, **m, **h;

  old = f->hash_order;
  oldn = f->hash_size;
  new = old + step;
  m = h = f->hash_table;
  DBG("Re-hashing FIB from order %d to %d\n", old, new);
  f->hash_order = new;
  fib_ht_alloc(f);
  t = n = f->hash_table;
  newn = f->hash_size;
  ni = 0;

  while (oldn--)
    {
      x = *h++;
      while (e = x)
	{
	  x = e->next;
	  nh = fib_hash(f, e->addr);
	  while (nh > ni)
	    {
	      *t = NULL;
	      ni++;
	      t = ++n;
	    }
	  *t = e;
	  t = &e->next;
	}
    }
  while (ni < newn)
    {
      *t = NULL;
      ni++;
      t = ++n;
    }
  fib_ht_free(m);
}

#define CAST(t) (const net_addr_##t *)
#define CAST2(t) (net_addr_##t *)

#define FIB_HASH(f,a,t) (net_hash_##t(CAST(t) a) >> f->hash_shift)

#define FIB_FIND(f,a,t)							\
  ({									\
    struct fib_node *e = f->hash_table[FIB_HASH(f, a, t)];		\
    while (e && !net_equal_##t(CAST(t) e->addr, CAST(t) a))		\
      e = e->next;							\
    fib_node_to_user(f, e);						\
  })

#define FIB_INSERT(f,a,e,t)						\
  ({									\
  u32 h = net_hash_##t(CAST(t) a);					\
  struct fib_node **ee = f->hash_table + (h >> f->hash_shift);		\
  struct fib_node *g;							\
									\
  while ((g = *ee) && (net_hash_##t(CAST(t) g->addr) < h))		\
    ee = &g->next;							\
									\
  net_copy_##t(CAST2(t) e->addr, CAST(t) a);				\
  e->next = *ee;							\
  *ee = e;								\
  })


static inline u32
fib_hash(struct fib *f, const net_addr *a)
{
  /* Same as FIB_HASH() */
  return net_hash(a) >> f->hash_shift;
}

void *
fib_get_chain(struct fib *f, const net_addr *a)
{
  ASSERT(f->addr_type == a->type);

  struct fib_node *e = f->hash_table[fib_hash(f, a)];
  return e;
}

/**
 * fib_find - search for FIB node by prefix
 * @f: FIB to search in
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix, return
 * a pointer to it or %NULL if no such node exists.
 */
void *
fib_find(struct fib *f, const net_addr *a)
{
  ASSERT(f->addr_type == a->type);

  switch (f->addr_type)
  {
  case NET_IP4: return FIB_FIND(f, a, ip4);
  case NET_IP6: return FIB_FIND(f, a, ip6);
  case NET_VPN4: return FIB_FIND(f, a, vpn4);
  case NET_VPN6: return FIB_FIND(f, a, vpn6);
  case NET_ROA4: return FIB_FIND(f, a, roa4);
  case NET_ROA6: return FIB_FIND(f, a, roa6);
  case NET_FLOW4: return FIB_FIND(f, a, flow4);
  case NET_FLOW6: return FIB_FIND(f, a, flow6);
  case NET_IP6_SADR: return FIB_FIND(f, a, ip6_sadr);
  case NET_MPLS: return FIB_FIND(f, a, mpls);
  default: bug("invalid type");
  }
}

static void
fib_insert(struct fib *f, const net_addr *a, struct fib_node *e)
{
  ASSERT(f->addr_type == a->type);

  switch (f->addr_type)
  {
  case NET_IP4: FIB_INSERT(f, a, e, ip4); return;
  case NET_IP6: FIB_INSERT(f, a, e, ip6); return;
  case NET_VPN4: FIB_INSERT(f, a, e, vpn4); return;
  case NET_VPN6: FIB_INSERT(f, a, e, vpn6); return;
  case NET_ROA4: FIB_INSERT(f, a, e, roa4); return;
  case NET_ROA6: FIB_INSERT(f, a, e, roa6); return;
  case NET_FLOW4: FIB_INSERT(f, a, e, flow4); return;
  case NET_FLOW6: FIB_INSERT(f, a, e, flow6); return;
  case NET_IP6_SADR: FIB_INSERT(f, a, e, ip6_sadr); return;
  case NET_MPLS: FIB_INSERT(f, a, e, mpls); return;
  default: bug("invalid type");
  }
}


/**
 * fib_get - find or create a FIB node
 * @f: FIB to work with
 * @n: network address
 *
 * Search for a FIB node corresponding to the given prefix and
 * return a pointer to it. If no such node exists, create it.
 */
void *
fib_get(struct fib *f, const net_addr *a)
{
  void *b = fib_find(f, a);
  if (b)
    return b;

  if (f->fib_slab)
    b = sl_alloc(f->fib_slab);
  else
    b = mb_alloc(f->fib_pool, f->node_size + a->length);

  struct fib_node *e = fib_user_to_node(f, b);
  e->readers = NULL;
  fib_insert(f, a, e);

  memset(b, 0, f->node_offset);
  if (f->init)
    f->init(f, b);

  if (f->entries++ > f->entries_max)
    fib_rehash(f, HASH_HI_STEP);

  return b;
}

static inline void *
fib_route_ip4(struct fib *f, net_addr_ip4 *n)
{
  void *r;

  while (!(r = fib_find(f, (net_addr *) n)) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip4_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

static inline void *
fib_route_ip6(struct fib *f, net_addr_ip6 *n)
{
  void *r;

  while (!(r = fib_find(f, (net_addr *) n)) && (n->pxlen > 0))
  {
    n->pxlen--;
    ip6_clrbit(&n->prefix, n->pxlen);
  }

  return r;
}

/**
 * fib_route - CIDR routing lookup
 * @f: FIB to search in
 * @n: network address
 *
 * Search for a FIB node with longest prefix matching the given
 * network, that is a node which a CIDR router would use for routing
 * that network.
 */
void *
fib_route(struct fib *f, const net_addr *n)
{
  ASSERT(f->addr_type == n->type);

  net_addr *n0 = alloca(n->length);
  net_copy(n0, n);

  switch (n->type)
  {
  case NET_IP4:
  case NET_VPN4:
  case NET_ROA4:
  case NET_FLOW4:
    return fib_route_ip4(f, (net_addr_ip4 *) n0);

  case NET_IP6:
  case NET_VPN6:
  case NET_ROA6:
  case NET_FLOW6:
    return fib_route_ip6(f, (net_addr_ip6 *) n0);

  default:
    return NULL;
  }
}


static inline void
fib_merge_readers(struct fib_iterator *i, struct fib_node *to)
{
  if (to)
    {
      struct fib_iterator *j = to->readers;
      if (!j)
	{
	  /* Fast path */
	  to->readers = i;
	  i->prev = (struct fib_iterator *) to;
	}
      else
	{
	  /* Really merging */
	  while (j->next)
	    j = j->next;
	  j->next = i;
	  i->prev = j;
	}
      while (i && i->node)
	{
	  i->node = NULL;
	  i = i->next;
	}
    }
  else					/* No more nodes */
    while (i)
      {
	i->prev = NULL;
	i = i->next;
      }
}

/**
 * fib_delete - delete a FIB node
 * @f: FIB to delete from
 * @E: entry to delete
 *
 * This function removes the given entry from the FIB,
 * taking care of all the asynchronous readers by shifting
 * them to the next node in the canonical reading order.
 */
void
fib_delete(struct fib *f, void *E)
{
  struct fib_node *e = fib_user_to_node(f, E);
  uint h = fib_hash(f, e->addr);
  struct fib_node **ee = f->hash_table + h;
  struct fib_iterator *it;

  while (*ee)
    {
      if (*ee == e)
	{
	  *ee = e->next;
	  if (it = e->readers)
	    {
	      struct fib_node *l = e->next;
	      while (!l)
		{
		  h++;
		  if (h >= f->hash_size)
		    break;
		  else
		    l = f->hash_table[h];
		}
	      fib_merge_readers(it, l);
	    }

	  if (f->fib_slab)
	    sl_free(E);
	  else
	    mb_free(E);

	  if (f->entries-- < f->entries_min)
	    fib_rehash(f, -HASH_LO_STEP);
	  return;
	}
      ee = &((*ee)->next);
    }
  bug("fib_delete() called for invalid node");
}

/**
 * fib_free - delete a FIB
 * @f: FIB to be deleted
 *
 * This function deletes a FIB -- it frees all memory associated
 * with it and all its entries.
 */
void
fib_free(struct fib *f)
{
  fib_ht_free(f->hash_table);
  rfree(f->fib_slab);
}

void
fit_init(struct fib_iterator *i, struct fib *f)
{
  unsigned h;
  struct fib_node *n;

  i->efef = 0xff;
  for(h=0; h<f->hash_size; h++)
    if (n = f->hash_table[h])
      {
	i->prev = (struct fib_iterator *) n;
	if (i->next = n->readers)
	  i->next->prev = i;
	n->readers = i;
	i->node = n;
	return;
      }
  /* The fib is empty, nothing to do */
  i->prev = i->next = NULL;
  i->node = NULL;
}

struct fib_node *
fit_get(struct fib *f, struct fib_iterator *i)
{
  struct fib_node *n;
  struct fib_iterator *j, *k;

  if (!i->prev)
    {
      /* We are at the end */
      i->hash = ~0 - 1;
      return NULL;
    }
  if (!(n = i->node))
    {
      /* No node info available, we are a victim of merging. Try harder. */
      j = i;
      while (j->efef == 0xff)
	j = j->prev;
      n = (struct fib_node *) j;
    }
  j = i->prev;
  if (k = i->next)
    k->prev = j;
  j->next = k;
  i->hash = fib_hash(f, n->addr);
  return n;
}

void
fit_put(struct fib_iterator *i, struct fib_node *n)
{
  struct fib_iterator *j;

  i->node = n;
  if (j = n->readers)
    j->prev = i;
  i->next = j;
  n->readers = i;
  i->prev = (struct fib_iterator *) n;
}

void
fit_put_next(struct fib *f, struct fib_iterator *i, struct fib_node *n, uint hpos)
{
  if (n = n->next)
    goto found;

  while (++hpos < f->hash_size)
    if (n = f->hash_table[hpos])
      goto found;

  /* We are at the end */
  i->prev = i->next = NULL;
  i->node = NULL;
  return;

found:
  fit_put(i, n);
}

void
fit_put_end(struct fib_iterator *i)
{
  i->prev = i->next = NULL;
  i->node = NULL;
  i->hash = ~0 - 1;
}

void
fit_copy(struct fib *f, struct fib_iterator *dst, struct fib_iterator *src)
{
  struct fib_iterator *nxt = src->next;

  fit_get(f, dst);

  if (!src->prev)
  {
    /* We are at the end */
    fit_put_end(dst);
    return;
  }

  src->next = dst;
  dst->prev = src;

  dst->next = nxt;
  if (nxt)
    nxt->prev = dst;

  dst->node = src->node;
  dst->hash = src->hash;
}


#ifdef DEBUGGING

/**
 * fib_check - audit a FIB
 * @f: FIB to be checked
 *
 * This debugging function audits a FIB by checking its internal consistency.
 * Use when you suspect somebody of corrupting innocent data structures.
 */
void
fib_check(struct fib *f)
{
  uint i, ec, nulls;

  ec = 0;
  for(i=0; i<f->hash_size; i++)
    {
      struct fib_node *n;
      for(n=f->hash_table[i]; n; n=n->next)
	{
	  struct fib_iterator *j, *j0;
	  uint h0 = fib_hash(f, n->addr);
	  if (h0 != i)
	    bug("fib_check: mishashed %x->%x (order %d)", h0, i, f->hash_order);
	  j0 = (struct fib_iterator *) n;
	  nulls = 0;
	  for(j=n->readers; j; j=j->next)
	    {
	      if (j->prev != j0)
		bug("fib_check: iterator->prev mismatch");
	      j0 = j;
	      if (!j->node)
		nulls++;
	      else if (nulls)
		bug("fib_check: iterator nullified");
	      else if (j->node != n)
		bug("fib_check: iterator->node mismatch");
	    }
	  ec++;
	}
    }
  if (ec != f->entries)
    bug("fib_check: invalid entry count (%d != %d)", ec, f->entries);
  return;
}

/*
int
fib_histogram(struct fib *f)
{
  log(L_WARN "Histogram dump start %d %d", f->hash_size, f->entries);

  int i, j;
  struct fib_node *e;

  for (i = 0; i < f->hash_size; i++)
    {
      j = 0;
      for (e = f->hash_table[i]; e != NULL; e = e->next)
	j++;
      if (j > 0)
	log(L_WARN "Histogram line %d: %d", i, j);
    }

  log(L_WARN "Histogram dump end");
}
*/

#endif

#ifdef TEST

#include "lib/resource.h"

struct fib f;

void dump(char *m)
{
  uint i;

  debug("%s ... order=%d, size=%d, entries=%d\n", m, f.hash_order, f.hash_size, f.hash_size);
  for(i=0; i<f.hash_size; i++)
    {
      struct fib_node *n;
      struct fib_iterator *j;
      for(n=f.hash_table[i]; n; n=n->next)
	{
	  debug("%04x %08x %p %N", i, ipa_hash(n->prefix), n, n->addr);
	  for(j=n->readers; j; j=j->next)
	    debug(" %p[%p]", j, j->node);
	  debug("\n");
	}
    }
  fib_check(&f);
  debug("-----\n");
}

void init(struct fib_node *n)
{
}

int main(void)
{
  struct fib_node *n;
  struct fib_iterator i, j;
  ip_addr a;
  int c;

  log_init_debug(NULL);
  resource_init();
  fib_init(&f, &root_pool, sizeof(struct fib_node), 4, init);
  dump("init");

  a = ipa_from_u32(0x01020304); n = fib_get(&f, &a, 32);
  a = ipa_from_u32(0x02030405); n = fib_get(&f, &a, 32);
  a = ipa_from_u32(0x03040506); n = fib_get(&f, &a, 32);
  a = ipa_from_u32(0x00000000); n = fib_get(&f, &a, 32);
  a = ipa_from_u32(0x00000c01); n = fib_get(&f, &a, 32);
  a = ipa_from_u32(0xffffffff); n = fib_get(&f, &a, 32);
  dump("fill");

  fit_init(&i, &f);
  dump("iter init");

  fib_rehash(&f, 1);
  dump("rehash up");

  fib_rehash(&f, -1);
  dump("rehash down");

next:
  c = 0;
  FIB_ITERATE_START(&f, &i, z)
    {
      if (c)
	{
	  FIB_ITERATE_PUT(&i, z);
	  dump("iter");
	  goto next;
	}
      c = 1;
      debug("got %p\n", z);
    }
  FIB_ITERATE_END(z);
  dump("iter end");

  fit_init(&i, &f);
  fit_init(&j, &f);
  dump("iter init 2");

  n = fit_get(&f, &i);
  dump("iter step 2");

  fit_put(&i, n->next);
  dump("iter step 3");

  a = ipa_from_u32(0xffffffff); n = fib_get(&f, &a, 32);
  fib_delete(&f, n);
  dump("iter step 3");

  return 0;
}

#endif

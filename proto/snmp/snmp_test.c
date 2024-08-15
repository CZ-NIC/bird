/*
 *	BIRD -- Simple Network Management Protocol (SNMP) Unit tests
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdarg.h>

#include "test/birdtest.h"
#include "test/bt-utils.h"

#include "bgp4_mib.h"
#include "subagent.h"
#include "snmp.h"
#include "snmp_utils.h"
#include "mib_tree.h"

static int t_oid_empty(void);
static int t_oid_compare(void);
static int t_varbind_name_to_tx(void);
static int t_walk_oid_desc(void);
static int t_walk_oid_compare(void);
static int t_tree_find(void);
static int t_tree_traversal(void);
static int t_tree_leafs(void);
static int t_tree_add(void);
static int t_tree_delete(void);

#define SNMP_BUFFER_SIZE 1024
#define TESTS_NUM   32
#define SMALL_TESTS_NUM 10
static int tree_sizes[] = { 0, 1, 10, 100, 1000 };

/* smaller than theoretical maximum (2^32) to fit in memory */
#define OID_MAX_ID 16

#define SNMP_EXPECTED(actual, expected) \
  bt_debug("%s  expected: %3u   actual: %3u\n", \
    #expected, expected, actual);

static inline struct oid *
oid_allocate(uint size)
{
  return tmp_alloc(sizeof(struct oid) + size * sizeof(u32));
}

static inline void
oid_init2(struct oid *oid, u8 n_subid, u8 prefix, u8 include, va_list ids)
{
  oid->n_subid = n_subid;
  oid->prefix = prefix;
  oid->include = include;
  oid->reserved = 0;

  for (u8 i = 0; i < n_subid; i++)
  {
    u32 id = va_arg(ids, u32);
    oid->ids[i] = id;
  }
}

static inline void
oid_init(struct oid *oid, u8 n_subid, u8 prefix, u8 include, ...)
{
  va_list ids;
  va_start(ids, include);
  oid_init2(oid, n_subid, prefix, include, ids);
  va_end(ids);
}

static inline struct oid *
oid_create(u8 n_subid, u8 prefix, u8 include, ...)
{
  struct oid *result = tmp_alloc(snmp_oid_size_from_len(n_subid));
  va_list ids;

  va_start(ids, include);
  oid_init2(result, n_subid, prefix, include, ids);
  va_end(ids);

  return result;
}

static u32
xrandom(u32 max)
{
  return (bt_random() % max);
}

static u32
oid_random_id(void)
{
  return (bt_random() % (OID_MAX_ID));
}

static struct oid *
random_prefixed_oid(void)
{
  u32 len = xrandom(OID_MAX_LEN + 1 - (ARRAY_SIZE(snmp_internet) + 1));

  u8 prefix = (u8) xrandom(UINT8_MAX + 1);

  if (!prefix)
    return oid_create(0, 0, 0, 0);

  struct oid *random = tmp_alloc(snmp_oid_size_from_len(len));
  /* (xrandom(2) * bt_random()) has 0.5 probability to have value 0 and
   * 0.5 to have random u32 (including zero) */
  oid_init(random, 0, prefix, xrandom(2) * bt_random());
  random->n_subid = len;

  for (u32 id = 0; id < len; id++)
    random->ids[id] = oid_random_id();

  return random;
}

static struct oid *
random_no_prefix_oid(void)
{
  /* probability that the random OID is prefixable is practically zero */
  u32 len = xrandom(OID_MAX_LEN + 1);

  struct oid *random = tmp_alloc(snmp_oid_size_from_len(len));
  /* (xrandom(2) * bt_random()) has 0.5 probability to have value 0 and
   * 0.5 to have random u32 (including zero) */
  oid_init(random, 0, 0, xrandom(2) * bt_random());
  random->n_subid = len;

  for (u32 id = 0; id < len; id++)
    random->ids[id] = oid_random_id();

  return random;
}

static struct oid *
random_prefixable_oid(void)
{
  /* generate the len without the snmp_internet prefix included and prefix ID */
  u32 len = xrandom(OID_MAX_LEN + 1 - (ARRAY_SIZE(snmp_internet) + 1));

  struct oid *random = tmp_alloc(
      snmp_oid_size_from_len(len + ARRAY_SIZE(snmp_internet) + 1));
  /* (xrandom(2) * bt_random()) has 0.5 probability to have value 0 and
   * 0.5 to have random u32 (including zero) */
  oid_init(random, 0, 0, xrandom(2) * bt_random());
  random->n_subid = len + ARRAY_SIZE(snmp_internet) + 1;

  for (u32 inet_id = 0; inet_id < ARRAY_SIZE(snmp_internet); inet_id++)
    random->ids[inet_id] = snmp_internet[inet_id];

  random->ids[ARRAY_SIZE(snmp_internet)] = xrandom(UINT8_MAX + 1);

  for (u32 id = 0; id < len; id++)
    random->ids[id + ARRAY_SIZE(snmp_internet) + 1] = oid_random_id();

  return random;
}

static struct oid *
random_oid(void)
{
  u32 option = xrandom(3);

  if (option == 0)
    return random_prefixed_oid();
  else if (option == 1)
    return random_no_prefix_oid();
  else
    return random_prefixable_oid();
}

static int
t_oid_empty(void)
{
  struct lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  bt_assert(snmp_is_oid_empty(NULL) == 0);

  {
    struct oid *blank = oid_create(0, 0, 0 /* no ids */);
    bt_assert(snmp_is_oid_empty(blank) == 1);
    lp_restore(tmp_linpool, &tmps);
  }


  {
    struct oid *prefixed = oid_create(3, 100, 1,
      /* ids */ ~((u32) 0), 0, 256);
    bt_assert(snmp_is_oid_empty(prefixed) == 0);
    lp_restore(tmp_linpool, &tmps);
  }


  {
    struct oid *to_prefix = oid_create(8, 0, 1,
      /* ids */ 1, 3, 6, 1, 100, ~((u32) 0), 0, 256);
    bt_assert(snmp_is_oid_empty(to_prefix) == 0);
    lp_restore(tmp_linpool, &tmps);
  }


  {
    struct oid *unprefixable = oid_create(2, 0, 0,
      /* ids */ 65535, 4);
    bt_assert(snmp_is_oid_empty(unprefixable) == 0);
    lp_restore(tmp_linpool, &tmps);
  }

  {
    struct oid *unprefixable2 = oid_create(8, 0, 1,
      /* ids */ 1, 3, 6, 2, 1, 2, 15, 6);
    bt_assert(snmp_is_oid_empty(unprefixable2) == 0);
    lp_restore(tmp_linpool, &tmps);
  }

  tmp_flush();
  return 1;
}

static int
t_oid_compare(void)
{
  struct lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  /* same length, no prefix */
  struct oid *l1 = oid_create(5, 0, 1,
      /* ids */ 1, 2, 3, 4, 5);

  struct oid *r1 = oid_create(5, 0, 0,
      /* ids */ 1, 2, 3, 4, 6);

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 1;
  r1->prefix = 1;

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* different prefix -- has higher priority */
  l1->prefix = 8;
  r1->prefix = 4;

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  lp_restore(tmp_linpool, &tmps);


  /* different length, no prefix */
  l1 = oid_create(4, 0, 0,
      /* ids */ 1, 2, 3, 4);

  r1 = oid_create(5, 0, 1,
      /* ids */ 1, 2, 3, 4, 1);

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 3;
  r1->prefix = 3;

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* different prefix -- has higher priority */
  l1->prefix = 17;
  r1->prefix = 14;

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  lp_restore(tmp_linpool, &tmps);


  /* inverse order different length, no prefix */
  l1 = oid_create(4, 0, 0,
      /* ids */ 1, 2, 3, 5);

  r1 = oid_create(5, 0, 0,
      /* ids */ 1, 2, 3, 4, 1);

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* same results for prefixed oids */
  l1->prefix = 254;
  r1->prefix = 254;

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  /* different prefix -- has higher priority */
  l1->prefix = 127;
  r1->prefix = 35;

  bt_assert(snmp_oid_compare(l1, r1) ==  1);
  bt_assert(snmp_oid_compare(r1, l1) == -1);

  lp_restore(tmp_linpool, &tmps);


/* ==== MIXED PREFIXED / NON PREFIXED OID compare ==== */
  /* same length, mixed */
  l1 = oid_create(6, 0, 1,
      /* ids */ 1, 2, 17, 3, 21, 4);

  r1 = oid_create(1, 5, 1,
      /* ids */ 3);

  bt_assert(snmp_oid_compare(l1, r1) == -1);
  bt_assert(snmp_oid_compare(r1, l1) ==  1);

  bt_assert(snmp_oid_compare(l1, l1) ==  0);
  bt_assert(snmp_oid_compare(r1, r1) ==  0);

  lp_restore(tmp_linpool, &tmps);

  struct oid *super = oid_create(4, 0, 0, /* ids */ 1, 3, 6, 1);
  struct oid *weird = oid_create(4, 70, 0, /* ids */ 9, 10, 10, 12);

  bt_assert(snmp_oid_compare(super, weird) != 0);

  struct oid *pref = oid_create(0, 7, 0); // no ids, only prefix
  struct oid *no_pref = oid_create(5, 0, 0, /* ids */ 1, 3, 6, 1, 7);

  bt_assert(snmp_oid_compare(pref, no_pref) == 0);

  struct oid *inet = oid_create(4, 0, 0, /* ids */ 1, 3, 6, 1);

  bt_assert(snmp_oid_compare(inet, pref) < 0);
  bt_assert(snmp_oid_compare(pref, inet) > 0);
  bt_assert(snmp_oid_compare(inet, no_pref) < 0);
  bt_assert(snmp_oid_compare(no_pref, inet) > 0);

  struct oid *pref2 = oid_create(0, 16, 0); // no ids, only prefix
  struct oid *no_pref2 = oid_create(5, 0, 0, /* ids */ 1, 3, 6, 1, 16);

  bt_assert(snmp_oid_compare(pref2, no_pref2) == 0);
  bt_assert(snmp_oid_compare(no_pref2, pref2) == 0);

  bt_assert(snmp_oid_compare(pref, pref2) < 0);
  bt_assert(snmp_oid_compare(pref2, pref) > 0);
  bt_assert(snmp_oid_compare(pref, no_pref2) < 0);
  bt_assert(snmp_oid_compare(no_pref2, pref) > 0);
  bt_assert(snmp_oid_compare(no_pref, pref2) < 0);
  bt_assert(snmp_oid_compare(pref2, no_pref) > 0);
  bt_assert(snmp_oid_compare(no_pref, no_pref2) < 0);
  bt_assert(snmp_oid_compare(no_pref2, no_pref) > 0);


  tmp_flush();
  return 1;
}

static inline void
fix_byteorder(u32 *ids, u32 len)
{
  for (u32 i = 0; i < len; i++)
    STORE_U32(ids[i], ids[i]);
}

int
u32cmp_bo(const u32 *cpu_native, const u32 *net_bo, u32 len)
{
  for (u32 i = 0; i < len; i++)
  {
    if (cpu_native[i] != LOAD_U32(net_bo[i]))
      return LOAD_U32(net_bo[i]) - cpu_native[i];
  }

  return 0;
}

#define CREATE_RANDOM(gen)	\
  ({  \
    struct oid *_o = gen(); \
    fix_byteorder(_o->ids, _o->n_subid);  \
    _o; \
  })

static int
t_varbind_name_to_tx(void)
{
  /* Test snmp_vb_name_to_tx() */

  lp_state tmps = { };
  struct snmp_proto *snmp_proto = tmp_alloc(sizeof(struct snmp_proto));
  memset(snmp_proto, 0, sizeof(struct snmp_proto));
  sock *s = sk_new(&root_pool);
  snmp_proto->sock = s;
  /* dirty hack sk_alloc_bufs() */
  s->tbsize = SNMP_BUFFER_SIZE;
  s->tbuf = s->tbuf_alloc = xmalloc(s->tbsize);
  void *buffer = s->tbuf;

  struct snmp_pdu copy = {
    .p = snmp_proto,
    .sr_vb_start = (void *) buffer,
    .buffer = buffer,
  };
  struct snmp_pdu c = copy;
  struct oid *new;
  struct agentx_varbind *vb;

  lp_save(tmp_linpool, &tmps);

  /* testing prefixable OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *oid = CREATE_RANDOM(random_prefixable_oid);

    /* both LOAD_U8() and STORE_U8() are pointless as it byteorder does not
     * influence single byte values.
     */

    u8 subids = oid->n_subid;
    u8 include = oid->include;
    u32 pid = LOAD_U32(oid->ids[ARRAY_SIZE(snmp_internet)]);

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    vb = snmp_vb_name_to_tx(&c, oid);
    new = &vb->name;

    bt_assert(new->n_subid == subids - (ARRAY_SIZE(snmp_internet) + 1));
    bt_assert(new->prefix == pid);
    bt_assert(!!new->include == !!include);
    bt_assert(new->reserved == 0);

    for (u32 i = 0; i < new->n_subid; i++)
    {
      bt_assert(new->ids[i] == LOAD_U32(oid->ids[i + ARRAY_SIZE(snmp_internet) + 1]));
    }

    for (u32 j = 0; j < ARRAY_SIZE(snmp_internet); j++)
      bt_assert(LOAD_U32(oid->ids[j]) == snmp_internet[j]);

    lp_restore(tmp_linpool, &tmps);
  }

  /* testing already prefixed OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *prefixed = CREATE_RANDOM(random_prefixed_oid);

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(prefixed) + 8);

    vb = snmp_vb_name_to_tx(&c, prefixed);
    new = &vb->name;

    bt_assert(new->n_subid == prefixed->n_subid);
    bt_assert(new->prefix == prefixed->prefix);
    bt_assert(!!new->include == !!prefixed->include);
    bt_assert(new->reserved == 0);
    bt_assert(!u32cmp_bo(&new->ids[0], &prefixed->ids[0], new->n_subid));

    lp_restore(tmp_linpool, &tmps);
  }

  lp_restore(tmp_linpool, &tmps);

  /* testing non-prefixable OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *oid = CREATE_RANDOM(random_no_prefix_oid);

    /* test that the OID is _really_ not prefixable */
    if (oid->n_subid > ARRAY_SIZE(snmp_internet) &&
	LOAD_U32(oid->ids[ARRAY_SIZE(snmp_internet) + 1]) <= UINT8_MAX)
    {
      for (u32 i = 0; i < ARRAY_SIZE(snmp_internet); i++)
	if (LOAD_U32(oid->ids[i]) != snmp_internet[i]) goto continue_testing;

      break; /* outer for loop */
    }

continue_testing:

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    vb = snmp_vb_name_to_tx(&c, oid);
    new = &vb->name;

    bt_assert(new->n_subid == oid->n_subid);
    bt_assert(new->prefix == oid->prefix);
    bt_assert(!!new->include == !!oid->include);
    bt_assert(new->reserved == 0);
    bt_assert(!u32cmp_bo(&new->ids[0], &oid->ids[0], new->n_subid));

    lp_restore(tmp_linpool, &tmps);
  }

  for (int test = 0; test < SMALL_TESTS_NUM; test++)
  {
    const struct oid *oid;
    {
      struct oid *work = random_prefixable_oid();
      fix_byteorder(work->ids, work->n_subid);

      /* include also the prefix ID (at index 4) */
      u32 index = xrandom(ARRAY_SIZE(snmp_internet) + 1);
      /* change randomly picked id at index from 0..5 (included) */
      u32 random = bt_random();
      if (index == ARRAY_SIZE(snmp_internet) && random > 255)
	work->ids[index] = VALUE_U32(random);
      else if (index != ARRAY_SIZE(snmp_internet) && work->ids[index] != random)
	work->ids[index] = VALUE_U32(random);
      else
	continue;
      oid = work;
    }

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    vb = snmp_vb_name_to_tx(&c, oid);
    new = &vb->name;

    bt_assert(new->n_subid == oid->n_subid);
    bt_assert(new->prefix == oid->prefix);
    bt_assert(!!new->include == !!oid->include);
    bt_assert(new->reserved == 0);
    bt_assert(!u32cmp_bo(&new->ids[0], &oid->ids[0], new->n_subid));

    lp_restore(tmp_linpool, &tmps);
  }

  rfree(snmp_proto->sock);
  tmp_flush();
  return 1;
}

static inline void
walk_to_oid_one(pool *pool, const struct oid *oid)
{
  struct mib_tree storage, *tree = &storage;
  mib_tree_init(pool, tree);

  struct mib_walk_state walk;
  mib_tree_walk_init(&walk, tree);

  const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
  mib_tree_remove(tree, inet_pref);

  (void) mib_tree_add(pool, tree, oid, xrandom(2));
  mib_tree_find(tree, &walk, oid);

  char buf[1024];
  struct oid *from_walk = (struct oid *) buf;

  int r = mib_tree_walk_to_oid(&walk, from_walk,
    (1024 - sizeof(struct oid)) / sizeof(u32));

  /* the memory limit should not be breached */
  bt_assert(r == 0);

  bt_assert(snmp_oid_compare(from_walk, oid) == 0);

  /* cleanup */
  mib_tree_remove(tree, inet_pref);
}

/* test MIB tree walk to OID */
static int
t_walk_to_oid(void)
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);


  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {

    walk_to_oid_one(pool, random_prefixed_oid());
    walk_to_oid_one(pool, random_no_prefix_oid());
    walk_to_oid_one(pool, random_prefixable_oid());
    /* only a one of above */
    //walk_to_oid_one(random_oid);

    lp_restore(tmp_linpool, &tmps);
  }

  tmp_flush();

  return 1;
}


static void
test_both(void *buffer, uint size, const struct oid *left, const struct oid
*right, const struct oid *expected)
{
  memset(buffer, 0, size);
  snmp_oid_common_ancestor(left, right, buffer);
  bt_assert(snmp_oid_compare(buffer, expected) == 0);

  memset(buffer, 0, size);
  snmp_oid_common_ancestor(right, left, buffer);
  bt_assert(snmp_oid_compare(buffer, expected) == 0);
}

#define TEST_BOTH(l, r, e) test_both(buffer, 1024, l, r, e)
static int
t_oid_ancestor(void)
{
  const struct oid *null = oid_create(0, 0, 0);
  const struct oid *shorter = oid_create(3, 15, 0, /* ids */ 192, 1, 7);
  const struct oid *prefixed = oid_create(4, 15, 0, /* ids */ 192, 1, 7, 82);
  const struct oid *no_prefix = oid_create(9, 0, 0, /* ids */ 1, 3, 6, 1, 15, 192, 1, 7, 82);
  const struct oid *outside = oid_create(7, 0, 0, /* ids */ 4, 3, 2, 1, 8, 0, 2);
  const struct oid *prefix_only =  oid_create(0, 15, 0);
  const struct oid *prefix_only2 = oid_create(0, 9, 0);
  const struct oid *partial = oid_create(3, 0, 0, /* ids */ 1, 3, 6);
  const struct oid *no_inet = oid_create(5, 0, 0, /* ids */ 1, 3, 6, 2, 5);

  const struct oid *inet = oid_create(4, 0, 0, /* ids */ 1, 3, 6, 1);


  const struct oid *oids[] = {
    null, shorter, prefixed, no_prefix, outside, prefix_only, partial, no_inet, inet
  };

  char buffer[1024];

  /* skip null oid */
  for (size_t o = 1; o < ARRAY_SIZE(oids); o++)
    TEST_BOTH(null, oids[o], null);

  for (size_t o = 0; o < ARRAY_SIZE(oids); o++)
    TEST_BOTH(oids[o], oids[o], oids[o]);

  TEST_BOTH(partial, no_prefix, partial);
  TEST_BOTH(partial, prefixed, partial);
  TEST_BOTH(partial, prefix_only, partial);
  TEST_BOTH(partial, prefix_only2, partial);

  TEST_BOTH(prefix_only2, prefixed, inet);
  TEST_BOTH(prefix_only2, no_prefix, inet);

  TEST_BOTH(prefix_only2, inet, inet);

  TEST_BOTH(prefix_only, prefix_only2, inet);

  TEST_BOTH(prefix_only, prefixed, prefix_only);
  TEST_BOTH(prefix_only, no_prefix, prefix_only);

  TEST_BOTH(prefix_only, inet, inet);

  /* skip null oid */
  for (size_t o = 1; o < ARRAY_SIZE(oids); o++)
  {
    if (oids[o] == outside) continue;

    TEST_BOTH(outside, oids[o], null);
  }

  TEST_BOTH(no_inet, partial, partial);
  TEST_BOTH(no_inet, inet, partial);
  TEST_BOTH(no_inet, prefix_only, partial);
  TEST_BOTH(no_inet, prefix_only2, partial);
  TEST_BOTH(no_inet, prefixed, partial);
  TEST_BOTH(no_inet, no_prefix, partial);

  TEST_BOTH(shorter, prefixed, shorter);
  TEST_BOTH(shorter, no_prefix, shorter);

  return 1;
}

/* really: static int test_snmp_oid_compare(const struct oid **left, const struct oid **right); */
static int
test_snmp_oid_compare(const void *left, const void *right)
{
  return snmp_oid_compare(
    *((const struct oid **) left),
    *((const struct oid **) right)
  );
}

static void
generate_raw_oids(struct oid *oids[], int size, struct oid *(*generator)(void))
{
  for (int i = 0; i < size; i++)
  {
    /* binary version of ~5% */
    if (i > 0 && xrandom(256) <= 13)
    {
      /* at this chance, we create a copy instead of generating new oid */
      oids[i] = tmp_alloc(snmp_oid_size(oids[i-1]));
      memcpy(oids[i], oids[i-1], snmp_oid_size(oids[i-1]));
    }
    else
      oids[i] = generator();
  }
}

static int
generate_oids(struct oid *oids[], struct oid *sorted[], int size, struct oid *(*generator)(void))
{
  generate_raw_oids(oids, size, generator);

  memcpy(sorted, oids, size * sizeof(struct oid *));

  qsort(sorted, (size_t) size, sizeof(struct oid *),
      test_snmp_oid_compare);

  // test sizes 0, 1, 2, 10, ...
  int last_used = 0;
  for (int index = 0; index < size; index++)
  {
    if (snmp_oid_compare(sorted[last_used], sorted[index]) != 0)
      sorted[++last_used] = sorted[index];
  }

  /* delete old pointers */
  for (int i = last_used + 1; i < size; i++)
    sorted[i] = NULL;

  return (size > 1) ? last_used + 1 : size;
}

static int
t_walk_oid_desc(void)
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  struct mib_tree storage, *tree = &storage;
  mib_tree_init(pool, tree);

  STATIC_ASSERT(ARRAY_SIZE(tree_sizes) > 0);
  int size = tree_sizes[ARRAY_SIZE(tree_sizes) - 1];
  ASSERT(size > 0);
  struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
  struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));

  (void) generate_oids(oids, sorted, size, random_oid);

  for (int i = 0; i < size; i++)
    (void) mib_tree_add(pool, tree, oids[i], 0);

  for (int test = 0; test < size; test++)
  {
    int i = xrandom(size);

    char buffer[1024];
    struct oid *oid = (struct oid *) buffer;

    memcpy(oid, oids[i], snmp_oid_size(oids[i]));

    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, NULL);
    (void) mib_tree_find(tree, &walk, oid);

    int type = xrandom(4);
    switch (type)
    {
      case 0:
	bt_assert(mib_tree_walk_is_oid_descendant(&walk, oids[i]) == 0);
	break;

      case 1:
      {
	/* oid is longer than walk or has same length */
	u8 ids = oid->n_subid;
	u32 upto = MIN(OID_MAX_LEN - ids, 16);

	if (!upto)
	  continue;

	u32 new = xrandom(upto) + 1;
	oid->n_subid = ids + new;

	for (u32 i = 0; i < new; i++)
	  oid->ids[ids + i] = xrandom(OID_MAX_ID);

	bt_assert(mib_tree_walk_is_oid_descendant(&walk, oid) > 0);

	break;
      }
      case 2:
      case 3:
      {
	/* oid is shorter than walk */
	u8 ids = oid->n_subid;

	if (ids == 0 || ids == OID_MAX_LEN)
	  continue;

	u32 split = (ids > 1) ? xrandom(ids - 1) + 1 : 0;
	u32 ext = (type == 3) ? xrandom(MIN(OID_MAX_LEN - ids, 16)) : 0;

	oid->n_subid = split + ext;
	for (u32 i = 0; i < ext; i++)
	  oid->ids[split + i] = xrandom(OID_MAX_ID);

	int no_change = 1;
	for (u32 j = 0; j < MIN(ids - split, ext); j++)
	{
	  if (oid->ids[split + j] != oids[i]->ids[split + j])
	    no_change = 0;
	}

	if (no_change)
	  continue;

	bt_assert(mib_tree_walk_is_oid_descendant(&walk, oid) < 0);
	break;
      }
    }
  }

  {
    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, tree);

    u32 zero = 0;
    const struct oid *null_oid = (struct oid *) &zero;
    u32 index = xrandom(size);

    bt_assert(mib_tree_walk_is_oid_descendant(&walk, null_oid) == 0);
    bt_assert(mib_tree_walk_is_oid_descendant(&walk, oids[index]) > 0);
    (void) mib_tree_find(tree, &walk, oids[index]);
    bt_assert(mib_tree_walk_is_oid_descendant(&walk, null_oid) < 0);
  }

  u32 null_oid = 0;
  mib_tree_remove(tree, (struct oid *) &null_oid);
  lp_restore(tmp_linpool, &tmps);

  return 1;
}

static int
t_walk_oid_compare(void)
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  struct mib_tree storage, *tree = &storage;
  mib_tree_init(pool, tree);

  STATIC_ASSERT(ARRAY_SIZE(tree_sizes) > 0);
  int size = tree_sizes[ARRAY_SIZE(tree_sizes) - 1];
  ASSERT(size > 0);
  struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
  struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));

  (void) generate_oids(oids, sorted, size, random_oid);

  for (int i = 0; i < size; i++)
    (void) mib_tree_add(pool, tree, oids[i], 0);

  for (int test = 0; test < size; test++)
  {
    int i = xrandom(size);

    char buffer[1024];
    struct oid *oid = (struct oid *) buffer;

    memcpy(oid, oids[i], snmp_oid_size(oids[i]));

    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, NULL);
    (void) mib_tree_find(tree, &walk, oids[i]);

    int type = xrandom(4);
    switch (type)
    {
      case 0:
	bt_assert(mib_tree_walk_oid_compare(&walk, oids[i]) == 0);
	break;

      case 1:
      {
	/* oid is longer than walk or has same length */
	u8 ids = oid->n_subid;
	u32 upto = MIN(OID_MAX_LEN - ids, 16);

	if (!upto)
	  continue;

	u32 new = xrandom(upto) + 1;
	oid->n_subid = ids + new;
	ASSERT(snmp_oid_size(oid) < 1024);

	for (u32 i = 0; i < new; i++)
	  oid->ids[ids + i] = xrandom(OID_MAX_ID);


	bt_assert(mib_tree_walk_oid_compare(&walk, oid) < 0);
	break;
      }
      case 2:
      case 3:
      {
	/* oid is shorter than walk */
	u8 ids = oid->n_subid;

	if (ids == 0 || ids == OID_MAX_LEN)
	  continue;

	u32 split = (ids > 1) ? xrandom(ids - 1) + 1 : 0;
	u32 ext = (type == 3) ? xrandom(MIN(OID_MAX_LEN - ids, 16)) : 0;

	oid->n_subid = split + ext;
	for (u32 i = 0; i < ext; i++)
	  oid->ids[split + i] = xrandom(OID_MAX_ID);

	int cmp_res = 0;
	for (u32 j = 0; j < MIN(ids - split, ext) && !cmp_res; j++)
	  cmp_res = oids[i]->ids[split + j] - oid->ids[split + j];

	if (!cmp_res && split + ext == ids)
	  continue;

	if (!cmp_res && split < ids && ext == 0)
	  cmp_res = +1;

	if (!cmp_res && split < ids && split + ext > ids)
	  cmp_res = -1;

	if (cmp_res < 0)
	  cmp_res = -1;
	else if (cmp_res > 0)
	  cmp_res = +1;

	bt_assert(mib_tree_walk_oid_compare(&walk, oid) == cmp_res);
	break;
      }
    }
  }

  {
    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, tree);

    u32 zero = 0;
    const struct oid *null_oid = (struct oid *) &zero;
    u32 index = xrandom(size);

    bt_assert(mib_tree_walk_oid_compare(&walk, null_oid) == 0);
    bt_assert(mib_tree_walk_oid_compare(&walk, oids[index]) < 0);
    (void) mib_tree_find(tree, &walk, oids[index]);
    bt_assert(mib_tree_walk_oid_compare(&walk, null_oid) > 0);
  }

  u32 null_oid = 0;
  mib_tree_remove(tree, (struct oid *) &null_oid);
  lp_restore(tmp_linpool, &tmps);

  return 1;

}

static void UNUSED
print_dups(const struct oid *oids[], uint size)
{
  for (uint i = 0; i < size; i++)
    for (uint j = i + 1; j < size; j++)
      if (snmp_oid_compare(oids[i], oids[j]) == 0)
	log(L_WARN "pair (%u, %u)", i, j);
}

static void UNUSED
print_all(const struct oid *oids[], uint size)
{
  for (uint i = 0; i < size; i++)
    snmp_oid_log(oids[i]);
}

static inline int
oid_is_leaf(const struct oid *oid, const struct oid *leafs[], uint leaf_idx)
{
  for (uint l = 0; l < leaf_idx; l++)
    if (snmp_oid_compare(oid, leafs[l]) == 0)
      return 1;

  return 0;
}

static int
all_invalid(const struct oid *oids[], const byte *invalid, uint size, uint index)
{
  if (!invalid[index])
    return 0;

  for (uint i = 0; i < size; i++)
  {
    if (i == index) continue;

    if (snmp_oid_compare(oids[i], oids[index]) == 0 &&
	!invalid[i])
      return 0;
  }

  return 1;
}

static int
count_error(const struct oid *oids[], const byte *invalid, uint size)
{
  int error = 0;
  for (uint i = 0; i < size; i++)
  {
    if (!invalid[i]) continue;

    int skip = 0;
    for (uint j = 0; j < i; j++)
    {
      if (snmp_oid_compare(oids[i], oids[j]) == 0)
      {
	skip = 1;
	break;
      }
    }

    if (skip) continue;

    if (all_invalid(oids, invalid, size, i))
      error++;
  }

  return error;
}

static int
gen_test_add(struct oid *(*generator)(void))
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_inet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    byte *types = mb_alloc(pool, size * sizeof(byte));
    byte *invalid_hist = mb_alloc(pool, size * sizeof(byte));
    struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));
    struct oid **leafs = (with_leafs) ? mb_alloc(pool, size * sizeof(struct oid *))
      : NULL;
    int leaf_idx = 0;
    int empty_prefix_added = 0;
    int distinct = generate_oids(oids, sorted, size, generator);

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(pool, tree);

    if (no_inet_prefix)
    {
      /* remove the node .1 and all children */
      const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
      mib_tree_remove(tree, inet_pref);
    }

    int invalid_counter = 0;
    int counter = 0;
    int cut = 0;
    for (int i = 0; i < size; i++)
    {
      int invalid = 0;
      int is_leaf = (with_leafs) ? (int) xrandom(2) : 0;
      types[i] = (byte) is_leaf;

      int will_cut = 0;
      int oid_nulled = snmp_is_oid_empty(oids[i]);

      if (oid_nulled && is_leaf)
	invalid = 1;

      if (!no_inet_prefix)
      {
	char buffer[1024];
	struct oid *o = (struct oid *) buffer;

	struct oid *inet = oid_create(4, 0, 0, /* ids */ 1, 3, 6, 1);
	snmp_oid_common_ancestor(oids[i], inet, o);

	/* If the standard internet prefix is present,
	 * then the prefix leafs are invalid. */
	if (snmp_oid_compare(oids[i], o) == 0)
	  invalid = is_leaf;
      }

      /* check existence of ancestor node of a new leaf */
      for (int oi = 0; !invalid && !oid_nulled && oi < i; oi++)
      {
	char buffer[1024];
	struct oid *o = (struct oid *) buffer;

	if (invalid_hist[oi])
	  continue;

	int other_is_leaf = (int) types[oi];

	if (snmp_oid_compare(oids[oi], oids[i]) == 0 &&
	    !snmp_is_oid_empty(oids[i]))
	{
	  if (other_is_leaf == is_leaf)
	    will_cut = 1;
	  else if (other_is_leaf != is_leaf)
	    invalid = 1;

	  break;
	}

	snmp_oid_common_ancestor(oids[oi], oids[i], o);

	if ((snmp_oid_compare(oids[i], o) == 0 && is_leaf) ||
	    (snmp_oid_compare(oids[oi], o) == 0 && other_is_leaf))
	{
	  invalid = 1;
	  break;
	}
      }

      if (!invalid && will_cut)
	cut++;

      if (is_leaf && !invalid)
	/* leafs could have duplicates */
	leafs[leaf_idx++] = oids[i];

      mib_node_u *node = mib_tree_add(pool, tree, oids[i], is_leaf);

      bt_assert((node == NULL) == invalid);

      invalid_hist[i] = 0;
      if (invalid)
      {
	invalid_hist[i] = 1;
	invalid_counter++;
      }

      if (node != NULL && (!snmp_is_oid_empty(oids[i]) || !empty_prefix_added))
	counter++;

      if (snmp_is_oid_empty(oids[i]) && !is_leaf)
	empty_prefix_added = 1;
    }

    int error = count_error((const struct oid **) oids, invalid_hist, size);
    bt_assert(counter - cut == distinct - error);

    lp_restore(tmp_linpool, &tmps);
    mb_free(oids);
    mb_free(sorted);
    mb_free(leafs);
  }

  return 1;
}

static int
t_tree_add(void)
{

  gen_test_add(random_prefixed_oid);
  gen_test_add(random_no_prefix_oid);
  gen_test_add(random_prefixable_oid);
  gen_test_add(random_oid);

  return 1;
}

static int
gen_test_find(struct oid *(*generator)(void))
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_inet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    mib_node_u **nodes = mb_alloc(pool, size * sizeof(mib_node_u *));
    struct oid **searched = mb_alloc(pool, size * sizeof(struct oid *));
    byte *types = mb_alloc(pool, size * sizeof(byte));

    /* enough to hold snmp_internet copy */
    uint longest_inet_pref_len = 0;
    struct oid *longest_inet_pref = oid_create(4, 0, 0, /* ids */ 0, 0, 0, 0);

    generate_raw_oids(oids, size, generator);
    generate_raw_oids(searched, size, generator);

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(pool, tree);

    if (no_inet_prefix)
    {
      /* remove the node .1 and all children */
      const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
      mib_tree_remove(tree, inet_pref);
    }

    for (int i = 0; i < size; i++)
      types[i] = (byte) ((with_leafs) ? xrandom(2) : 0);

    /*
     * by default initialized MIB tree will have internet prefix have inserted
     */
    if (!no_inet_prefix)
    {
      memcpy(longest_inet_pref->ids, snmp_internet, sizeof(snmp_internet));
      longest_inet_pref_len = 4;
    }

    for (int i = 0; i < size; i++)
    {
      nodes[i] = mib_tree_add(pool, tree, oids[i], types[i]);

      if (nodes[i] == NULL) continue;

      if (snmp_oid_is_prefixed(oids[i]))
      {
	memcpy(longest_inet_pref->ids, snmp_internet, sizeof(snmp_internet));
	longest_inet_pref_len = 4;
      }
      else
      {
	for (uint j = 0; j < MIN(oids[i]->n_subid,
	    ARRAY_SIZE(snmp_internet)); j++)
	{
	  if (oids[i]->ids[j] == snmp_internet[j] &&
	      j >= longest_inet_pref_len)
	  {
	    longest_inet_pref->ids[j] = snmp_internet[j];
	    longest_inet_pref_len = j + 1;
	  }
	  else if (oids[i]->ids[j] == snmp_internet[j])
	    ;
	  else
	    break;
	}
      }
    }

    for (int i = 0; i < size; i++)
    {
      for (int j = 0; j < size; j++)
      {
	if (nodes[i] != NULL &&
	    nodes[j] != NULL &&
	    snmp_oid_compare(oids[i], oids[j]) == 0)
	  bt_assert(nodes[i] == nodes[j]);
      }
    }

    mib_node_u *last = NULL;
    for (int i = 0; i < size; i++)
    {
      /*
       * This solves cases where we tried to insert
       * both leaf and inner node for same OID.
       * Result of insertion should be NULL in cases
       * when the insertion is inconsistent with the current tree state.
       * (the first insertion wins)
       */
      int expected_precise = 1;
      mib_node_u *expected = nodes[i];

      if (!no_inet_prefix)
      {
	char buf[1024];
	struct oid *o = (struct oid *) buf;
	snmp_oid_common_ancestor(oids[i], longest_inet_pref, o);
	if (snmp_oid_compare(oids[i], o) == 0)
	  expected_precise = 0;
      }

      if (snmp_is_oid_empty(oids[i]))
      {
	expected_precise = 0;
      }

      for (int j = 0; expected_precise && j < size; j++)
      {
	if (i == j) continue;

	if (snmp_oid_compare(oids[i], oids[j]) == 0 &&
	    types[i] != types[j] && nodes[i] == NULL)
	{
	  if (nodes[j] != NULL)
	  {
	    expected = nodes[j];
	    break;
	  }

	  /* else expected = NULL; */
	}

	char buf[1024];
	struct oid *o = (struct oid *) buf;

	snmp_oid_common_ancestor(oids[i], oids[j], o);

	/* oids[j] lies on path from root to oids[i] */
	if (snmp_oid_compare(oids[i], o) == 0 &&
	    nodes[j] != NULL &&
	    expected == NULL)
	{
	  expected_precise = 0;
	  break;
	}
      }


      struct mib_walk_state walk;
      //mib_tree_walk_init(&walk, tree, 0);
      mib_tree_walk_init(&walk, NULL);
      mib_node_u *found = mib_tree_find(tree, &walk, oids[i]);

      bt_assert(walk.stack_pos <= MIB_WALK_STACK_SIZE + 1);
      bt_assert(walk.id_pos <= OID_MAX_LEN);

      if (expected_precise)
	bt_assert(found == expected);
      else
	/* found is an auto-inserted node on path to some dest OID */
	bt_assert(found != NULL);

      last = found;

      /* test finding with walk state not pointing at the root of the tree */
      u8 subids = oids[i]->n_subid;
      if (subids > 0)
      {
	found = NULL;
	u32 new_ids = xrandom(subids);
	mib_tree_walk_init(&walk, (xrandom(2)) ? tree : NULL);

	oids[i]->n_subid = new_ids;

	mib_node_u *ignored UNUSED;
	ignored = mib_tree_find(tree, &walk, oids[i]);

	oids[i]->n_subid = subids;

	found = mib_tree_find(tree, &walk, oids[i]);

	/* see above */
	if (expected_precise)
	  bt_assert(found == expected);
	else
	{
	  /* test that the result is same as direct searched from tree root */
	  bt_assert(found == last);
	  bt_assert(found != NULL);
	}
      }
    }

    for (int search = 0; search < size; search++)
    {
      int has_node = 0;
      for (int stored = 0; stored < size; stored++)
      {
	char buf[1024];
	struct oid *o = (struct oid *) buf;
	snmp_oid_common_ancestor(oids[stored], searched[search], o);

	/* test if OID oids[stored] is valid and if it forms a path from root
	 * with OID searched[search] */
	if (nodes[stored] != NULL && snmp_oid_compare(searched[search], o) == 0)
	{
	  has_node = 1;
	  break;
	}
      }

      const struct oid *oid = searched[search];
      if (!has_node && !snmp_oid_is_prefixed(oid))
      {
	for (uint i = 0; i < MIN(ARRAY_SIZE(snmp_internet),
	    oid->n_subid); i++)
	{
	  if (longest_inet_pref->ids[i] != 0 &&
	      longest_inet_pref->ids[i] == oid->ids[i])
	    has_node = 1;
	  else
	  {
	    has_node = 0;
	    break;
	  }
	}

	if (has_node && oid->n_subid > ARRAY_SIZE(snmp_internet))
	  has_node = 0;
      }

      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, NULL);
      //mib_tree_walk_init(&walk, tree); /* TODO should work also like this */
      mib_node_u *found = mib_tree_find(tree, &walk, searched[search]);
      bt_assert(has_node == (found != NULL));

      bt_assert(walk.stack_pos <= MIB_WALK_STACK_SIZE + 1);
      bt_assert(walk.id_pos <= OID_MAX_LEN);

      last = found;

      u8 subids = searched[search]->n_subid;
      if (subids > 0)
      {
	found = NULL;
	u32 new_ids = xrandom(subids);
	mib_tree_walk_init(&walk, (xrandom(2)) ? tree : NULL);

	searched[search]->n_subid = new_ids;

	mib_node_u *ignored UNUSED;
	ignored = mib_tree_find(tree, &walk, searched[search]);

	searched[search]->n_subid = subids;

	found = mib_tree_find(tree, &walk, searched[search]);

	bt_assert(has_node == (found != NULL));

	bt_assert(walk.stack_pos <= MIB_WALK_STACK_SIZE + 1);
	bt_assert(walk.id_pos <= OID_MAX_LEN);

	/* test that the result is same as direct search from tree root */
	bt_assert(last == found);
      }
    }

    lp_restore(tmp_linpool, &tmps);
    mb_free(oids);
    mb_free(nodes);
    mb_free(searched);
    mb_free(types);
  }

  tmp_flush();
  return 1;
}

static int
t_tree_find(void)
{

  gen_test_find(random_prefixed_oid);
  gen_test_find(random_no_prefix_oid);
  gen_test_find(random_prefixable_oid);
  gen_test_find(random_oid);

  return 1;
}

#if 0
static int
delete_cleanup(const struct oid *oid, struct oid *oids[], mib_node_u *valid[], int size)
{
  uint counter = 0;
  for (int i = 0; i < size; i++)
  {
    char buf[1024];
    struct oid *o = (struct oid *) buf;

    if (oid == oids[i])
    {
      counter++;
      continue;
    }

    snmp_oid_common_ancestor(oid, oids[i], o);

    if (snmp_oid_compare(oid, o) == 0)
    {
      valid[i] = NULL;
      counter++;
    }
  }

  return counter;
}
#endif

static int
gen_test_delete_remove(struct oid *(*generator)(void), int remove)
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_inet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));
    mib_node_u **nodes = mb_alloc(pool, size * sizeof(mib_node_u *));
    byte *types = mb_alloc(pool, size * sizeof(byte));

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(pool, tree);

    if (no_inet_prefix)
    {
      /* remove the node .1 and all children */
      const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
      mib_tree_remove(tree, inet_pref);
    }

    int distinct = generate_oids(oids, sorted, size, generator);

    for (int i = 0; i < size; i++)
    {
      int is_leaf;
      is_leaf = types[i] = (byte) (with_leafs) ? xrandom(2) : 0;
      (void) mib_tree_add(pool, tree, oids[i], is_leaf);
    }

    for (int d = 0; d < distinct; d++)
    {
      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, NULL);
      //mib_tree_walk_init(&walk, tree); TODO
      nodes[d] = mib_tree_find(tree, &walk, sorted[d]);
    }

    /* we need to populate the nodes array after all insertions because
     * some insertion may fail (== NULL) because we try to insert a leaf */
#if 0
    for (int i = 0; i < size; i++)
    {
      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, tree, 0);
      nodes[i] = mib_tree_find(tree, &walk, oids[i]);
    }
#endif

    int deleted, invalid_counter;
    /* test deletion one of the inserted OIDs */
    for (int round = 0; round < (size + 3) / 4 + remove; round++)
    {
      /* note: we do not run any rounds for size zero because xrandom(0)
       * does not exist */
      int i;
      struct oid *oid;
      if (!remove)
      {
	/* this way we are also testing remove non-existent tree nodes */
	i = xrandom(size); /* not xrandom(distinct) */
	oid = oids[i];
      }
      else
      {
	i = -1; /* break fast  */
	oid = generator();
      }

      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, NULL);
      // mib_tree_walk_init(&walk, tree); TODO
      mib_node_u *node = mib_tree_find(tree, &walk, oid);

      if (node == NULL)
	continue;

      if (!remove)
	deleted = mib_tree_delete(tree, &walk);
      else
	deleted = mib_tree_remove(tree, oid);

      bt_assert(deleted > 0 || snmp_is_oid_empty(oid));

      invalid_counter = 0;
      int counted_removed = 0;
      for (int j = 0; j < distinct; j++)
      {
	//mib_tree_walk_init(&walk, tree, 0);
	mib_tree_walk_init(&walk, NULL);
	mib_node_u *node = mib_tree_find(tree, &walk, sorted[j]);

	if (snmp_is_oid_empty(oid))
	  ;
	/* the oid could have multiple instances in the oids dataset */
	else if (snmp_oid_compare(oid, sorted[j]) == 0 && !counted_removed)
	{
	  invalid_counter++;
	  counted_removed = 1;
	  bt_assert(node == NULL);
	  nodes[j] = NULL;
	}
	else if (node != nodes[j])
	{
	  invalid_counter++;
	  bt_assert(node == NULL);
	  nodes[j] = NULL;
	}
      }

      /* we do not count the internal node that are included in the deleted */
      bt_assert(deleted >= invalid_counter);
    }

    lp_restore(tmp_linpool, &tmps);
    mb_free(oids);
    mb_free(sorted);
    mb_free(nodes);
  }

  tmp_flush();

  return 1;
}

static int
t_tree_delete(void)
{

  gen_test_delete_remove(random_prefixed_oid, 0);
  gen_test_delete_remove(random_no_prefix_oid, 0);
  gen_test_delete_remove(random_prefixable_oid, 0);
  gen_test_delete_remove(random_oid, 0);

  return 1;
}

static int
t_tree_remove(void)
{

  gen_test_delete_remove(random_prefixed_oid, 1);
  gen_test_delete_remove(random_no_prefix_oid, 1);
  gen_test_delete_remove(random_prefixable_oid, 1);
  gen_test_delete_remove(random_oid, 1);

  return 1;
}

static void
gen_test_traverse(struct oid *(*generator)(void))
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_inet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));
    mib_node_u **nodes = mb_allocz(pool, size * sizeof(mib_node_u *));

    const int distinct = generate_oids(oids, sorted, size, generator);

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(pool, tree);

    if (no_inet_prefix)
    {
      /* remove the node .1 and all children */
      const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
      mib_tree_remove(tree, inet_pref);
    }

    for (int o = 0; o < size; o++)
    {
      int is_leaf = (with_leafs) ? (int) xrandom(2) : 0;
      (void) mib_tree_add(pool, tree, oids[o], is_leaf);
    }

    for (int d = 0; d < distinct; d++)
    {
      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, NULL);
      nodes[d] = mib_tree_find(tree, &walk, sorted[d]);
    }

    int bound = 0;

    for (int d = 0; d < distinct; d++)
    {
      if (snmp_oid_is_prefixed(sorted[d]))
	bound += 5;
      bound += (int) sorted[d]->n_subid;
    }

    if (!no_inet_prefix)
      bound += (ARRAY_SIZE(snmp_internet) + 1);

    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, tree);

    char buf[1024], buf2[1024];
    struct oid *oid = (struct oid *) buf;
    struct oid *last = (struct oid *) buf2;
    memset(oid, 0, sizeof(struct oid));	  /* create a null OID */
    memset(last, 0, sizeof(struct oid));

    int oid_index = 0;
    if (size > 0  && snmp_is_oid_empty(sorted[oid_index]))
      oid_index++;

    mib_node_u *current;
    int i = 0;
    while ((current = mib_tree_walk_next(tree, &walk)) != NULL && i++ < bound)
    {
      memcpy(last, oid, snmp_oid_size(oid));
      mib_tree_walk_to_oid(&walk, oid,
	  (1024 - sizeof(struct oid) / sizeof(u32)));

      bt_assert(snmp_oid_compare(last, oid) < 0);

      while (oid_index < distinct && nodes[oid_index] == NULL)
	oid_index++;

      if (oid_index < distinct && snmp_oid_compare(sorted[oid_index], oid) == 0)
	oid_index++;
    }

    bt_assert(current == NULL);
    while (oid_index < distinct && nodes[oid_index] == NULL)
      oid_index++;

    /* the bound check is only for that the loop is finite */
    bt_assert(i <= bound + 2);

    current = mib_tree_walk_next(tree, &walk);
    bt_assert(current == NULL);
    bt_assert(oid_index == distinct);

    mb_free(oids);
    mb_free(sorted);
    mb_free(nodes);

    lp_restore(tmp_linpool, &tmps);
  }

  tmp_flush();
}

static int
t_tree_traversal(void)
{
  gen_test_traverse(random_prefixed_oid);
  gen_test_traverse(random_no_prefix_oid);
  gen_test_traverse(random_prefixable_oid);
  gen_test_traverse(random_oid);

  return 1;
}

static void
gen_test_leafs(struct oid *(*generator)(void))
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_inet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    struct oid **sorted = mb_alloc(pool, size * sizeof(struct oid *));
    mib_node_u **nodes = mb_allocz(pool, size * sizeof(mib_node_u *));

    const int distinct = generate_oids(oids, sorted, size, generator);

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(pool, tree);

    if (no_inet_prefix)
    {
      /* remove the node .1 and all children */
      const struct oid *inet_pref = oid_create(1, 0, 0, /* ids */ 1);
      mib_tree_remove(tree, inet_pref);
    }

    for (int o = 0; o < size; o++)
    {
      int is_leaf = (with_leafs) ? (int) xrandom(2) : 0;
      (void) mib_tree_add(pool, tree, oids[o], is_leaf);
    }

    int leafs = 0;
    for (int d = 0; d < distinct; d++)
    {
      struct mib_walk_state walk;
      mib_tree_walk_init(&walk, NULL);
      nodes[d] = mib_tree_find(tree, &walk, sorted[d]);

      /* count only leafs that was successfully inserted without duplicits */
      if (nodes[d] != NULL && mib_node_is_leaf(nodes[d]))
	leafs++;
    }

    struct mib_walk_state walk;
    mib_tree_walk_init(&walk, tree);
    if (!with_leafs)
    {
      struct mib_leaf *leaf = mib_tree_walk_next_leaf(tree, &walk, 0);
      bt_assert(leaf == NULL);

      continue;
    }

    char buf[1024], buf2[1024];
    struct oid *oid = (struct oid *) buf;
    struct oid *last = (struct oid *) buf2;
    memset(oid, 0, sizeof(struct oid));	  /* create a null OID */
    memset(last, 0, sizeof(struct oid));

    int oid_index = 0;

    struct mib_leaf *current;
    int i = 0;	/* iteration counter ~ leafs found */
    while ((current = mib_tree_walk_next_leaf(tree, &walk, 0)) != NULL && i++ < leafs)
    {
      memcpy(last, oid, snmp_oid_size(oid));
      mib_tree_walk_to_oid(&walk, oid,
	  (1024 - sizeof(struct oid) / sizeof(u32)));

      bt_assert(snmp_oid_compare(last, oid) < 0);
      bt_assert(mib_node_is_leaf(((mib_node_u *)current)));

      while (oid_index < distinct &&
	  (nodes[oid_index] == NULL || !mib_node_is_leaf(nodes[oid_index])))
	oid_index++;

      if (oid_index < distinct && snmp_oid_compare(sorted[oid_index], oid) == 0)
	oid_index++;
    }

    bt_assert(current == NULL);
    while (oid_index < distinct &&
	(nodes[oid_index] == NULL || !mib_node_is_leaf(nodes[oid_index])))
      oid_index++;

    current = mib_tree_walk_next_leaf(tree, &walk, 0);
    bt_assert(current == NULL);
    bt_assert(oid_index == distinct);
    bt_assert(i == leafs);

    mb_free(oids);
    mb_free(sorted);
    mb_free(nodes);

    lp_restore(tmp_linpool, &tmps);
  }

  tmp_flush();
}

static int
t_tree_leafs(void)
{

  gen_test_leafs(random_prefixed_oid);
  gen_test_leafs(random_no_prefix_oid);
  gen_test_leafs(random_prefixable_oid);
  gen_test_leafs(random_oid);

  return 1;
}

#if 0
static int
t_tree_all(void)
{
  /* random sequences of insertion/deletion/searches and walks */
  return 0; /* failed */
}
#endif


int main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();

  //unsigned seed = rand();
  unsigned seed = 1000789714;
  log("random seed is %d", seed);
  srandom(seed);

  bt_test_suite(t_oid_empty, "Function that determines if the OID is empty");
  bt_test_suite(t_oid_compare, "Function defining lexicographical order on OIDs");
  bt_test_suite(t_varbind_name_to_tx, "Function loading OID from RX buffer with prefixation");
  bt_test_suite(t_oid_ancestor, "Function finding common ancestor of two OIDs");
  bt_test_suite(t_walk_to_oid, "Function transforming MIB tree walk state to OID");
  bt_test_suite(t_walk_oid_desc, "Function testing relation being subtree between MIB tree walk and OID");
  bt_test_suite(t_walk_oid_compare, "Function comparing MIB tree walk and OID");

  bt_test_suite(t_tree_find, "MIB tree search");
  bt_test_suite(t_tree_traversal, "MIB tree traversal");
  bt_test_suite(t_tree_leafs, "MIB tree leafs traversal");
  bt_test_suite(t_tree_add, "MIB tree insertion");
  bt_test_suite(t_tree_delete, "MIB tree deletion");
  bt_test_suite(t_tree_remove, "MIB tree removal");
  //bt_test_suite(t_tree_all, "MIB tree random find, add, delete mix");

  return bt_exit_value();
}

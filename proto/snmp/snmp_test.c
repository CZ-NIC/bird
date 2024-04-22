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

#include "bgp_mib.h"
#include "subagent.h"
#include "snmp.h"
#include "snmp_utils.h"
#include "mib_tree.h"

// TODO test walk state stack overflow
// TODO hint for child len alloc size

static int t_oid_empty(void);
static int t_oid_compare(void);
static int t_oid_prefixize(void);
static int t_tree_find(void);
static int t_tree_traversal(void);
static int t_tree_leafs(void);
static int t_tree_add(void);
static int t_tree_delete(void);

#define SNMP_BUFFER_SIZE 1024
#define TESTS_NUM   20
#define SMALL_TESTS_NUM 10
static int tree_sizes[] = { 0, 1, 10, 100, 1000 };

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
  u32 len = xrandom(OID_MAX_LEN + 1 - ARRAY_SIZE(snmp_internet));

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

  tmp_flush();
  return 1;
}

static struct oid *
snmp_oid_prefixize(struct snmp_proto *p, const struct oid *oid, struct snmp_pdu *c)
{
  struct agentx_varbind *vb = snmp_vb_to_tx(p, oid, c);
  bt_assert(vb->reserved == 0);
  return &vb->name;
}

/*
 * t_oid_prefixize - test prefixing aspect of function snmp_vb_to_tx()
 */
static int
t_oid_prefixize(void)
{
  lp_state tmps = { };
  struct snmp_proto *snmp_proto = NULL;

  byte *buffer = tmp_alloc(SNMP_BUFFER_SIZE);
  const struct snmp_pdu copy = {
    .buffer = buffer,
    .size = SNMP_BUFFER_SIZE,
    .error = AGENTX_RES_NO_ERROR,
    .index = 0,
  };
  struct snmp_pdu c;

  lp_save(tmp_linpool, &tmps);


  /* testing prefixable OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *oid = random_prefixable_oid();

    u8 subids = oid->n_subid;
    u8 include = oid->include;
    u32 pid = oid->ids[ARRAY_SIZE(snmp_internet)];

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    struct oid *new = snmp_oid_prefixize(snmp_proto, oid, &c);

    bt_assert(new->n_subid == subids - (ARRAY_SIZE(snmp_internet) + 1));
    bt_assert(new->prefix == pid);
    bt_assert(!!new->include == !!include);
    bt_assert(new->reserved == 0);

    for (u32 i = 0; i < new->n_subid; i++)
    {
      bt_assert(new->ids[i] == oid->ids[i + ARRAY_SIZE(snmp_internet) + 1]);
    }

    for (u32 j = 0; j < ARRAY_SIZE(snmp_internet); j++)
      bt_assert(oid->ids[j] == snmp_internet[j]);

    lp_restore(tmp_linpool, &tmps);
  }

  /* testing already prefixed OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *prefixed = random_prefixed_oid();

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(prefixed) + 8);

    struct oid *new = snmp_oid_prefixize(snmp_proto, prefixed, &c);

    bt_assert(new->n_subid == prefixed->n_subid);
    bt_assert(new->prefix == prefixed->prefix);
    bt_assert(!!new->include == !!prefixed->include);
    bt_assert(new->reserved == 0);
    bt_assert(!memcmp(&new->ids[0], &prefixed->ids[0], new->n_subid * sizeof(u32)));

    lp_restore(tmp_linpool, &tmps);
  }

  lp_restore(tmp_linpool, &tmps);

  /* testing non-prefixable OIDs */
  for (int test = 0; test < TESTS_NUM; test++)
  {
    const struct oid *oid = random_no_prefix_oid();

    /* test that the OID is _really_ not prefixable */
    if (oid->n_subid > ARRAY_SIZE(snmp_internet) &&
	oid->ids[ARRAY_SIZE(snmp_internet) + 1] <= UINT8_MAX)
    {
      for (u32 i = 0; i < ARRAY_SIZE(snmp_internet); i++)
	if (oid->ids[i] != snmp_internet[i]) goto continue_testing;

      break; /* outer for loop */
    }

continue_testing:

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    struct oid *new = snmp_oid_prefixize(snmp_proto, oid, &c);

    bt_assert(new->n_subid == oid->n_subid);
    bt_assert(new->prefix == oid->prefix);
    bt_assert(!!new->include == !!oid->include);
    bt_assert(new->reserved == 0);
    bt_assert(!memcmp(&new->ids[0], &oid->ids[0], new->n_subid * sizeof(u32)));

    lp_restore(tmp_linpool, &tmps);
  }

  for (int test = 0; test < SMALL_TESTS_NUM; test++)
  {
    const struct oid *oid;
    {
      struct oid *work = random_prefixable_oid();

      /* include also the prefix ID (at index 4) */
      u32 index = xrandom(ARRAY_SIZE(snmp_internet) + 1);
      /* change randomly picked id at index from 0..5 (included) */
      u32 random = bt_random();
      if (index == ARRAY_SIZE(snmp_internet) && random > 255)
	work->ids[index] = random;
      else if (index != ARRAY_SIZE(snmp_internet) && work->ids[index] != random)
	work->ids[index] = random;
      else
	continue;
      oid = work;
    }

    /* reset to the default snmp_pdu */
    c = copy; memset(buffer, 0, snmp_oid_size(oid) + 8);

    struct oid *new = snmp_oid_prefixize(snmp_proto, oid, &c);

    bt_assert(new->n_subid == oid->n_subid);
    bt_assert(new->prefix == oid->prefix);
    bt_assert(!!new->include == !!oid->include);
    bt_assert(new->reserved == 0);
    bt_assert(!memcmp(&new->ids[0], &oid->ids[0], new->n_subid * sizeof(u32)));

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

/* checks if the last two oids are same, but one is leaf and the other is not */
static inline int UNUSED
corner_case(struct oid **oids, int oid_idx, struct oid **leafs, int leaf_idx, int is_leaf)
{
  const struct oid **oids_c = (const struct oid **) oids;
  const struct oid **leafs_c = (const struct oid **) leafs;
  if (oid_idx == 0)
    return 0;

  /* if the current (last) OID from oids is not leaf */
  if (!is_leaf && leaf_idx > 0 &&
      /* and is same as the last leaf */
      snmp_oid_compare(oids_c[oid_idx], leafs_c[leaf_idx - 1]) == 0)
    return 1;	/* then return true */


  /* if the current (last) OID from oids is a leaf */
  if (is_leaf && oid_idx > 0 &&
      /* and is same as previous OID */
      snmp_oid_compare(oids_c[oid_idx], oids_c[oid_idx - 1]) == 0)
    return 1;	/* then return true */

  return 0; /* false */
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
    byte *invalid_hist = mb_alloc(pool, size & sizeof(byte));
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

      /* check existence of ancestor node of a new leaf */
      for (int oi = 0; !invalid && !oid_nulled && oi < i; oi++)
      {
	char buffer[1024];
	struct oid *o = (void *) buffer;

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
	for (uint j = 0; j < MIN(LOAD_U8(oids[i]->n_subid),
	    ARRAY_SIZE(snmp_internet)); j++)
	{
	  if (LOAD_U32(oids[i]->ids[j]) == snmp_internet[j] &&
	      j >= longest_inet_pref_len)
	  {
	    longest_inet_pref->ids[j] = snmp_internet[j];
	    longest_inet_pref_len = j + 1;
	  }
	  else if (LOAD_U32(oids[i]->ids[j]) == snmp_internet[j])
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
      for (int j = 0; j < size; j++)
      {
	if (i == j) continue;

	if (snmp_oid_compare(oids[i], oids[j]) == 0 &&
	    types[i] != types[j] && nodes[i] == NULL)
	{
	  expected = nodes[j];
	  break;
	}

	char buf[1024];
	struct oid *o = (void *) buf;

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
      mib_tree_walk_init(&walk);
      mib_node_u *found = mib_tree_find(tree, &walk, oids[i]);

      if (expected_precise)
	bt_assert(found == expected);
      else
	/* found is an auto-inserted node on path to some dest OID */
	bt_assert(found != NULL);
    }

    for (int search = 0; search < size; search++)
    {
      int has_node = 0;
      for (int stored = 0; stored < size; stored++)
      {
	char buf[1024];
	struct oid *o = (void *) buf;
	snmp_oid_common_ancestor(oids[stored], searched[search], o);

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
	    LOAD_U8(oid->n_subid)); i++)
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

	if (has_node && LOAD_U8(oid->n_subid) > ARRAY_SIZE(snmp_internet))
	  has_node = 0;
      }

      struct mib_walk_state walk;
      mib_tree_walk_init(&walk);
      mib_node_u *found = mib_tree_find(tree, &walk, searched[search]);
      bt_assert(has_node == (found != NULL));
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

static int
delete_cleanup(const struct oid *oid, struct oid *oids[], mib_node_u *valid[], int size)
{
  uint counter = 0;
  for (int i = 0; i < size; i++)
  {
    char buf[1024];
    struct oid *o = (void *) buf;

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

static int
gen_test_delete(struct oid *(*generator)(void))
{
  lp_state tmps;
  lp_save(tmp_linpool, &tmps);

  pool *pool = &root_pool;

  for (int test = 0; test < TESTS_NUM; test++)
  {
    size_t tsz = ARRAY_SIZE(tree_sizes);

    int size = tree_sizes[test % tsz];
    int with_leafs = (test % (2 * tsz)) < tsz;
    int no_iet_prefix = (test % (4 * tsz)) < (2 * tsz);

    struct oid **oids = mb_alloc(pool, size * sizeof(struct oid *));
    mib_node_u **nodes = mb_alloc(pool, size * sizeof(struct mib_node_u *));
    byte *types = mb_alloc(pool, size * sizeof(byte));

    struct mib_tree storage, *tree = &storage;
    mib_tree_init(tree);

    generate_raw_oids(oids, size, generator);

    for (int i = 0; i < size; i++)
    {
      int is_leaf;
      is_leaf = types[i] = (byte) (with_leafs) ? xrandom(2) : 0;
      nodes[i] = mib_tree_add(pool, tree, oids[i], is_leaf);
    }

    for (int round = 0; round < size / 4; round++)
    {
      int i = xrandom(size);

      mib_tree_walk_state walk;
      mib_tree_walk_walk_init(&walk);
      mib_node_u *node = mib_tree_find(tree, walk, oids[i]);

      int deleted = mib_tree_delete(tree, walk);

      int invalid_counter = 0;
      for (int j = 0; j < size; j++)
      {
	if (oids[i] == oids[j])
	{
	  mib_node_u *node = mib_tree_find(oids[j]);
	  bt_assert(node == NULL);
	  invalid_counter++;
	  continue;
	}

	char buf[1024];
	struct oid *o = (void *) buf;

	// TODO check that new invalid oids is == or below the deleted one */

	mib_node_u *node = mib_tree_find(oids[j]);
	if (node != nodes[j])
	{
	  nodes[j] = NULL;
	  invalid_counter++;
	}
      }

    }

    lp_restore(tmp_linpool, &tmps);
    mb_free(oids);
    mb_free(nodes);
  }

  tmp_flush();

  return 1;
}

static int
t_tree_delete(void)
{

  gen_test_delete(random_prefixed_oid);
  gen_test_delete(random_no_prefix_oid);
  gen_test_delete(random_prefixable_oid);
  gen_test_delete(random_oid);

  return 1;
}

static int
t_tree_remove(void)
{
  return 0; /* failed */
}


static int
t_tree_traversal(void)
{
  return 0; /* failed */
}

static int
t_tree_leafs(void)
{
  return 0; /* failed */
}

static int
t_tree_all(void)
{
  /* random sequences of insertion/deletion */
  return 0; /* failed */
}


int main(int argc, char **argv)
{
  bt_init(argc, argv);
  bt_bird_init();

  srandom(0x0000fa00);

  bt_test_suite(t_oid_empty, "Function that determines if the OID is empty");
  bt_test_suite(t_oid_compare, "Function defining lexicographical order on OIDs");
  bt_test_suite(t_oid_prefixize, "Function transforming OID to prefixed form");
  bt_test_suite(t_oid_ancestor, "Function finding common ancestor of two OIDs");

  bt_test_suite(t_tree_find, "MIB tree search");
  bt_test_suite(t_tree_traversal, "MIB tree traversal");
  bt_test_suite(t_tree_leafs, "MIB tree leafs traversal");
  bt_test_suite(t_tree_add, "MIB tree insertion");
  bt_test_suite(t_tree_delete, "MIB tree removal");

  return bt_exit_value();
}

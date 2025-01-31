#include "test/birdtest.h"
#include "nest/route.h"



static _Bool
eattr_same_value2(const eattr *a, const eattr *b)
{
  // this function comes from rt-attr.c
  if (
      a->id != b->id ||
      a->flags != b->flags ||
      a->type != b->type ||
      a->undef != b->undef
     )
    return 0;

  if (a->undef)
    return 1;

  if (a->type & EAF_EMBEDDED)
    return a->u.data == b->u.data;
  else
    return adata_same(a->u.ptr, b->u.ptr);
}

void
init_ea_list(struct ea_list *eal, int count)
{
  eal->flags = 0;
  eal->count = count;
  eal->next = NULL;
}

void
init_ea_with_3eattr(struct ea_list *eal)
{
  init_ea_list(eal, 3);
  eal->attrs[0] = EA_LITERAL_EMBEDDED(&ea_gen_preference, 0, 1234);
  eal->attrs[1] = EA_LITERAL_EMBEDDED(&ea_gen_source, 0, 5678);
  ip_addr dummy;
  dummy.addr[0] = 123;
  eal->attrs[2] = EA_LITERAL_STORE_ADATA(&ea_gen_from, 0, &dummy, sizeof(ip_addr));
  eal->attrs[0].originated = 0;
  eal->attrs[1].originated = 1;
}

static int
t_normalize_one_layer(void)
{
  struct ea_list *eal = xmalloc(sizeof(struct ea_list) + 3 * sizeof(eattr));

  init_ea_with_3eattr(eal);

  struct ea_list *new_eal = ea_normalize(eal, 0);

  eattr *result[] = {&eal->attrs[0], &eal->attrs[2], &eal->attrs[1]};

  if (new_eal->count != 3)
    return 0;

  for(uint i = 0; i < new_eal->count; i++)
    if (!(eattr_same_value2(&new_eal->attrs[i], result[i]) &&
        new_eal->attrs[i].originated == result[i]->originated &&
        new_eal->attrs[i].fresh == 0))
      return 0;
  if (new_eal->flags != EALF_SORTED)
    return 0;
  return 1;
}


static int
t_normalize_two_layers(void)
{
  struct ea_list *eal1 = xmalloc(sizeof(struct ea_list) + 4 * sizeof(eattr));
  struct ea_list *eal2 = xmalloc(sizeof(struct ea_list) + 5 * sizeof(eattr));

  init_ea_with_3eattr(eal1);
  struct nexthop_adata nhad = NEXTHOP_DEST_LITERAL(1357);
  eal1->attrs[3] = EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nhad.ad);
  eal1->attrs[3].originated = 1;
  eal1->count++;
  // ids are 4, 7, 6, 1 in this order

  nhad = NEXTHOP_DEST_LITERAL(13);
  eal2->attrs[0] = EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nhad.ad);
  eal2->attrs[0].originated = 0;
  eal2->attrs[1] = EA_LITERAL_EMBEDDED(&ea_gen_source, 0, 8765);
  eal2->attrs[2] = EA_LITERAL_EMBEDDED(&ea_gen_igp_metric, 0, 45);
  eal2->attrs[3] = EA_LITERAL_EMBEDDED(&ea_gen_mpls_policy, 0, 57);
  eal2->attrs[3].originated = 0;
  eal2->attrs[4] = EA_LITERAL_EMBEDDED(&ea_gen_preference, 0, 0);
  eal2->attrs[4].undef = 1;
  // ids are 1, 7, 5, 9, 4 in this order

  eal2->count = 5;
  eal2->next = eal1;

  struct ea_list *new_eal = ea_normalize(eal2, 0);

  if (new_eal->count != 5)
    return 0;

  eattr result[5];
  result[0] = eal2->attrs[0]; // id 1
  result[0].originated = 1;
  result[1] = eal2->attrs[2]; // id 5, eattr with id 4 was undefed
  result[2] = eal1->attrs[2]; // id 6
  result[3] = eal2->attrs[1]; // id 7
  result[3].originated = 1;
  result[4] = eal2->attrs[3]; // id 9


  for(uint i = 0; i < new_eal->count; i++)
    if (!(eattr_same_value2(&new_eal->attrs[i], &result[i]) &&
        new_eal->attrs[i].originated == result[i].originated &&
        new_eal->attrs[i].fresh == 0))
      return 0;

  if (new_eal->flags != EALF_SORTED)
    return 0;

  return 1;
}

static int
normalize_two_leave_last(void)
{
  struct ea_list *eal1 = xmalloc(sizeof(struct ea_list) + 4 * sizeof(eattr));
  struct ea_list *eal2 = xmalloc(sizeof(struct ea_list) + 5 * sizeof(eattr));
  struct ea_list *base = xmalloc(sizeof(struct ea_list) + 4 * sizeof(eattr));

  struct nexthop_adata nhad = NEXTHOP_DEST_LITERAL(13);
  base->attrs[0] = EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nhad.ad); // changes
  base->attrs[0].originated = 0;
  base->attrs[1] = EA_LITERAL_EMBEDDED(&ea_gen_source, 0, 8765);  // remains
  base->attrs[2] = EA_LITERAL_EMBEDDED(&ea_gen_mpls_policy, 0, 57); // will be set
  base->attrs[2].originated = 0;
  base->attrs[3].undef = 1;
  base->attrs[3] = EA_LITERAL_EMBEDDED(&ea_gen_preference, 0, 0); // remains unset (set ad unset)
  base->attrs[3].undef = 1;

  struct nexthop_adata nnnhad = NEXTHOP_DEST_LITERAL(31);
  eal1->attrs[0] = EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nnnhad.ad);
  eal1->attrs[1] = EA_LITERAL_EMBEDDED(&ea_gen_source, 0, 8765);
  eal1->attrs[2] = EA_LITERAL_EMBEDDED(&ea_gen_igp_metric, 0, 66);
  eal1->attrs[3] = EA_LITERAL_EMBEDDED(&ea_gen_preference, 0, 36);

  struct nexthop_adata nnhad = NEXTHOP_DEST_LITERAL(333);
  eal2->attrs[0] = EA_LITERAL_DIRECT_ADATA(&ea_gen_nexthop, 0, &nnhad.ad);
  eal2->attrs[1] = EA_LITERAL_EMBEDDED(&ea_gen_igp_metric, 0, 45);
  eal2->attrs[1].undef = 1;
  eal2->attrs[2] = EA_LITERAL_EMBEDDED(&ea_gen_mpls_policy, 0, 58);
  eal2->attrs[3] = EA_LITERAL_EMBEDDED(&ea_gen_preference, 0, 0);
  eal2->attrs[3].undef = 1;
  ip_addr dummy;
  dummy.addr[0] = 123;
  eal2->attrs[4] = EA_LITERAL_STORE_ADATA(&ea_gen_from, 0, &dummy, sizeof(ip_addr));

  eattr result[3];
  result[0] = eal2->attrs[0]; // 1
  result[1] = eal2->attrs[4]; // 6
  result[2] = eal2->attrs[2]; // 9

  base->count = 4;
  base->next = NULL;
  base = ea_lookup(base, 0, EALS_CUSTOM);

  eal1->count = 4;
  eal1->next = base;
  eal1->stored = 0;
  eal2->count = 5;
  eal2->next = eal1;
  eal2->stored = 0;

  struct ea_list *new_eal = ea_normalize(eal2, BIT32_ALL(EALS_CUSTOM));
  for(uint i = 0; i < new_eal->count; i++)
    log("two l %i ", new_eal->attrs[i].id);

  if (new_eal->count != 3)
    return 0;

  return 1;
  for(uint i = 0; i < new_eal->count; i++)
    if (!(eattr_same_value2(&new_eal->attrs[i], &result[i]) &&
        new_eal->attrs[i].originated == result[i].originated &&
        new_eal->attrs[i].fresh == 0))
      return 0;

  if (new_eal->flags != EALF_SORTED)
    return 0;

  return 1;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  rta_init();

  bt_test_suite(t_normalize_one_layer,		"One layer normalization");
  bt_test_suite(t_normalize_two_layers,		"Two layers normalization");
  bt_test_suite(normalize_two_leave_last,		"Two layers normalization with base layer");
  return bt_exit_value();
}

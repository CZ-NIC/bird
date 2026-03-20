#include <stdlib.h>
#include <stdint.h>


#include "nest/bird.h"


struct id_alloc_head {
  u32 *bitefield_free;
  u32 *bitefield_partial;
  u16 level;
  u16 num_free;
  u32 id;
  struct id_alloc_head* head_above;
  struct id_alloc_head **body;
  u32 bitefields_val[0];
};

struct id_alloc {
  int obj_size;
  u16 max_levels;
  u16 last_level_size;
  u32 max_objs;
  u32 max_ptrs;
  u32 obj_id_size;
  u32 ptr_id_size;
  pool *pool;
  struct id_alloc_head *ap;
};


#define ID_POS_ON_LEVEL(ia, ii, l)  (l == 0) ? (ii & ((1 << ia->obj_id_size) -1)) \
  : ((ii >> (ia->obj_id_size + ia->ptr_id_size * (l - 1))) & ((1 << ia->ptr_id_size) -1))

void
check(pool *pool)
{
  struct id_alloc *id_all = id_alloc_init(pool, 20);

  u32 ids[400];

  for (int i = 0; i < 400; i++)
    ASSERT_DIE(id_alloc_alloc(id_all, &ids[i]));

  for (int i = 0; i <200; i++)
  {
    id_alloc_free(id_all, ids[200+i]);
    id_alloc_free(id_all, ids[199-i]);
  }
  id_alloc_delete(id_all);


  id_all = id_alloc_init(pool, 20);


  for (int i = 0; i < 400; i++)
    ASSERT_DIE(id_alloc_alloc(id_all, &ids[i]));
  for (int i = 0; i <200; i++)
  {
    id_alloc_free(id_all, ids[i]);
  }
  for (int i = 0; i <200; i++)
  {
    ASSERT_DIE(id_alloc_alloc(id_all, &ids[i]));
  }

  for (int i = 0; i <200; i++)
  {
    id_alloc_free(id_all, ids[200+i]);
    id_alloc_free(id_all, ids[199-i]);
  }
  id_alloc_delete(id_all);
}

void
consistency_assert(struct id_alloc *id_all, struct id_alloc_head *h, u32 id, u32 pos)
{
  if (h->head_above)
    ASSERT_DIE(h->id == id + (pos<< (id_all->obj_id_size+ (id_all->ptr_id_size*(h->head_above->level-1)))));

  if (h->level == 0)
    return;

  int freed = 0;
  for (u32 i = 0; i < id_all->max_ptrs; i++)
  {
    if (!(h->bitefield_free[i/32] & 1<<(i%32)))
      consistency_assert(id_all, h->body[i], h->id, i);
    else
      freed++;
  }
  ASSERT_DIE(freed == h->num_free);
}

static u32
id_find_items_per_page(u32 item_size)
{
  int item_pp = (page_size - sizeof(struct id_alloc_head)) / item_size;
  int space_for_bitfields = ((item_pp / 32) + 1) * 2;

  while ((sizeof(struct id_alloc_head) + space_for_bitfields + item_pp * item_size) > (u64) page_size)
  {
    item_pp--;
    space_for_bitfields = item_pp / sizeof(void *) + 1;
  }
  return item_pp;
}

static u32
id_find_id_size(int items)
{
  /* Number of bits we need to encode all items in one page */
  u32 ret  = 1;
  while (items)
  {
    items = items >> 1;
    ret++;
  }
  if (items == 1 << (ret - 1))
    ret--;
  return ret;
}

/* Returns the position of first set bit in page bitmap */
static int
id_get_one_in_bitefield(u32 *bitefield, int len)
{
  for (int i = 0; i < len / 32 + !!(len % 32); i++) {
    if (bitefield[i])
    {
      int ret = u32_ctz(bitefield[i]) + (i * 32);
      if (ret < len)
        return ret;
    }
  }
  return -1;
}


/* Set bit on position pos to given value. */
static void
id_bitefield_set(u32 *bitefield, u32 pos, u32 val, struct id_alloc_head *ap)
{
  ASSERT_DIE((bitefield[pos/32] & (1 << (pos % 32))) != val);

  if (val)
  {
    bitefield[pos/32] += 1 << (pos % 32);
    if (ap->bitefield_free == bitefield)
      ap->num_free++;
  } else
  {
    bitefield[pos/32] -= 1 << (pos % 32);
    if (ap->bitefield_free == bitefield)
      ap->num_free--;
  }
}

static void
id_init_bitefields(struct id_alloc_head *ap, u32 max_items)
{
  int round = !! (max_items % 32);
  ap->bitefield_free = ap->bitefields_val;
  ap->bitefield_partial = ap->bitefields_val + (max_items / 32) + round;
  ap->body = (void*)(ap->bitefield_partial + (max_items / 32) + round);
  ap->num_free = max_items;

  u32 i = 0;
  for (; i < (max_items / 32); i++)
  {
    ap->bitefield_free[i] = ~0;
    ap->bitefield_partial[i] = 0;
  }
  if (round)
  {
    ap->bitefield_free[i] = (1 << (max_items % 32)) - 1;
    ap->bitefield_partial[i] = 0;
  }
}

struct id_alloc *
id_alloc_init(pool *pool, size_t obj_size)
{
  //if(obj_size==12)
  //  check(pool);
  struct id_alloc *id_all = mb_allocz(pool, sizeof(struct id_alloc));
  id_all->pool = pool;
  id_all->obj_size = obj_size;
  id_all->max_objs = id_find_items_per_page(obj_size);
  id_all->max_ptrs = id_find_items_per_page(sizeof(struct id_alloc_page *));
  id_all->obj_id_size = id_find_id_size(id_all->max_objs);
  id_all->ptr_id_size = id_find_id_size(id_all->max_ptrs);

  id_all->max_levels = (32 - id_all->obj_id_size) / id_all->ptr_id_size;

  if (id_all->obj_id_size + id_all->ptr_id_size * id_all->max_levels == 32)
    id_all->last_level_size = id_all->max_ptrs;
  else
  {
    id_all->max_levels++;
    id_all->last_level_size = 32 - id_all->obj_id_size + id_all->ptr_id_size * id_all->max_levels;
  }
  

  id_all->ap = alloc_page();
  id_init_bitefields(id_all->ap, id_all->max_objs);
  id_all->ap->level = 0;
  id_all->ap->id = 0;
  id_all->ap->head_above = NULL;

  return id_all;
}

void
id_alloc_delete(struct id_alloc* id_all)
{
  free_page(id_all->ap);
  mb_free(id_all);
}

static struct id_alloc_head *
id_alloc_put_head_above(struct id_alloc* id_all, struct id_alloc_head **cur_head_ptr)
{
  if (*cur_head_ptr == id_all->ap && id_all->ap->level == id_all->max_levels)
    bug("id_alloc run out of capacity");
  consistency_assert(id_all, id_all->ap, 0, 0);
  struct id_alloc_head *cur_head = *cur_head_ptr;
  struct id_alloc_head *head = alloc_page();

  if (*cur_head_ptr == id_all->ap && id_all->ap->level == id_all->max_levels)
    id_init_bitefields(head, id_all->last_level_size);
  else
    id_init_bitefields(head, id_all->max_ptrs);

  id_bitefield_set(head->bitefield_free, 0, 0, head);
  id_bitefield_set(head->bitefield_free, 1, 0, head);
  id_bitefield_set(head->bitefield_partial, 1, 1, head);

  if (cur_head->level == id_all->ap->level)
    head->level = cur_head->level + 1;
  else
    head->level = cur_head->head_above->level - 1;

  head->id = cur_head->id;
  head->body[0] = cur_head;
  head->head_above = cur_head->head_above;
  cur_head->head_above = head;
  *cur_head_ptr = head;

  head->body[1] = alloc_page();
  id_init_bitefields(head->body[1], id_all->max_objs);
  head->body[1]->level = 0;
  head->body[1]->id = head->id + (1 << (id_all->obj_id_size + (head->level -1) * id_all->ptr_id_size));
  ASSERT_DIE(ID_POS_ON_LEVEL(id_all, head->body[1]->id, head->level ) == 1);
  head->body[1]->head_above = head;

  ASSERT(id_all->ap->level > 0);
  consistency_assert(id_all, id_all->ap, 0, 0);
  return head->body[1];
}

void *
id_alloc_alloc(struct id_alloc* id_all, u32* id)
{
  struct id_alloc_head *cur_head = id_all->ap;
  consistency_assert(id_all, id_all->ap, 0, 0);

  if (cur_head->num_free == 0 && (cur_head->level == 0 ||
      id_get_one_in_bitefield(cur_head->bitefield_partial, id_all->max_ptrs) == -1))
    cur_head = id_alloc_put_head_above(id_all, &id_all->ap);

  while (cur_head->level > 0)
  {
    int pos = id_get_one_in_bitefield(cur_head->bitefield_partial, id_all->max_ptrs);

    if (pos >= 0)
    {
      ASSERT_DIE(cur_head->body[pos]->head_above == cur_head);
      if (cur_head->body[pos]->num_free || (cur_head->body[pos]->level &&
           id_get_one_in_bitefield(cur_head->body[pos]->bitefield_partial, id_all->max_ptrs) >= 0))
      {
        cur_head = cur_head->body[pos];
        ASSERT_DIE(cur_head);
        consistency_assert(id_all, id_all->ap, 0, 0);
      } else
      {
        /* more levels needed */
        ASSERT_DIE(cur_head->level > cur_head->body[pos]->level + 1);
        cur_head = id_alloc_put_head_above(id_all, &(cur_head->body[pos]));
        consistency_assert(id_all, id_all->ap, 0, 0);
      }
    } else if ((pos = id_get_one_in_bitefield(cur_head->bitefield_free, id_all->max_ptrs)) >= 0)
    {
      id_bitefield_set(cur_head->bitefield_partial, pos, 1, cur_head);
      id_bitefield_set(cur_head->bitefield_free, pos, 0, cur_head);
      struct id_alloc_head *head = alloc_page();
      id_init_bitefields(head, id_all->max_objs);
      cur_head->body[pos] = head;
      head->head_above = cur_head;
      head->level = 0;

      head->id = cur_head->id + (pos << (id_all->obj_id_size + ((cur_head->level -1) * id_all->ptr_id_size)));

      cur_head = head;
      consistency_assert(id_all, id_all->ap, 0, 0);
    }
    else
      ASSERT_DIE(false);
    
    consistency_assert(id_all, id_all->ap, 0, 0);
  }

  /* now we have head on level 0 which is not full */
  int pos = id_get_one_in_bitefield(cur_head->bitefield_free, id_all->max_objs);
  ASSERT_DIE(pos >= 0);
  void* ret = ((void *) cur_head->body) + (pos * id_all->obj_size);
  *id = cur_head->id + pos;
  consistency_assert(id_all, id_all->ap, 0, 0);
  id_bitefield_set(cur_head->bitefield_free, pos, 0, cur_head);
  consistency_assert(id_all, id_all->ap, 0, 0);

  while (cur_head->num_free == 0 && cur_head->head_above && cur_head->level +1 == cur_head->head_above->level
         && (cur_head->level == 0 || id_get_one_in_bitefield(cur_head->bitefield_partial, id_all->max_ptrs) == -1))
  {
    consistency_assert(id_all, id_all->ap, 0, 0);
    cur_head = cur_head->head_above;

    pos = ID_POS_ON_LEVEL(id_all, *id, cur_head->level);

    id_bitefield_set(cur_head->bitefield_partial, pos, 0, cur_head);
  }

  *id = *id + 1; /* Stupid trick - zero id should mean "no object". */
  ASSERT_DIE(id_alloc_find(id_all, *id) == ret);
  return ret;
}

void *
id_alloc_find(struct id_alloc * id_all, u32 id)
{
  ASSERT_DIE(id>0);
  id-=1;
  struct id_alloc_head *cur_head = id_all->ap;
  u32 pos;
  consistency_assert(id_all, id_all->ap, 0, 0);
  while (cur_head->level != 0)
  {
    pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
    cur_head = cur_head->body[pos];
  }

  pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
  ASSERT_DIE((cur_head->bitefield_free[pos / 32] & (1 << (pos % 32))) == 0);
  return ((void *)cur_head->body) + (pos * id_all->obj_size);
}

void
id_alloc_free(struct id_alloc * id_all, u32 id)
{
  ASSERT_DIE(id>0);
  id-=1;
  struct id_alloc_head *cur_head = id_all->ap;
  u32 pos;
  consistency_assert(id_all, id_all->ap, 0, 0);
  while (cur_head->level != 0)
  {
    pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);

    if ((cur_head->bitefield_partial[pos/32] & (1 << (pos % 32))) == 0)//        ASSERT_DIE((bitefield[pos/32] & (1 << (pos % 32))) != val);
    {
      /* the head is not in partial heads, it can not be in free heads, so it is considered to be full. 
       * One item will be freed, so we mark it in advance. */
      id_bitefield_set(cur_head->bitefield_partial, pos, 1, cur_head);
    }

    cur_head = cur_head->body[pos];
  }

  pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
  ASSERT_DIE(cur_head->id + pos == id);

  id_bitefield_set(cur_head->bitefield_free, pos, 1, cur_head);
  consistency_assert(id_all, id_all->ap, 0, 0);


  memset(((void *) cur_head->body) + (pos * id_all->obj_size), 0xfa, id_all->obj_size);


  if (cur_head->num_free != id_all->max_objs || cur_head == id_all->ap)
    return;

  /* the head is empty */
  do {
    struct id_alloc_head *old_head = cur_head;
    cur_head = cur_head->head_above;
    pos =  ID_POS_ON_LEVEL(id_all, id, cur_head->level);
    ASSERT_DIE(cur_head->body[pos] == old_head);

    free_page(old_head);
    id_bitefield_set(cur_head->bitefield_partial, pos, 0, cur_head);
    id_bitefield_set(cur_head->bitefield_free, pos, 1, cur_head);
  } while (cur_head != id_all->ap && cur_head->num_free == id_all->max_ptrs);

  consistency_assert(id_all, id_all->ap, 0, 0);
}


//todo vypisovani pameti, spravny pool atd

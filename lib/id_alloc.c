/*
 *	BIRD Resource Manager 
 *
 *	(c) 2026       Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Id allocator
 *
 * This allocator is based on slab principles (it allocates memory blocks of fixed size),
 * but it has one specific feature - each allocated block of memory recieves an 32 bit id.
 * This id can be used to find the allocated block and it is needed to free the block.
 * That makes possible to store only 32 bit ids instead of full pointers.
 * 
 * The allocator uses tree like struct of pages. The root page (if more pages present)
 * contains pointers to other pages. Those pages contain either pointers to other pages
 * or stored objects.
 * 
 * The id is composed of indexes of the pointers in the pages and index of the object itself.
 * The size of each part of the id depends on number of objects (and pointers) possible
 * to fit into one page. The ids internaly start with zero, but, because of having
 * zero id is not very handy, (id + 1) is returned instead.
 * 
 * Each head has two bitfields. bitfield_free bit is set if the corresponding place is
 * free. In pointer page, it indicates no valid pointer. In object page, free space for
 * storing object. bitfield_partial is relevant only to pointer pages. It indicates
 * existing subtree with at least one free space for object.
 * 
 * Storing object
 * Before storing the first object, we have only one inited page which is root. It is
 * empty object page. As all object page, it has level = 0. The greater level, the further
 * the page is (or can be) from its most distant child object page. The id of the page is
 * zero as well.
 * 
 * The first allocated object will have id 0 (page id + index = 0), but propagated to outside
 * as id 1. The number of free items and bit in bitfield_free will change.
 * 
 * It will be more interesting after the head is fulfilled. The next object will need new
 * page. First, pointer page is initiated and become new root. Its level is 1, its id is
 * zero and first pointer (on index 0) leads to the old root head. This way we can keep
 * the old head id, which is composed from its index and ids of heads above it.
 * 
 * Pointer in pointer head on index 1 leads to new object page. This page has
 * id = (1 << (space reserved for object part of id)). Its id is 0.
 * 
 * If a head with level 2 or more has no partial subtrees, but still have some free spaces
 * for new pointers, the first pointer space is used to allocate object page with level 0.
 * The partial_bitfield for that page remains 1 even after that page is fulfilled. If more
 * heads needed, we put the new (pointer) head between the old pointer head and object head.
 * 
 * Once a head (object or pointer) is fulfilled, the information propagates to its parent,
 * unsetting bitfield_partial.
 * 
 * Imagine we have tiny pages with space only for two pointers or two objects.
 * Inserting objects O with ids (id) into heads H named a, b, c... would look like this:
 * 
 * one head needed:
 * {Ha(0): O(0), O(1)}
 * 
 * two heads:
 *   {Hb(0)}----------------\
 *     |                     \
 * {Ha(0): O(0), O(1)}    {Hc(10): O(10), O(11))}
 * 
 * three:
 *      {Hd(0)}---------------------------------\
 *        |                                      \
 *    {Hb(0)}----------------\                    \
 *     |                      \                    \
 * {Ha(0): O(0), O(1)}    {Hc(10): O(10), O(11))}    {He(100): O(100), O(101)}
 * 
 * four:
 *      {Hd(0)}---------------------------------\
 *        |                                      \
 *    {Hb(0)}----------------\                 {Hf(100)}-----------------------\
 *     |                      \                    \                            \
 * {Ha(0): O(0), O(1)}    {Hc(10): O(10), O(11))}    {He(100): O(100), O(101)}   {Hg(110): O(110), O(111)}
 *
 * 
 * Freeing object:
 * As we walk the tree for the object to free, we set on all unset bits in bitefiel_partial bitfields
 * leading to the object. Free is done just by unsetting its  bit in bitfield_partial. If the head
 * is free now, we free the page (unless it is root) and propagate the information to the parent head.
*/

#include <stdlib.h>
#include <stdint.h>


#include "nest/bird.h"

#ifdef DEBUGGING
#define POISON		/* Poison all regions after they are freed */
#endif


struct id_alloc_head {
  u32 *bitfield_free; /* No object or pointer stored yet */
  u32 *bitfield_partial; /* Rerlevant only for pointer heads - free space somewhere in the subtree */
  u16 level; /* 0 for object pages, distance from furthest object page for pointer heads */
  u16 num_free; /* Number of set bites in bitfield_free */
  u32 id; /* Id composed from parent head id and index of the thead in parent */
  struct id_alloc_head* head_above; /* pointer to parent head */
  struct id_alloc_head **body; /* space for pointers or objects */
  u32 bitfields_val[0]; /* where bitfields are realy stored */
};

struct id_alloc {
  int obj_size;
  u16 max_levels;
  u16 last_level_size; /* We might have less space for the greatest level in 32 bit id */
  u32 max_objs; /* Max number of objects we fit into one page */
  u32 max_ptrs; /* Max number of pointers we fit into one page */
  u32 obj_id_size; /* Number of id bits needed to encode object index */
  u32 ptr_id_size; /* Number of id bits needed to encode pointer index */
  pool *pool;
  struct id_alloc_head *ap; /* root head */
};


#define ID_POS_ON_LEVEL(ia, ii, l)  (l == 0) ? (ii & ((1 << ia->obj_id_size) -1)) \
  : ((ii >> (ia->obj_id_size + ia->ptr_id_size * (l - 1))) & ((1 << ia->ptr_id_size) -1))


/* Only for testing purposes, maybe part of tests in future id_alloc_test.c */
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
    if (!(h->bitfield_free[i/32] & 1<<(i%32)))
      consistency_assert(id_all, h->body[i], h->id, i);
    else
      freed++;
  }
  ASSERT_DIE(freed == h->num_free);
}

/* Find out how many items can we fit into one page. More items means longer bitfields. */
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
id_get_one_in_bitfield(u32 *bitfield, int len)
{
  for (int i = 0; i < len / 32 + !!(len % 32); i++) {
    if (bitfield[i])
    {
      int ret = u32_ctz(bitfield[i]) + (i * 32);
      if (ret < len)
        return ret;
    }
  }
  return -1;
}


/* Set bit on position pos to given value. */
static void
id_bitfield_set(u32 *bitfield, u32 pos, u32 val, struct id_alloc_head *ap)
{
  /* Assert the current value differs from requested one. */
  ASSERT_DIE((bitfield[pos/32] & (1 << (pos % 32))) != val);

  if (val)
  {
    /* Setting to one */
    bitfield[pos/32] += 1 << (pos % 32);

    if (ap->bitfield_free == bitfield)
      ap->num_free++;
  } else
  {
    /* Setting to zero */
    bitfield[pos/32] -= 1 << (pos % 32);

    if (ap->bitfield_free == bitfield)
      ap->num_free--;
  }
}

static void
id_init_bitfields(struct id_alloc_head *ap, u32 max_items)
{
  int round = !! (max_items % 32); /* Find out if the last u32 of the bitfield will be full */
  ap->bitfield_free = ap->bitfields_val;
  ap->bitfield_partial = ap->bitfields_val + (max_items / 32) + round;
  ap->body = (void*)(ap->bitfield_partial + (max_items / 32) + round);
  ap->num_free = max_items;

  u32 i = 0;
  for (; i < (max_items / 32); i++)
  {
    ap->bitfield_free[i] = ~0; /* set to ones - everything is free now */
    ap->bitfield_partial[i] = 0;
  }
  if (round)
  {
    ap->bitfield_free[i] = (1 << (max_items % 32)) - 1; /* Let padding bits unset */
    ap->bitfield_partial[i] = 0;
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

  /* How many levels can we encde into 32 bit id. The head with greatest 
   * possible level might not be possible to fill up completely. */
  id_all->max_levels = (32 - id_all->obj_id_size) / id_all->ptr_id_size;

  if (id_all->obj_id_size + id_all->ptr_id_size * id_all->max_levels == 32)
    id_all->last_level_size = id_all->max_ptrs;
  else
  {
    id_all->max_levels++;
    id_all->last_level_size = 32 - id_all->obj_id_size + id_all->ptr_id_size * id_all->max_levels;
  }
  
  /* Root head. There is allways at least one head in id alloc */
  id_all->ap = alloc_page();
  id_init_bitfields(id_all->ap, id_all->max_objs);
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

/* This function is used for adding root head and for adding head between two heads
 * whose levels are more than one level apart. (This happens because alloc tries to
 * add next heads without adding unnecessary pointer heads) */
static struct id_alloc_head *
id_alloc_put_head_above(struct id_alloc* id_all, struct id_alloc_head **cur_head_ptr)
{
  if (*cur_head_ptr == id_all->ap && id_all->ap->level == id_all->max_levels)
    bug("id_alloc run out of capacity");
  //consistency_assert(id_all, id_all->ap, 0, 0);
  struct id_alloc_head *cur_head = *cur_head_ptr;
  struct id_alloc_head *head = alloc_page(); /* new pointer head */

  if (*cur_head_ptr == id_all->ap && id_all->ap->level == id_all->max_levels)
    id_init_bitfields(head, id_all->last_level_size); /* This might be the last level, which might be smaller */
  else
    id_init_bitfields(head, id_all->max_ptrs);

  id_bitfield_set(head->bitfield_free, 0, 0, head); /* space for old head*/
  id_bitfield_set(head->bitfield_free, 1, 0, head); /* space for new object head */
  id_bitfield_set(head->bitfield_partial, 1, 1, head); /* the new head will contain only one object */

  if (cur_head->level == id_all->ap->level)
    head->level = cur_head->level + 1; /* head is new root */
  else
    head->level = cur_head->head_above->level - 1; /* computing level for head in between two heads */

  head->id = cur_head->id; /* the head id must be the same as the id of the old head,
                            * because the old head is on index 0*/
  head->body[0] = cur_head;
  head->head_above = cur_head->head_above;
  cur_head->head_above = head;
  *cur_head_ptr = head;

  head->body[1] = alloc_page(); /* new object page */
  id_init_bitfields(head->body[1], id_all->max_objs);
  head->body[1]->level = 0;
  /* id of the new object head is parent id plus its index (1) shifted as it would be the on the greatest 
   * level we can put under the new pointer head. This make space for inserting a head in between if
   * pointer head is not level 1.*/
  head->body[1]->id = head->id + (1 << (id_all->obj_id_size + (head->level -1) * id_all->ptr_id_size));
  ASSERT_DIE(ID_POS_ON_LEVEL(id_all, head->body[1]->id, head->level ) == 1);
  head->body[1]->head_above = head;

  ASSERT(id_all->ap->level > 0);
  return head->body[1];
}

void *
id_alloc_alloc(struct id_alloc* id_all, u32* id)
{
  struct id_alloc_head *cur_head = id_all->ap;

  /* Is there any space in current page tree? */
  if (cur_head->num_free == 0 && (cur_head->level == 0 ||
      id_get_one_in_bitfield(cur_head->bitfield_partial, id_all->max_ptrs) == -1))
    cur_head = id_alloc_put_head_above(id_all, &id_all->ap);

  /* Look for suitable head on level 0 */
  while (cur_head->level > 0)
  {
    int pos = id_get_one_in_bitfield(cur_head->bitfield_partial, id_all->max_ptrs);

    if (pos >= 0)
    {
      /* We found subtree wit free space */
      ASSERT_DIE(cur_head->body[pos]->head_above == cur_head);
      if (cur_head->body[pos]->num_free || (cur_head->body[pos]->level &&
           id_get_one_in_bitfield(cur_head->body[pos]->bitfield_partial, id_all->max_ptrs) >= 0))
      {
        /* eveerything ok, we can continue */
        cur_head = cur_head->body[pos];
        ASSERT_DIE(cur_head);
      } else
      {
        /* The head below is actually full. That is because we skipped a level
         * (current level is greater than child level + 1.
         * The skipped level is needed now, lets insert missing page */
        ASSERT_DIE(cur_head->level > cur_head->body[pos]->level + 1);
        cur_head = id_alloc_put_head_above(id_all, &(cur_head->body[pos]));
      }
    } else if ((pos = id_get_one_in_bitfield(cur_head->bitfield_free, id_all->max_ptrs)) >= 0)
    {
      /* No partialy filled subtree. But since we got here, there must be a space for new */

      if (cur_head->level == id_all->max_levels && id_all->max_ptrs - cur_head->num_free == id_all->last_level_size)
        bug("id_alloc run out of capacity");
      id_bitfield_set(cur_head->bitfield_partial, pos, 1, cur_head);
      id_bitfield_set(cur_head->bitfield_free, pos, 0, cur_head);
      struct id_alloc_head *head = alloc_page();
      id_init_bitfields(head, id_all->max_objs);
      cur_head->body[pos] = head;
      head->head_above = cur_head;
      head->level = 0;

      head->id = cur_head->id + (pos << (id_all->obj_id_size + ((cur_head->level -1) * id_all->ptr_id_size)));

      cur_head = head;
    }
    else
      ASSERT_DIE(false);
  }

  /* now we have head on level 0 which is not full */
  int pos = id_get_one_in_bitfield(cur_head->bitfield_free, id_all->max_objs);
  ASSERT_DIE(pos >= 0);
  void* ret = ((void *) cur_head->body) + (pos * id_all->obj_size);
  *id = cur_head->id + pos;
  id_bitfield_set(cur_head->bitfield_free, pos, 0, cur_head);

  while (cur_head->num_free == 0 && cur_head->head_above && cur_head->level +1 == cur_head->head_above->level
         && (cur_head->level == 0 || id_get_one_in_bitfield(cur_head->bitfield_partial, id_all->max_ptrs) == -1))
  {
    /* The head is full, we need to propagate the info up */
    cur_head = cur_head->head_above;

    pos = ID_POS_ON_LEVEL(id_all, *id, cur_head->level);

    id_bitfield_set(cur_head->bitfield_partial, pos, 0, cur_head);
  }

  *id = *id + 1; /* Stupid trick - zero id should mean "no object". */

  return ret;
}

void *
id_alloc_find(struct id_alloc * id_all, u32 id)
{
  ASSERT_DIE(id > 0);
  id -= 1; /* Stupid trick - zero id should mean "no object". */
  struct id_alloc_head *cur_head = id_all->ap;
  u32 pos;
  //consistency_assert(id_all, id_all->ap, 0, 0);
  while (cur_head->level != 0)
  {
    pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
    cur_head = cur_head->body[pos];
  }

  pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
  ASSERT_DIE((cur_head->bitfield_free[pos / 32] & (1 << (pos % 32))) == 0);
  return ((void *)cur_head->body) + (pos * id_all->obj_size);
}

void
id_alloc_free(struct id_alloc * id_all, u32 id)
{
  ASSERT_DIE(id > 0);
  id -= 1; /* Stupid trick - zero id should mean "no object". */
  struct id_alloc_head *cur_head = id_all->ap;
  u32 pos;

  while (cur_head->level != 0)
  {
    pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);

    if ((cur_head->bitfield_partial[pos/32] & (1 << (pos % 32))) == 0)
    {
      /* the head is not in partial heads, it can not be in free heads, so it is considered to be full. 
       * One item will be freed, so we mark it in advance. */
      id_bitfield_set(cur_head->bitfield_partial, pos, 1, cur_head);
    }

    cur_head = cur_head->body[pos];
  }

  pos = ID_POS_ON_LEVEL(id_all, id, cur_head->level);
  ASSERT_DIE(cur_head->id + pos == id);

  id_bitfield_set(cur_head->bitfield_free, pos, 1, cur_head);

#ifdef POISON
  memset(((void *) cur_head->body) + (pos * id_all->obj_size), 0xfa, id_all->obj_size);
#endif

  if (cur_head->num_free != id_all->max_objs || cur_head == id_all->ap)
    return;

  /* The head is empty. We need to free it and pass the info to its parent.
   * If it was the onlz child, free it as well ect. Never free root. */
  do {
    struct id_alloc_head *old_head = cur_head;
    cur_head = cur_head->head_above;
    pos =  ID_POS_ON_LEVEL(id_all, id, cur_head->level);
    ASSERT_DIE(cur_head->body[pos] == old_head);

    free_page(old_head);
    id_bitfield_set(cur_head->bitfield_partial, pos, 0, cur_head);
    id_bitfield_set(cur_head->bitfield_free, pos, 1, cur_head);
  } while (cur_head != id_all->ap && cur_head->num_free == id_all->max_ptrs);
}


//todo vypisovani pameti, spravny pool atd

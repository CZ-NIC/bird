/*
 *	BIRD Resource Manager 
 *
 *	(c) 2026       Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Islab
 *
 * This allocator is based on slab principles (it allocates memory blocks of fixed size),
 * but it has one specific feature - each allocated block of memory recieves an 32 bit id.
 * This id can be used to find the allocated block and to free the block. That makes it
 * possible to store only 32 bit ids instead of full pointers.
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


struct islab_head {
  u32 *bitfield_free; /* No object or pointer stored yet */
  u32 *bitfield_partial; /* Rerlevant only for pointer heads - free space somewhere in the subtree */
  u32 id; /* Id composed from parent head id and index of the thead in parent */
  u16 level; /* 0 for object pages, distance from furthest object page for pointer heads */
  u16 num_free; /* Number of set bites in bitfield_free */
  struct islab_head* head_above; /* pointer to parent head */
  struct islab_head **body; /* space for pointers or objects */
  u32 bitfields_val[0]; /* where bitfields are realy stored */
};

struct islab {
  resource r;
  int obj_size;
  u16 max_levels;
  u16 last_level_size; /* We might have less space for the greatest level in 32 bit id */
  u32 max_objs; /* Max number of objects we fit into one page */
  u32 max_ptrs; /* Max number of pointers we fit into one page */
  u32 obj_id_size; /* Number of id bits needed to encode object index */
  u32 ptr_id_size; /* Number of id bits needed to encode pointer index */
  u32 obj_stored;
  u32 heads_stored;
  pool *pool;
  struct islab_head *ap; /* root head */
};

void isl_delete(resource *r);
static void islab_dump(struct dump_request *dreq, resource *r);
static struct resmem islab_memsize(resource *r);

static struct resclass islab_class = {
  .name = "Islab",
  .size = sizeof(struct islab),
  .free = isl_delete,
  .dump = islab_dump,
  .memsize = islab_memsize,
};


#define ISL_POS_ON_LEVEL(ia, ii, l)  (l == 0) ? (ii & ((1 << ia->obj_id_size) -1)) \
  : ((ii >> (ia->obj_id_size + ia->ptr_id_size * (l - 1))) & ((1 << ia->ptr_id_size) -1))

#define ISL_BITFIELD_IS_SET(b, p) (b[p/32] & (1 << (p%32)))

/* Only for testing purposes, maybe part of tests in future islab_test.c */
void
check(pool *pool)
{
  struct islab *isl = islab_init(pool, 20);

  void* bzs[400];
  u32 bz;

  for (int i = 0; i < 400; i++)
    ASSERT_DIE(bzs[i] = islab_alloc(isl, &bz));

  for (int i = 0; i <200; i++)
  {
    islab_free_ptr(isl, bzs[200+i]);
    islab_free_ptr(isl, bzs[199-i]);
  }
  islab_delete(isl);


  u32 ids[400];
  isl = islab_init(pool, 20);


  for (int i = 0; i < 400; i++)
    ASSERT_DIE(islab_alloc(isl, &ids[i]));
  for (int i = 0; i <200; i++)
  {
    islab_free(isl, ids[i]);
  }
  for (int i = 0; i <200; i++)
  {
    ASSERT_DIE(islab_alloc(isl, &ids[i]));
  }

  for (int i = 0; i <200; i++)
  {
    islab_free(isl, ids[200+i]);
    islab_free(isl, ids[199-i]);
  }
  islab_delete(isl);
}

void
consistency_assert(struct islab *isl, struct islab_head *h, u32 id, u32 pos)
{
  if (h->head_above)
    ASSERT_DIE(h->id == id + (pos << (isl->obj_id_size+ (isl->ptr_id_size*(h->head_above->level-1)))));

  if (h->level == 0)
    return;

  int freed = 0;
  for (u32 i = 0; i < isl->max_ptrs; i++)
  {
    if (!(ISL_BITFIELD_IS_SET(h->bitfield_free, i)))
      consistency_assert(isl, h->body[i], h->id, i);
    else
      freed++;
  }
  ASSERT_DIE(freed == h->num_free);
}

/* Find out how many items can we fit into one page. More items means longer bitfields. */
static u32
id_find_items_per_page(u32 item_size, bool obj_page)
{
  int item_pp = (page_size - sizeof(struct islab_head)) / item_size;
  int space_for_bitfields;

  if (obj_page)
    space_for_bitfields = ((item_pp / 32) + !!(item_pp % 32)) * 4;
  else
    space_for_bitfields = (((item_pp / 32) + !!(item_pp % 32)) * 2) * 4;

  while ((sizeof(struct islab_head) + space_for_bitfields + (item_pp * item_size)) > (u64) page_size)
  {
    item_pp--;
    if (obj_page)
      space_for_bitfields = ((item_pp / 32) + !!(item_pp % 32)) * 4;
    else
      space_for_bitfields = ((item_pp / 32) + !!(item_pp % 32)) * 2 * 4;
  }

  if (item_pp <= 2)
    bug("islab: objects are too big");
  //log("head %i, biffileds %i, item pp %i it size %i, pp*siz %i, page %i", sizeof(struct islab_head), space_for_bitfields,item_pp, item_size, item_pp * item_size, page_size);
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
id_bitfield_set(struct islab_head *ap, u32 *bitfield, u32 pos, u32 val)
{
  /* Assert the current value differs from requested one. */
  ASSERT_DIE(ISL_BITFIELD_IS_SET(bitfield, pos) != val);

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
id_init_bitfields(struct islab_head *ap, u32 max_items, bool is_obj)
{
  int round = !! (max_items % 32); /* Find out if the last u32 of the bitfield will be full */
  ap->bitfield_free = ap->bitfields_val;

  if (is_obj)
  {
    ap->bitfield_partial = NULL;
    ap->body = (void*)(ap->bitfields_val + (max_items / 32) + round);
  }
  else
  {
    ap->bitfield_partial = ap->bitfields_val + (max_items / 32) + round;
    ap->body = (void*)(ap->bitfield_partial + (max_items / 32) + round);
  }
  ap->num_free = max_items;

  u32 i = 0;
  for (; i < (max_items / 32); i++)
    ap->bitfield_free[i] = ~0; /* set to ones - everything is free now */

  if (round)
    ap->bitfield_free[i] = (1 << (max_items % 32)) - 1; /* Let padding bits unset */

  if (!is_obj)
  {
    for (i = 0; i < (max_items / 32) + round; i++)
      ap->bitfield_partial[i] = 0;
  }
}

struct islab *
islab_init(pool *pool, size_t obj_size)
{
  //if(obj_size==12)
  //  check(pool);
  struct islab *isl = ralloc(pool, &islab_class);
  isl->pool = pool;
  isl->obj_size = obj_size;
  isl->max_objs = id_find_items_per_page(obj_size, true);
  ASSERT_DIE(isl->max_objs > 1);
  isl->max_ptrs = id_find_items_per_page(sizeof(struct islab_page *), false);
  isl->obj_id_size = id_find_id_size(isl->max_objs);
  isl->ptr_id_size = id_find_id_size(isl->max_ptrs);

  /* How many levels can we encde into 32 bit id. The head with greatest 
   * possible level might not be possible to fill up completely. */
  isl->max_levels = (32 - isl->obj_id_size) / isl->ptr_id_size;

  if (isl->obj_id_size + isl->ptr_id_size * isl->max_levels == 32)
    isl->last_level_size = isl->max_ptrs;
  else
  {
    isl->max_levels++;
    isl->last_level_size = 32 - isl->obj_id_size + isl->ptr_id_size * isl->max_levels;
  }
  
  /* Root head. There is allways at least one head in islab */
  isl->ap = alloc_page();
  isl->heads_stored = 1;
  isl->ap->level = 0;
  isl->ap->id = 0;
  id_init_bitfields(isl->ap, isl->max_objs, true);
  isl->ap->head_above = NULL;

  return isl;
}

void
islab_delete(struct islab* isl)
{
  rfree(&isl->r);
}

void
isl_delete(resource *r)
{
  struct islab *isl = (struct islab *) r;
  free_page(isl->ap);
}


/* This function is used for adding root head and for adding head between two heads
 * whose levels are more than one level apart. (This happens because alloc tries to
 * add next heads without adding unnecessary pointer heads) */
static struct islab_head *
islab_put_head_above(struct islab* isl, struct islab_head **cur_head_ptr)
{
  if (*cur_head_ptr == isl->ap && isl->ap->level == isl->max_levels)
    bug("islab run out of capacity");
  //consistency_assert(isl, isl->ap, 0, 0);
  struct islab_head *cur_head = *cur_head_ptr;
  struct islab_head *head = alloc_page(); /* new pointer head */

  id_init_bitfields(head, isl->max_ptrs, false);

  id_bitfield_set(head, head->bitfield_free, 0, 0); /* space for old head*/
  id_bitfield_set(head, head->bitfield_free, 1, 0); /* space for new object head */
  id_bitfield_set(head, head->bitfield_partial, 1, 1); /* the new head will contain only one object */
  //log("head %p set %i put above", head, 1);

  if (cur_head->level == isl->ap->level)
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
  id_init_bitfields(head->body[1], isl->max_objs, true);
  head->body[1]->level = 0;
  /* id of the new object head is parent id plus its index (1) shifted as it would be the on the greatest 
   * level we can put under the new pointer head. This make space for inserting a head in between if
   * pointer head is not level 1.*/
  head->body[1]->id = head->id + (1 << (isl->obj_id_size + (head->level -1) * isl->ptr_id_size));
  ASSERT_DIE(ISL_POS_ON_LEVEL(isl, head->body[1]->id, head->level ) == 1);
  head->body[1]->head_above = head;

  isl->heads_stored += 2;
  ASSERT(isl->ap->level > 0);
  return head->body[1];
}

void *
islab_alloc(struct islab* isl, u32* id)
{
  struct islab_head *cur_head = isl->ap;
  ASSERT_DIE(!!(cur_head->bitfield_partial) == !!(cur_head->level));

  /* Is there any space in current page tree? */
  if (cur_head->num_free == 0 && (cur_head->level == 0 ||
      id_get_one_in_bitfield(cur_head->bitfield_partial, isl->max_ptrs) == -1))
    cur_head = islab_put_head_above(isl, &isl->ap);

  /* Look for suitable head on level 0 */
  while (cur_head->level > 0)
  {
    int pos = id_get_one_in_bitfield(cur_head->bitfield_partial, isl->max_ptrs);

    if (pos >= 0)
    {
      /* We found subtree with free space */
      ASSERT_DIE(cur_head->body[pos]->head_above == cur_head);
      if (cur_head->body[pos]->num_free || (cur_head->body[pos]->level &&
           id_get_one_in_bitfield(cur_head->body[pos]->bitfield_partial, isl->max_ptrs) >= 0))
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
        cur_head = islab_put_head_above(isl, &(cur_head->body[pos]));
      }
    } else if ((pos = id_get_one_in_bitfield(cur_head->bitfield_free, isl->max_ptrs)) >= 0)
    {
      /* No partialy filled subtree. But since we got here, there must be a space for new */

      if (cur_head->level == isl->max_levels && isl->max_ptrs - cur_head->num_free == isl->last_level_size)
        bug("islab run out of capacity");

      id_bitfield_set(cur_head, cur_head->bitfield_partial, pos, 1);
      //log("head %p set %i put below", cur_head, pos);
      id_bitfield_set(cur_head, cur_head->bitfield_free, pos, 0);
      struct islab_head *head = alloc_page();
      isl->heads_stored++;
      id_init_bitfields(head, isl->max_objs, true);
      cur_head->body[pos] = head;
      head->head_above = cur_head;
      head->level = 0;

      head->id = cur_head->id + (pos << (isl->obj_id_size + ((cur_head->level -1) * isl->ptr_id_size)));

      cur_head = head;
    }
    else
      ASSERT_DIE(false);
  }

  /* now we have head on level 0 which is not full */
  int pos = id_get_one_in_bitfield(cur_head->bitfield_free, isl->max_objs);
  ASSERT_DIE(pos >= 0);
  void* ret = ((void *) cur_head->body) + (pos * isl->obj_size);
  *id = cur_head->id + pos;
  id_bitfield_set(cur_head, cur_head->bitfield_free, pos, 0);

  while (cur_head->num_free == 0 && cur_head->head_above && cur_head->level +1 == cur_head->head_above->level
         && (cur_head->level == 0 || id_get_one_in_bitfield(cur_head->bitfield_partial, isl->max_ptrs) == -1))
  {
    /* The head is full, we need to propagate the info up */
    cur_head = cur_head->head_above;

    pos = ISL_POS_ON_LEVEL(isl, *id, cur_head->level);

    id_bitfield_set(cur_head, cur_head->bitfield_partial, pos, 0);
  }

  *id = *id + 1; /* Stupid trick - zero id should mean "no object". */
  isl->obj_stored++;

  return ret;
}

void *
islab_allocz(struct islab* isl, u32* id)
{
  void *ret = islab_alloc(isl, id);
  memset(ret, 0x0, isl->obj_size);
  return ret;
}

void *
islab_find(struct islab * isl, u32 id)
{
  ASSERT_DIE(id > 0);
  id -= 1; /* Stupid trick - zero id should mean "no object". */
  struct islab_head *cur_head = isl->ap;
  u32 pos;
  //consistency_assert(isl, isl->ap, 0, 0);
  while (cur_head->level != 0)
  {
    pos = ISL_POS_ON_LEVEL(isl, id, cur_head->level);
    cur_head = cur_head->body[pos];
  }

  pos = ISL_POS_ON_LEVEL(isl, id, cur_head->level);
  ASSERT_DIE(ISL_BITFIELD_IS_SET(cur_head->bitfield_free, pos) == 0);
  return ((void *)cur_head->body) + (pos * isl->obj_size);
}

static void
islab_free_empty_pages(struct islab * isl, struct islab_head *cur_head)
{
  if (cur_head->num_free != isl->max_objs || cur_head == isl->ap)
    return;

  ASSERT_DIE(cur_head->level == 0);
  u32 id = cur_head->id;

  /* The head is empty. We need to free it and pass the info to its parent.
   * If it was the only child, free it as well ect. Never free root. */
  do {
    struct islab_head *old_head = cur_head;
    cur_head = cur_head->head_above;
    u32 pos =  ISL_POS_ON_LEVEL(isl, id, cur_head->level);
    ASSERT_DIE(cur_head->body[pos] == old_head);

    free_page(old_head);
    isl->heads_stored--;
    id_bitfield_set(cur_head, cur_head->bitfield_partial, pos, 0);
    id_bitfield_set(cur_head, cur_head->bitfield_free, pos, 1);
  } while (cur_head != isl->ap && cur_head->num_free == isl->max_ptrs);

  if (cur_head == isl->ap && cur_head->num_free == isl->max_ptrs)
  {
    cur_head->level = 0;
    id_init_bitfields(cur_head, isl->max_objs, true);
  }
}

void
islab_free(struct islab * isl, u32 id)
{
  ASSERT_DIE(id > 0);
  id -= 1; /* Stupid trick - zero id should mean "no object". */
  struct islab_head *cur_head = isl->ap;
  u32 pos;

  while (cur_head->level != 0)
  {
    pos = ISL_POS_ON_LEVEL(isl, id, cur_head->level);

    if (ISL_BITFIELD_IS_SET(cur_head->bitfield_partial, pos) == 0)
    {
      /* the head is not in partial heads, it can not be in free heads, so it is considered to be full. 
       * One item will be freed, so we mark it in advance. */
      id_bitfield_set(cur_head, cur_head->bitfield_partial, pos, 1);
    }

    cur_head = cur_head->body[pos];
  }

  pos = ISL_POS_ON_LEVEL(isl, id, cur_head->level);
  ASSERT_DIE(cur_head->id + pos == id);

  id_bitfield_set(cur_head, cur_head->bitfield_free, pos, 1);

#ifdef POISON
  memset(((void *) cur_head->body) + (pos * isl->obj_size), 0xfa, isl->obj_size);
#endif

  islab_free_empty_pages(isl, cur_head);
  isl->obj_stored--;
}


/* Alternative way to free an allocated block without knowing its id. */
void
islab_free_ptr(struct islab *isl, void *ptr)
{
  struct islab_head *head = PAGE_HEAD(ptr);
  ASSERT_DIE(head->level == 0);
  uint off = ptr - ((void *) head->body);
  uint index = off / isl->obj_size;
  ASSERT_DIE(((void *)head->body) + (isl->obj_size * index) == ptr);

  #ifdef POISON
  memset(ptr, 0xdb, isl->obj_size);
  #endif

  id_bitfield_set(head, head->bitfield_free, index, 1);
  isl->obj_stored--;

  if (head->num_free == 1 && head->head_above && (head->level + 1 == head->head_above->level))
  {
    u32 id = head->id;

    bool cont;
    do {
      head = head->head_above;
      u32 pos = ISL_POS_ON_LEVEL(isl, id, head->level);
      cont = head->num_free == 0;
      cont = cont && (id_get_one_in_bitfield(head->bitfield_partial, isl->max_ptrs) == -1);
      id_bitfield_set(head, head->bitfield_partial, pos, 1);
    } while (cont && head != isl->ap && (head->level + 1 == head->head_above->level));

    return;
  }

  islab_free_empty_pages(isl, head);
}


static void
islab_dump_level(struct dump_request *dreq, struct islab *isl, struct islab_head *head, int off)
{
  /* Dump is done recursively, because not too much is levels expected */
  RDUMP("%*s (%x) head %p (id %x) bitfield free ", off, "", head->level, head, head->id);

  if (head->level == 0)
  {
    u32 obj_bitfield_len = (isl->max_objs / 32) + !!(isl->max_ptrs % 32);
    for (u32 i = 1; i <= obj_bitfield_len; i++)
      RDUMP("%x", head->bitfield_free[obj_bitfield_len - i]);
    return;
  }

  u32 ptr_bitfield_len = (isl->max_ptrs / 32) + !!(isl->max_ptrs % 32);
  for (u32 i = 1; i <= ptr_bitfield_len; i++)
    RDUMP("%x", head->bitfield_free[ptr_bitfield_len - i]);

  RDUMP(", bitfield partial ");

  for (u32 i = 1; i <= ptr_bitfield_len; i++)
    RDUMP("%x", head->bitfield_partial[ptr_bitfield_len - i]);

  for (u32 i = 0; i < isl->max_ptrs; i++)
  {
    if (ISL_BITFIELD_IS_SET(head->bitfield_free, i) == 0)
    {
      RDUMP("\n");
      struct islab_head *h = head->body[i];
      islab_dump_level(dreq, isl, h, off + ((head->level - h->level) * 10));
    }
  }
  RDUMP("\n");
}

static void
islab_dump(struct dump_request *dreq, resource *r)
{
  struct islab *isl = (struct islab *) r;

  RDUMP("\n");
  islab_dump_level(dreq, isl, isl->ap, dreq->indent+3);
}

long isl_empty = 0;
long isl_overhead = 0;
long isl_eff = 0;

static struct resmem
islab_memsize(resource *r)
{
  struct islab *isl = (struct islab *) r;

  isl_empty += isl->ap->num_free == isl->max_objs;
  isl_overhead += (isl->heads_stored * page_size) - (isl->obj_stored * isl->obj_size);
  isl_eff += isl->obj_stored * isl->obj_size;

  log("isl %p eff %li over %li heads %i objs %li obj siz %i (em %i e %li o %li)",isl, isl->obj_stored * isl->obj_size,
    (isl->heads_stored * page_size) - (isl->obj_stored * isl->obj_size), isl->heads_stored, isl->obj_stored, isl->obj_size, isl_empty, isl_eff, isl_overhead);

  return (struct resmem) {
    .effective = isl->obj_stored * isl->obj_size,
    .overhead = (isl->heads_stored * page_size) - (isl->obj_stored * isl->obj_size),
  };
}

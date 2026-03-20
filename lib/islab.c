/*
 *	BIRD Resource Manager -- Indexed slab-like Memory Allocator
 *
 *	(c) 2026       Katerina Kubecova <katerina.kubecova@nic.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

/**
 * DOC: Islab
 *
 * This allocator is based on slab principles (it allocates memory blocks of fixed size),
 * but it has one specific feature -- each allocated block of memory recieves a 32 bit ID.
 * That ID can be then used to find the allocated block and to free the block,
 * and vice versa, the block pointer can be resolved to an ID. That makes it
 * possible to store only 32 bit IDs instead of full pointers.
 * 
 * The allocator uses tree-like structure of pages, containing either pointers
 * to other pages or stored objects.
 * 
 * The id is composed of indexes of the pointers in the pages and index of the object itself.
 * The size of each part of the id depends on number of objects (and pointers) possible
 * to fit into one page. The ids internaly start with zero, but, because of having
 * zero id is not very handy, the API always passess (id + 1).
 *
 ******************
 * Object storage *
 ******************
 * 
 * The leaves of the tree are pages directly containing the allocated objects.
 * Every such page has a header |struct islab_head_obj| which contains
 * information about the allocated objects, and parent information.
 *
 * As soon as the objects grow out of the first page, an index page is allocated,
 * pointing to actual object pages. When an index page is full, another level
 * of index pages is added, etc.
 *
 ************
 * Indexing *
 ************
 *
 * Object IDs are composed from indexes into the pages. For outside, indexes
 * are incremented by one to avoid zero index.
 *
 * The object at zero index in the only page is therefore returned as 1,
 * object at index K is K+1.
 *
 * With index pages, the least significant bits are object index inside
 * the object page, and most significant bits are child index at the topmost tree level.
 *
 * Imagine we have tiny pages with space only for two pointers or two objects.
 * Inserting objects O with ids (binary id) into heads H named a, b, c... would look like this:
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
 */

#include <stdlib.h>
#include <stdint.h>

#include "nest/bird.h"

#ifdef DEBUGGING
#define POISON		/* Poison all regions after they are freed */
#endif

#if 0
#define ISLOG(x, ...)  log(L_DEBUG "%s:%d " x, __FILE__, __LINE__, __VA_ARGS__)
#else
#define ISLOG(...)
#endif


struct islab_head {
  char obj[0];			/* Actual objects; offset by size of bitfields */
  u16 level;			/* Level of this head (depth of subtree) */
  u16 ubindex;			/* Persistent index to used_bits */
  u16 num_free;			/* Number of free children (NULLs or unallocated) */
  u16 num_partial;		/* Number of partial children (for index pages) */
  u32 id;			/* Total ID of this head */
  struct islab_head *parent;	/* Parent head */
  u32 used_bits[0];		/* Object page: One for every available object.
				   Index page: One for every partial child. */
  struct islab_head *child[0];	/* Pointers to children; offset by size of bitfields */
};

struct islab {
  resource r;
  uint data_size;		/* Requested object size */
  uint obj_size;		/* Allocated object size (aligned) */
  uint max_objs;		/* Number of objects we fit into one page */
  uint max_ptrs;		/* Number of pointers we fit into one page */
  u8 obj_bits;			/* Bits needed to encode object index */
  u8 ptr_bits;			/* Bits needed to encode pointer index */
  u8 top_level_bits;		/* Index bit limit for the top level to fit into 32 bits */
  u8 max_levels;		/* Limit on nesting */
  u16 ptr_offset;		/* Pointer index offset (in items) to not collide with bitmaps */
  u16 obj_offset;		/* Object index offset (in bytes from the beginning of the page)
				   to not collide with bitmaps */
  u32 obj_stored;		/* Actual object storage count for statistics */
  u32 heads_stored;		/* Actual page count for statistics */
  struct islab_head *root;	/* Root head */
  struct islab_head *last;	/* Last head */
};

#define ISL_PTR_BITFIELD_LEN(isl)	(((isl)->max_ptrs + 31) / 32)
#define ISL_OBJ_BITFIELD_LEN(isl)	(((isl)->max_objs + 31) / 32)

/*
 * Resource and cleanup definitions
 **/

void
isl_delete(struct islab* isl)
{
  rfree(&isl->r);
}

static void
islab_free(resource *r)
{
  struct islab *isl = (struct islab *) r;
  ASSERT_DIE(!isl->heads_stored && !isl->obj_stored && !isl->root);
}

static void islab_dump(struct dump_request *dreq, resource *r);
static struct resmem islab_memsize(resource *r);

static struct resclass islab_class = {
  .name = "Islab",
  .size = sizeof(struct islab),
  .free = islab_free,
  .dump = islab_dump,
  .memsize = islab_memsize,
};

bool
isl_feasible(size_t size)
{
  return sl_obj_count(
      page_size,
      sizeof(struct islab_head),
      MAX(BIRD_ALIGN(size, CPU_STRUCT_ALIGN), sizeof (struct islab_head *)),
      1) >= 2;
}

struct islab *
isl_new(pool *pool, size_t size)
{
  struct islab *isl = ralloc(pool, &islab_class);

  /* Calculate object sizes */
  isl->data_size = size;
  isl->obj_size = BIRD_ALIGN(size, CPU_STRUCT_ALIGN);
  
  isl->max_objs = sl_obj_count(page_size, sizeof(struct islab_head), isl->obj_size, 1);
  isl->max_ptrs = sl_obj_count(page_size, sizeof(struct islab_head), sizeof (struct islab_head *), 1);

  if (isl->max_objs < 2)
    bug("Requested islab with size %u, page size %lu, can't fit objects",
	size, page_size);

  ASSERT_DIE(isl->max_ptrs >= 2);

  /* Calculate storage offsets */
  isl->obj_offset = BIRD_ALIGN(
      OFFSETOF(struct islab_head, used_bits)
      + ISL_OBJ_BITFIELD_LEN(isl) * sizeof (u32),
      CPU_STRUCT_ALIGN);

  isl->ptr_offset = (
      ISL_PTR_BITFIELD_LEN(isl) * sizeof (u32)
      + sizeof(struct islab_head *) - 1
      ) / sizeof (struct islab_head *);

  if (isl->max_objs > 0xffff)
    bug("iSlab: Inefficient page size %lu for item size %u",
	page_size, isl->data_size);

  if (isl->max_ptrs > 0xffff)
    bug("iSlab: Inefficient page size %lu for pointer size %u",
	page_size, sizeof (struct islab_head *));

  /* Calculate index bit lengths */
  isl->obj_bits = 32 - u32_clz(isl->max_objs - 1);
  isl->ptr_bits = 32 - u32_clz(isl->max_ptrs - 1);
  isl->max_levels = (32 - isl->obj_bits) / isl->ptr_bits;

  /* Top level bit limit with maximum nesting */
  isl->top_level_bits = 32 - isl->obj_bits - isl->ptr_bits * isl->max_levels;
  if (isl->top_level_bits == 0)
    isl->top_level_bits = isl->ptr_bits;
  else
    isl->max_levels++;

  /* Sanity checks for indexes and bitfields */
  ASSERT_DIE(((void *) (&isl->root->child[isl->ptr_offset]))
      > ((void *) (&isl->root->used_bits[(isl->max_ptrs-1) / 32])));
  ASSERT_DIE(((void *) (&isl->root->child[isl->ptr_offset + isl->max_ptrs]))
      <= ((void *) isl->root) + page_size);

  ASSERT_DIE(((void *) (&isl->root->obj[isl->obj_offset]))
      > ((void *) (&isl->root->used_bits[(isl->max_objs-1) / 32])));
  ASSERT_DIE(((void *) (&isl->root->obj[isl->obj_offset + isl->max_objs * isl->obj_size]))
      <= ((void *) isl->root) + page_size);

  return isl;
}


/*
 * Auxiliary functions
 */

/* Calculate object pointer from head-local index. */
static inline void *
isl_head_idx_to_ptr(const struct islab *isl, struct islab_head *cur, const u16 idx)
{
  return &(cur->obj[isl->obj_offset + idx * isl->obj_size]);
}

/*
 * isl_idx_on_level - object ID to index, levelled
 * @isl: islab
 * @id: full internal ID (external minus 1)
 * @level: level of that page in which we are indexing
 *
 * Calculate head index on the given level, from its ID.
 * This function extracts the appropriate bitrange. For example,
 * if obj_bits == 6 and ptr_bits == 9:
 *
 * 32      24        15         6      0 (LSB)
 * +++++++++++++++++++++++++++++++++++++
 * | ptr L3 | ptr L2  | ptr L1  | obj  |
 * +++++++++++++++++++++++++++++++++++++
 * */
static inline u16
isl_idx_on_level(const struct islab *isl, const u32 id, const uint level)
{
  if (level)
  {
    /* Level 1 = cut out the ptr L1 index. */
    uint idx = (id >> (isl->obj_bits + isl->ptr_bits * (level - 1)))
      & ((1 << isl->ptr_bits) - 1);
    ASSERT_DIE(idx < isl->max_ptrs);
    return idx;
  }
  else
  {
    /* Level is zero, cut out the object index */
    uint idx = id & ((1 << isl->obj_bits) - 1);
    ASSERT_DIE(idx < isl->max_objs);
    return idx;
  }
}

/*
 * Allocation
 */

/**
 * isl_alloc_obj_page - allocate level-zero page for objects
 * @isl: islab
 * @parent: parent head, NULL for first page
 * @idx: index in the parent head
 *
 * Returns an allocated head, initialized, assigned to parent.
 */
static struct islab_head *
isl_alloc_obj_page(struct islab *isl, struct islab_head *parent, uint idx)
{
  /* Allocate and initialize */
  struct islab_head *head = alloc_page();
  memset(head, 0, sizeof (struct islab_head) + ISL_OBJ_BITFIELD_LEN(isl) * sizeof (u32));
  isl->heads_stored++;

  head->num_free = isl->max_objs;

  if (!parent)
  {
    ISLOG("New root object page %p for isl %p",
	head, isl);
  
    /* ID is zero for the first page */
    ASSERT_DIE(!isl->root);
    return isl->root = head;
  }

  /* Derive ID and store in parent. Beware, the parent level
   * is significant, we may be skipping some levels here, and if that happens,
   * it is expected that there are virtual empty index pages where this page
   * is at index-zero position. Therefore, the ID of this page puts the
   * index in the parent into the position relative to the parent level,
   * not to this page. */
  ASSERT_DIE(parent->level > 0);
  ASSERT_DIE((parent->id & ((1 << (isl->obj_bits + isl->ptr_bits * (parent->level))) - 1)) == 0);

  head->parent = parent;
  head->id = parent->id + (idx << (isl->obj_bits + isl->ptr_bits * (parent->level - 1)));

  ISLOG("New object page %p for isl %p, id %x, parent %p, index %u",
	head, isl, head->id, parent, idx);

  /* This page is becoming partial, and we have to mark it as partial here.
   * No need to bubble up. */
  ASSERT_DIE(!BIT32_TEST(parent->used_bits, idx));
  BIT32_SET(parent->used_bits, idx);
  ISLOG("set bit pg %p id %u", parent, idx);

  /* Update free/partial counters */
  ASSERT_DIE(parent->num_free);
  ASSERT_DIE(parent->num_free <= isl->max_ptrs);
  parent->num_free--;

  ASSERT_DIE(parent->num_partial < isl->max_ptrs);
  parent->num_partial++;

  /* Store the child pointer and we're done */
  ASSERT_DIE(!parent->child[idx + isl->ptr_offset]);
  return parent->child[idx + isl->ptr_offset] = head;
}

/**
 * isl_alloc_index_page - allocate a new index page
 * @isl: islab
 * @child: the page's first child
 *
 * There are places in the tree where links skip a level. We need
 * to insert an index page into one of that place, directly above
 * the given child.
 *
 * The new page will replace the original child in the parent pointer
 * array, and the original child becomes the node zero of this new page.
 *
 * Examples:
 *
 * Before:  [ L2 page ID (7, 0, 0, 0) ] --> [ L0 page ID (7, 42, 0, 0) ]
 * After:  [ L2 page ID (7, 0, 0, 0) ] --> [ L1 page ID (7, 42, 0, 0) ] --> [ L0 page ID (7, 42, 0, 0) ]
 *
 * Before:  [ L3 page ID (0, 0, 0, 0) ] --> [ L0 page ID (67, 0, 0, 0) ]
 * After:  [ L3 page ID (0, 0, 0, 0) ] --> [ L1 page ID (67, 0, 0, 0) ] --> [ L0 page ID (67, 0, 0, 0) ]
 *
 * Returns the new index head.
 */
static struct islab_head *
isl_alloc_index_page(struct islab *isl, struct islab_head *child)
{
  /* Allocate and initialize */
  struct islab_head *mid = alloc_page();
  memset(mid, 0, page_size);
  isl->heads_stored++;

  /* ID stays the same as the child ID */
  mid->id = child->id;

  /* Level is always just above child */
  mid->level = child->level + 1;

  /* Check for ID overflow */
  if (mid->level > isl->max_levels)
    bug("iSlab for data size %u with page size %lu has run out of capacity at %u items",
	isl->data_size, page_size, isl->obj_stored);

  /* The child node is considered full, others are free */
  ASSERT_DIE(!child->num_free);
  mid->num_free = isl->max_ptrs - 1;

  /* Setup the pointers from here */
  struct islab_head *parent = mid->parent = child->parent;
  mid->child[0 + isl->ptr_offset] = child;

  /* Setup pointer from child */
  child->parent = mid;

  /* Setup pointer from parent */
  if (parent)
  {
    uint idx = isl_idx_on_level(isl, child->id, parent->level);
    ASSERT_DIE(parent->child[idx + isl->ptr_offset] == child);
    parent->child[idx + isl->ptr_offset] = mid;

    /* Check parent bits */
    ASSERT_DIE(BIT32_TEST(parent->used_bits, idx));
  }
  else
  {
    /* Replacing root node */
    ASSERT_DIE(child == isl->root);
    isl->root = mid;
  }

  ISLOG("New index page %p for isl %p, id %x, parent %p, child %p",
	mid, isl, mid->id, parent, child);
  return mid;
}

/* 
 * isl_find_bit - find some bit in used_bits with the specified value
 * @cur: the head
 * @limit: maximum bit index
 * @one: one to look for one, zero to look for zero
 *
 * Returns position of some bit in used_bits with that value.
 * Uses |ubindex| to keep last search index because often the next bit
 * available is just the next one.
 */
static uint
isl_find_bit(struct islab_head *cur, const uint limit, bool one)
{
  u16 orig = cur->ubindex;
  while (true) {
    while (cur->used_bits[cur->ubindex] + 1 == one)
    {
      cur->ubindex++;
      if (cur->ubindex * 32 >= limit)
	cur->ubindex = 0;
      if (cur->ubindex == orig)
	bug("iSlab has inconsistent bitfield");
    }

    uint pos = cur->ubindex * 32 + (one
      ? u32_ctz(cur->used_bits[cur->ubindex])
      : u32_ctz(~cur->used_bits[cur->ubindex]));

    if (pos >= limit)
    {
      cur->ubindex = 0;
      continue;
    }

    ASSERT_DIE(!BIT32_TEST(cur->used_bits, pos) == !one);
    return pos;
  }
}

/**
 * isl_head_full - the given head has become full
 * @isl: islab
 * @cur: the head which has been allocated from
 *
 * When allocating, the head may have become full,
 * and transitively all its parents as well.
 */
static void
isl_head_full(struct islab *isl, struct islab_head *cur)
{
  /* Check the parent */
  struct islab_head *parent = cur->parent;

  /* Top of the tree */
  if (!parent)
    return;

  /* Level skip means that we can add an index page inbetween,
   * this subtree therefore stays partial for the parent even though
   * it considers itself full. */
  if (parent->level > cur->level + 1)
    return;

  /* Sanity check */
  ASSERT_DIE(parent->level == cur->level + 1);

  /* We expect that this page has been partial before,
   * otherwise there is something weird. Now this page
   * is becoming full. */
  uint pidx = isl_idx_on_level(isl, cur->id, parent->level);

  ASSERT_DIE(BIT32_TEST(parent->used_bits, pidx));
  BIT32_CLR(parent->used_bits, pidx);
  ISLOG("clear bit pg %p id %u", cur, pidx);

  ASSERT_DIE(parent->num_partial);
  ASSERT_DIE(parent->num_partial <= isl->max_ptrs);
  parent->num_partial--;

  /* Rinse and repeat for the parent. */
  if (parent->num_partial + parent->num_free == 0)
    return isl_head_full(isl, parent);
}

/**
 * isl_alloc_from_head - allocate from the given head
 * @isl: islab
 * @cur: the head
 *
 * This auxiliary function expects a head with non-zero |num_free|,
 * and does just the allocation of one block.
 *
 * Returns the block information structure.
 */
static struct isl_block
isl_alloc_from_head(struct islab *isl, struct islab_head *cur)
{
  ASSERT_DIE(!cur->level);

  /* Find a free object */
  uint next = isl_find_bit(cur, isl->max_objs, 0);

  /* Check consistency */
  if (next >= isl->max_objs)
    bug("iSlab bitfield search returned %u with max %u", next, isl->max_objs);

  ISLOG("Alloc from head %p of isl %p, id %x, idx %u, total id %x, free %d",
      cur, isl, cur->id, next, (cur->id | next) + 1, cur->num_free - 1);

  /* Mark used */
  if (!--cur->num_free)
    isl_head_full(isl, cur);

  ASSERT_DIE(!BIT32_TEST(cur->used_bits, next));
  BIT32_SET(cur->used_bits, next);
  ISLOG("set bit pg %p id %u", cur, next);

  /* Keep track */
  isl->last = cur;
  isl->obj_stored++;

  /* Calculate public index and return */
  return (struct isl_block) {
    .id = (cur->id | next) + 1,
    .ptr = isl_head_idx_to_ptr(isl, cur, next),
  };
}

/**
 * isl_alloc - allocate from islab
 * @isl: islab
 *
 * Returns an allocated block together with its ID.
 *
 * When the last page is unavailable for allocation, we look for another one.
 * We walk the tree up until we leave the subtree which is completely full,
 * and then we look for partial heads and subtrees until we get to some pages
 * where free space still exists.
 *
 * In various cases, it's needed to allocate a new page, either just
 * an object page, or even an index page. This function identifies and handles
 * such cases.
 */
struct isl_block
isl_alloc(struct islab *isl)
{
  /* Try the last head */
  struct islab_head *cur = isl->last;

  /* Allocate from last page if available */
  if (cur && cur->num_free)
    return isl_alloc_from_head(isl, cur);

  /* No head exists, actually. Create one. */
  if (!isl->root)
  {
    ASSERT_DIE(!cur);
    return isl_alloc_from_head(isl, isl_alloc_obj_page(isl, NULL, 0));
  }

  /* Add level if root is full */
  if (isl->root->num_free + isl->root->num_partial == 0)
    return isl_alloc_from_head(isl, isl_alloc_obj_page(isl, isl_alloc_index_page(isl, isl->root), 1));

  /* Starting from root node down */
  cur = isl->root;

  /* Store previous for level insertion */
  struct islab_head *prev = NULL;

  /* Walk down partial children */
  while (cur->num_partial)
  {
    /* Consistency check */
    ASSERT_DIE(cur->level);
    ASSERT_DIE(!prev || prev->level > cur->level);

    /* Find a partial child */
    uint next = isl_find_bit(cur, isl->max_ptrs, 1);

    /* Move to that partial child */
    prev = cur;
    cur = cur->child[next + isl->ptr_offset];
    continue;
  }

  /* What if his child is actually full */
  if (!cur->num_free)
  {
    /* We must have just skipped a level */
    if (prev->level == cur->level + 1)
      bug("iSlab inconsistent bitmap with children availability");

    return isl_alloc_from_head(isl, isl_alloc_obj_page(isl, isl_alloc_index_page(isl, cur), 1));
  }

  /* Found an object page with free items! */
  if (!cur->level)
    return isl_alloc_from_head(isl, cur);

  /* Need to allocate an object page but where?
     Start searching just after |ubindex|, there will be probably free space.
     The top limit may be shortened for the toplevel page */
  uint mp = isl->max_ptrs;
  if ((cur->level == isl->max_levels) && (mp >> isl->top_level_bits))
    mp = (1 << isl->top_level_bits);

  uint start = (cur->ubindex * 32) % mp;
  for (uint ii = 0, i = start;
      ii < mp;
      i = (++ii + start) % mp)
    if (!cur->child[i + isl->ptr_offset])
    {
      cur->ubindex = i / 32;
      return isl_alloc_from_head(isl, isl_alloc_obj_page(isl, cur, i));
    }

  bug("iSlab inconsistent tree, no available children");
}

/**
 * isl_allocz - allocate from islab, pre-zeroed
 * @isl: islab
 *
 * Returns an allocated block together with its ID, zeroed.
 */
struct isl_block
isl_allocz(struct islab *isl)
{
  struct isl_block ret = isl_alloc(isl);
  memset(ret.ptr, 0, isl->obj_size);
  return ret;
}


/*
 * Resolving block information
 */

struct isl_block_info {
  struct islab_head *head;	/* The head where the block belongs */ 
  uint idx;			/* Its index in the head */
  u32 full_id;			/* Full external ID */
  void *ptr;			/* Final pointer */
};

/**
 * isl_info_id - internal object id resolver
 */
static struct isl_block_info
isl_info_id(const struct islab *isl, u32 id)
{
  /* Reduce ID by one for internal representation */
  ASSERT_DIE(id-- > 0);

  /* Walk heads down from root */
  struct islab_head *cur = isl->root;
  while (cur->level)
    cur = cur->child[isl_idx_on_level(isl, id, cur->level) + isl->ptr_offset];

  /* Now at the bottom, resolve the final object pointer */
  uint idx = isl_idx_on_level(isl, id, 0);
  ASSERT_DIE(BIT32_TEST(cur->used_bits, idx));

  return (struct isl_block_info) {
    .head = cur,
    .idx = idx,
    .full_id = id,
    .ptr = isl_head_idx_to_ptr(isl, cur, idx),
  };
}

/**
 * isl_info_ptr - internal object pointer resolver
 */
static struct isl_block_info
isl_info_ptr(const struct islab *isl, void *ptr)
{
  /* Resolve the head */
  struct islab_head *head = PAGE_HEAD(ptr);
  ASSERT_DIE(!head->level);

  /* Resolve the object offset */
  uint off = (const char *) ptr - head->obj - isl->obj_offset;
  ASSERT_DIE(off % isl->obj_size == 0);

  uint idx = off / isl->obj_size;
  ASSERT_DIE(BIT32_TEST(head->used_bits, idx));

  return (struct isl_block_info) {
    .head = head,
    .idx = idx,
    .full_id = (head->id | idx) + 1,
    .ptr = ptr,
  };
}

/**
 * isl_find_id - resolve an object ID to pointer
 * @isl: islab
 * @id: object id
 *
 * For an already allocated object ID, this returns its pointer,
 * so that one may store just IDs and not pointers.
 */
void *
isl_find_id(const struct islab *isl, u32 id)
{
  return isl_info_id(isl, id).ptr;
}

/**
 * isl_find_ptr - resolve an object pointer to its ID
 * @isl: islab
 * @ptr: object pointer
 *
 * For a pointer, return back its ID. The caller must be sure
 * that the pointer is indeed owned by the islab in question.
 */
u32
isl_find_ptr(const struct islab *isl, void *ptr)
{
  return isl_info_ptr(isl, ptr).full_id;
}


/*
 * Freeing objects
 */

/**
 * isl_head_empty - head is completely empty
 * @isl: islab
 * @cur: the head which has become empty
 *
 * When freeing, the head may have become empty,
 * and transitively all its parents as well.
 */
static void
isl_head_empty(struct islab *isl, struct islab_head *cur)
{
  struct islab_head *parent = cur->parent;

  ISLOG("Head %p in isl %p empty, parent %p, islast %p",
      cur, isl, parent, isl->last);

  /* Check for trailing last pointer */
  if (cur == isl->last)
    isl->last = NULL;

  /* The last page standing */
  if (!parent)
  {
    ASSERT_DIE(cur == isl->root);
    isl->root = NULL;

#ifdef POISON
    memset(cur, 0xde, page_size);
#endif
    free_page(cur);

    ASSERT_DIE(--isl->heads_stored == 0);
    return;
  }

  /* Get index in the parent head */
  ASSERT_DIE(parent->level > cur->level);
  uint pidx = isl_idx_on_level(isl, cur->id, parent->level);

  /* Drop pointer from parent */
  ASSERT_DIE(parent->child[pidx + isl->ptr_offset] == cur);
  parent->child[pidx + isl->ptr_offset] = NULL;

  /* Free the page */
#ifdef POISON
  memset(cur, 0xd1, page_size);
#endif
  free_page(cur);
  ASSERT_DIE(--isl->heads_stored > 0);

  /* Unset bit in parent */
  ASSERT_DIE(BIT32_TEST(parent->used_bits, pidx));
  BIT32_CLR(parent->used_bits, pidx);
  ISLOG("clear bit pg %p id %u", parent, pidx);

  ASSERT_DIE(parent->num_partial);
  ASSERT_DIE(parent->num_partial <= isl->max_ptrs);
  parent->num_partial--;

  ASSERT_DIE(parent->num_free < isl->max_ptrs);
  parent->num_free++;

  /* The parent head is also completely empty, continue with that */
  if (parent->num_free == isl->max_ptrs)
  {
    ASSERT_DIE(parent->num_partial == 0);
    isl_head_empty(isl, parent);
  }
}

/**
 * isl_head_partial - head has become partial by freeing
 * @isl: islab
 * @cur: the head which has become partial
 *
 * When freeing, a full head may become partial,
 * and transitively all its parents as well.
 */
static void
isl_head_partial(struct islab *isl, struct islab_head *cur)
{
  struct islab_head *parent = cur->parent;
  ISLOG("head %p is partial in isl %p, id %u", cur, isl, cur->id);

  /* No propagation beyond root */
  if (!parent)
    return;

  /* Get index in the parent head */
  ASSERT_DIE(parent->level > cur->level);
  uint pidx = isl_idx_on_level(isl, cur->id, parent->level);

  if (parent->level > cur->level + 1)
  {
    /* There is a gap, we are already marked as partial in the (grand)parent */
    ASSERT_DIE(BIT32_TEST(parent->used_bits, pidx));
    return;
  }

  /* Set bit in parent */
  ASSERT_DIE(!BIT32_TEST(parent->used_bits, pidx));
  BIT32_SET(parent->used_bits, pidx);
  ISLOG("set bit pg %p id %u", parent, pidx);

  /* The parent head was full, continue up */
  if (parent->num_partial + parent->num_free == 0)
    isl_head_partial(isl, parent);

  /* Update counter */
  ASSERT_DIE(parent->num_partial < isl->max_ptrs);
  parent->num_partial++;
}

static void
isl_free_info(struct islab *isl, struct isl_block_info i)
{
  ISLOG("Free to head %p of isl %p, id %x, idx %u, total id %x, free %d",
      i.head, isl, i.head->id, i.idx, i.full_id, i.head->num_free);

  /* Clear used bit; checked when fetching info */
  BIT32_CLR(i.head->used_bits, i.idx);
  ISLOG("clear bit pg %p id %u", i.head, i.idx);

#ifdef POISON
  memset(i.ptr, 0xfa, isl->obj_size);
#endif

  /* Update free counts */
  ASSERT_DIE(i.head->num_free < isl->max_objs);
  if (!i.head->num_free)
    isl_head_partial(isl, i.head);

  i.head->num_free++;
  isl->obj_stored--;

  if (i.head->num_free == isl->max_objs)
    isl_head_empty(isl, i.head);
}

 
/**
 * isl_free_id - free an object identified by an ID
 * @isl: islab
 * @id: allocated object ID
 *
 * The object stops existing after this call, and the resolved pointers as well.
 */
void
isl_free_id(struct islab *isl, u32 id)
{
  isl_free_info(isl, isl_info_id(isl, id));
}

/**
 * isl_free_ptr - free an object identified by its pointer
 * @isl: islab
 * @ptr: object to free
 *
 * The object stops existing after this call, and its ID as well.
 */
void
isl_free_ptr(struct islab *isl, void *ptr)
{
  isl_free_info(isl, isl_info_ptr(isl, ptr));
}


/*
 * Dumping info
 */

static void
islab_dump_level(struct dump_request *dreq, struct islab *isl, struct islab_head *head)
{
  if (!head)
    return;

  /* Dump is done recursively. Can't have more than 32 levels. */
  RDUMP("%*s (%u) head %p (id %x) ubindex=%u free=%u partial=%u used_bits ",
      dreq->offset + (isl->root->level - head->level + 1)*3, "",
      head->level, head, head->id, head->ubindex, head->num_free, head->num_partial);

  uint blen = head->level ? ISL_PTR_BITFIELD_LEN(isl) : ISL_OBJ_BITFIELD_LEN(isl);

  for (u32 i = 1; i <= blen; i++)
    RDUMP("%08x", head->used_bits[blen - i]);

  RDUMP("\n");
  if (!head->level)
    return;

  for (u32 i = 0; i < isl->max_ptrs; i++)
    islab_dump_level(dreq, isl, head->child[i + isl->ptr_offset]);
}

static void
islab_dump(struct dump_request *dreq, resource *r)
{
  struct islab *isl = (struct islab *) r;

  RDUMP("[ds=%u, os=%u, omax=%u, pmax=%u, obits=%u, pbits=%u, tlb=%u, lmax=%u, poff=%u, ooff=%u] %u objects, %u heads\n",
      isl->data_size, isl->obj_size, isl->max_objs, isl->max_ptrs, isl->obj_bits, isl->ptr_bits,
      isl->top_level_bits, isl->max_levels, isl->ptr_offset, isl->obj_offset, isl->obj_stored, isl->heads_stored);

  islab_dump_level(dreq, isl, isl->root);
}

static struct resmem
islab_memsize(resource *r)
{
  struct islab *isl = (struct islab *) r;

  return (struct resmem) {
    .effective = isl->obj_stored * isl->data_size,
    .overhead = ALLOC_OVERHEAD + sizeof(struct islab)
      + (isl->heads_stored * page_size) - (isl->obj_stored * isl->data_size),
  };
}

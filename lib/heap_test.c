/*
 *	BIRD Library -- Universal Heap Macros Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/heap.h"

#define MAX_NUM 1000
#define SPECIAL_KEY -3213

#define MY_CMP(x, y) ((x) < (y))

#define MY_HEAP_SWAP(heap,a,b,t)		\
    do {					\
      bt_debug("swap(%d %d) ", a, b);		\
      HEAP_SWAP(heap,a,b,t);			\
    } while(0)

static int num;
static int heap[MAX_NUM+1];

#define SHOW_HEAP(heap) 			\
    do {					\
      uint _i; 					\
      bt_debug("\nnum = %d; ", num);		\
      for(_i = 1; _i <= num; _i++)		\
	bt_debug("%d ", heap[_i]);		\
      if(is_heap_valid(heap, num))		\
	 bt_debug("OK \n");			\
      else					\
	bt_debug("NON-VALID HEAP! \n");		\
    } while(0)

static int
is_heap_valid(int heap[], uint num)
{
 /*
  * A valid heap must follow these rules:
  *   - `num >= 0`
  *   - `heap[i] >= heap[i / 2]` for each `i` in `[2, num]`
  */

  if(num < 0)
    return 0;

  int i;
  for(i = 2; i <= num; i++)
    if(heap[i] < heap[i / 2])
      return 0;

  return 1;
}

static void
init_heap(void)
{
  int i;
  num = 0;
  heap[0] = SPECIAL_KEY;		/* heap[0] should be unused */
  for(i = 1; i <= MAX_NUM; i++)
    heap[i] = 0;
}

static int
t_heap_insert(void)
{
  init_heap();

  int i;
  for(i = 1; i <= MAX_NUM; i++)
  {
    bt_debug("ins %d at pos %d ", MAX_NUM - i, i);
    heap[i] = MAX_NUM - i;
    HEAP_INSERT(heap, ++num, int, MY_CMP, MY_HEAP_SWAP);
    SHOW_HEAP(heap);
    bt_assert(is_heap_valid(heap, num));
  }

  return BT_SUCCESS;
}

static int
t_heap_increase_decrease(void)
{
  init_heap();
  t_heap_insert();

  int i;
  for(i = 1; i <= MAX_NUM; i++)
  {
    if(i > heap[i])
    {
      bt_debug("inc %d ", i);
      heap[i] = i;
      HEAP_INCREASE(heap, num, int, MY_CMP, MY_HEAP_SWAP, i);
    }
    else if (i < heap[i])
    {
      bt_debug("dec %d ", i);
      heap[i] = i;
      HEAP_INCREASE(heap, num, int, MY_CMP, MY_HEAP_SWAP, i);
    }
    SHOW_HEAP(heap);
    bt_assert(is_heap_valid(heap, num));
  }

  return BT_SUCCESS;
}

static int
t_heap_delete(void)
{
  init_heap();
  t_heap_insert();
  t_heap_increase_decrease();

  int i;
  for(i = 1; i <= num; i++)
  {
    bt_debug("del at pos %d ", i);
    HEAP_DELETE(heap, num, int, MY_CMP, MY_HEAP_SWAP, i);
    SHOW_HEAP(heap);
    bt_assert(is_heap_valid(heap, num));
  }

  return BT_SUCCESS;
}

static int
t_heap_0(void)
{
  init_heap();
  t_heap_insert();
  t_heap_increase_decrease();
  t_heap_delete();

  return (heap[0] == SPECIAL_KEY) ? BT_SUCCESS : BT_FAILURE;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_case(t_heap_insert, "Test Inserting");
  bt_test_case(t_heap_increase_decrease, "Test Increasing/Decreasing");
  bt_test_case(t_heap_delete, "Test Deleting");
  bt_test_case(t_heap_0, "Is heap[0] unused?");

  return 0;
}

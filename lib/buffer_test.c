/*
 *	BIRD Library -- Buffer Tests
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include "test/birdtest.h"
#include "sysdep/config.h"
#include "lib/resource.h"
#include "lib/buffer.h"

#define MAX_NUM 33
typedef BUFFER(int) buffer_int;

int expected[MAX_NUM];
buffer_int buffer;
struct pool *buffer_pool;

static void
show_buf(buffer_int *b)
{
  int i;
  bt_debug(".used = %d, .size = %d\n", b->used, b->size);

  for (i = 0; i < b->used; i++)
    bt_debug("  .data[%3d] = %-16d  expected %-16d  %s\n", i, b->data[i], expected[i], (b->data[i] == expected[i] ? "OK" : "FAIL!"));
}

static void
fill_expected_array(void)
{
  int i;

  for (i = 0; i < MAX_NUM; i++)
    expected[i] = bt_rand_num();
}

static void
init_buffer(void)
{
  buffer_pool = NULL;
  BUFFER_INIT(buffer, buffer_pool, MAX_NUM);
}

static void
free_buffer(void)
{
  free(buffer_pool);
}

static int
is_buffer_as_expected(buffer_int *b)
{
  show_buf(b);

  int i;
  for (i = 0; i < MAX_NUM; i++)
    bt_assert(b->data[i] == expected[i]);
  return 1;
}
static int
t_buffer_push(void)
{
  int i;

  init_buffer();
  fill_expected_array();

  for (i = 0; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i];
  is_buffer_as_expected(&buffer);

  free_buffer();
  return BT_SUCCESS;
}

static int
t_buffer_pop(void)
{
  int i;

  init_buffer();
  fill_expected_array();

  /* POP a half of elements */
  for (i = 0; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i];
  for (i = MAX_NUM-1; i >= MAX_NUM/2; i--)
    BUFFER_POP(buffer);
  for (i = MAX_NUM/2; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i] = bt_rand_num();
  is_buffer_as_expected(&buffer);

  /* POP all of elements */
  for (i = MAX_NUM-1; i >= 0; i--)
    BUFFER_POP(buffer);
  bt_assert(buffer.used == 0);
  for (i = 0; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i];
  is_buffer_as_expected(&buffer);

  free_buffer();
  return BT_SUCCESS;
}

static int
t_buffer_resize(void)
{
  int i;

  buffer_pool = NULL;
  BUFFER_INIT(buffer, buffer_pool, 0);
  fill_expected_array();

  for (i = 0; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i];
  is_buffer_as_expected(&buffer);
  bt_assert(buffer.size >= MAX_NUM);

  free_buffer();
  return BT_SUCCESS;
}

static int
t_buffer_flush(void)
{
  int i;

  init_buffer();
  fill_expected_array();
  for (i = 0; i < MAX_NUM; i++)
    BUFFER_PUSH(buffer) = expected[i];

  BUFFER_FLUSH(buffer);
  bt_assert(buffer.used == 0);

  free_buffer();
  return BT_SUCCESS;
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_buffer_push, "Pushing new elements");
  bt_test_suite(t_buffer_pop, "Fill whole buffer (PUSH), a half of elements POP and PUSH new elements");
  bt_test_suite(t_buffer_resize, "Init a small buffer and try overfill");
  bt_test_suite(t_buffer_flush, "Fill and flush all elements");

  return bt_end();
}


/* Mockup */
void *
mb_alloc(pool *UNUSED, unsigned size) {
  return (void *) malloc(size);
};

/* Mockup */
#define STEP_UP(x) ((x) + (x)/2 + 4)
#define MIN_(a,b) (((a)<(b))?(a):(b))
#define MIN(a,b) MIN_(a,b)
void
buffer_realloc(void **buf, unsigned *size, unsigned need, unsigned item_size)
{
  unsigned nsize = MIN(*size, need);

  while (nsize < need)
    nsize = STEP_UP(nsize);

  *buf = realloc(*buf, nsize * item_size);
  *size = nsize;
}

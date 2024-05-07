/*
 *	BIRD -- Allocator Tests
 *
 *	(c) 2023       CZ.NIC z.s.p.o.
 *	(c) 2023       Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "test/bt-utils.h"
#include "lib/resource.h"

#include <unistd.h>
#include <pthread.h>

#define ALLOC_AND_TREE_LIMIT	(1 << 14)

static void *
alloc_and_free_main(void *data UNUSED)
{
#define BLOCK_SIZE	32
  void *block[BLOCK_SIZE];

  for (int i=0; i<ALLOC_AND_TREE_LIMIT; i++)
  {
    for (int b=0; b<BLOCK_SIZE; b++)
    {
      block[b] = alloc_page();
      ASSERT_DIE(PAGE_HEAD(block[b]) == block[b]);
      memset(block[b], 0x42, page_size);
    }

    for (int b=0; b<BLOCK_SIZE; b++)
    {
      free_page(block[b]);
      block[b] = alloc_page();
      ASSERT_DIE(PAGE_HEAD(block[b]) == block[b]);
      memset(block[b], 0x53, page_size); 
    }

    for (int b=0; b<BLOCK_SIZE; b++)
      free_page(block[b]);
  }

  return NULL;
}

static int
t_alloc_and_free(void)
{
#define THR_N	16
  pthread_t tid[THR_N];

  for (int i=0; i<THR_N; i++)
  {
    pthread_create(&tid[i], NULL, alloc_and_free_main, NULL);
    usleep(50 * i);
  }

  for (int i=0; i<THR_N; i++)
    pthread_join(tid[i], NULL);

  return 1;
}

int main(int argc, char **argv)
{
  bt_init(argc, argv);
  
  bt_test_suite(t_alloc_and_free, "Testing parallel allocations and free");

  return bt_exit_value();
}

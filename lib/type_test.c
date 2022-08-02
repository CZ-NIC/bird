/*
 *	BIRD Library -- Data Type Alignment Tests
 *
 *	(c) 2022 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "test/birdtest.h"
#include "lib/type.h"
#include "lib/route.h"

#define CHECK_ONE(val)	\
  for (uint i=0; i<sizeof(val); i++) \
    bt_assert(((const u8 *) &val)[i] == (u8) ~0);

#define SET_PADDING(val, name)	\
  for (uint i=0; i<sizeof(val.PADDING_NAME(name)); i++) \
    val.PADDING_NAME(name)[i] = ~0;


static int
t_bval(void)
{
  union bval v;

  memset(&v, 0, sizeof(v));
  v.data = ~0;
  SET_PADDING(v, data);
  CHECK_ONE(v);

  memset(&v, 0, sizeof(v));
  v.i = ~0;
  SET_PADDING(v, i);
  CHECK_ONE(v);

  memset(&v, 0, sizeof(v));
  v.ptr = (void *) ~0;
  CHECK_ONE(v);

  memset(&v, 0, sizeof(v));
  v.ad = (void *) ~0;
  CHECK_ONE(v);

  return 1;
}

static int
t_eattr(void)
{
  struct eattr e;
  memset(&e, 0, sizeof(e));

  e.id = ~0;
  e.flags = ~0;
  e.type = ~0;
  e.rfu = ~0;
  e.originated = ~0;
  e.fresh = ~0;
  e.undef = ~0;
  memset(&e.u, ~0, sizeof(e.u));  /* Assumes t_bval passed */

  SET_PADDING(e, unused);

  CHECK_ONE(e);

  return 1;
}


int main(int argc, char *argv[])
{
  bt_init(argc, argv);

  bt_test_suite(t_bval,	  "Structure alignment test: bval");
  bt_test_suite(t_eattr,  "Structure alignment test: eattr");

  return bt_exit_value();
}

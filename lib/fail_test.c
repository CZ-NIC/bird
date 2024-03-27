#include "test/birdtest.h"

void
just_bug_fce(void)
{
  bug("bug message");
}

static int
t_check_bug(void)
{
  return bt_assert_bug(just_bug_fce, "bug message");
}

int
main(int argc, char *argv[])
{
  bt_init(argc, argv);
  bt_test_suite(t_check_bug,	"bug fce");

  return bt_exit_value();
}

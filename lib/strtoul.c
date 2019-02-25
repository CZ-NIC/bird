/*
 *	BIRD Library -- Parse numbers
 *
 *	(c) 2019 Maria Matejka <mq@jmq.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "lib/string.h"

#include <errno.h>

#define ULI_MAX_DIV10 (UINT64_MAX / 10)
#define ULI_MAX_MOD10 (UINT64_MAX % 10)

u64
bstrtoul10(const char *str, char **end)
{
  u64 out = 0;
  for (*end = (char *) str; (**end >= '0') && (**end <= '9'); (*end)++) {
    u64 digit = **end - '0';
    if ((out > ULI_MAX_DIV10) ||
	(out == ULI_MAX_DIV10) && (digit > ULI_MAX_MOD10)) {
      errno = ERANGE;
      return UINT64_MAX;
    }
    
    out *= 10;
    out += (**end) - '0';
  }
  return out;
}

u64
bstrtoul16(const char *str, char **end)
{
  u64 out = 0;
  for (int i=0; i<=(64/4); i++) {
    switch (str[i]) {
      case '0' ... '9':
	out *= 16;
	out += str[i] - '0';
	break;
      case 'a' ... 'f':
	out *= 16;
	out += str[i] + 10 - 'a';
	break;
      case 'A' ... 'F':
	out *= 16;
	out += str[i] + 10 - 'A';
	break;
      default:
	*end = (char *) &(str[i]);
	return out;
    }
  }

  errno = ERANGE;
  return UINT64_MAX;
}

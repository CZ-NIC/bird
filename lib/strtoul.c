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

static int
fromxdigit(char c)
{
  switch (c)
  {
  case '0' ... '9':
    return c - '0';
  case 'a' ... 'f':
    return c + 10 - 'a';
  case 'A' ... 'F':
    return c + 10 - 'A';
  default:
    return -1;
  }
}

int
bstrhextobin(const char *s, byte *b)
{
  int len = 0;
  int hi = 0;

  for (; *s; s++)
  {
    int v = fromxdigit(*s);
    if (v < 0)
    {
      if (strchr(" -.:", *s) && !hi)
	continue;
      else
	return -1;
    }

    if (len == INT32_MAX)
      return -1;

    if (b)
    {
      if (!hi)
	b[len] = (v << 4);
      else
	b[len] |= v;
    }

    len += hi;
    hi = !hi;
  }

  return !hi ? len : -1;
}

static char
toxdigit(uint b)
{
  if (b < 10)
    return ('0' + b);
  else if (b < 16)
    return ('a' + b - 10);
  else
    return 0;
}

int
bstrbintohex(const byte *b, size_t len, char *buf, size_t size, char delim)
{
  ASSERT(size >= 6);
  char *bound = buf + size - 3;

  size_t i;
  for (i = 0; i < len; i++)
  {
    if (buf > bound)
    {
      strcpy(buf - 4, "...");
      return -1;
    }

    uint x = b[i];
    buf[0] = toxdigit(x >> 4);
    buf[1] = toxdigit(x & 0xF);
    buf[2] = delim;
    buf += 3;
  }

  buf[i ? -1 : 0] = 0;

  return 0;
}

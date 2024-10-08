/*
 *	BIRD Library -- String Functions
 *
 *	(c) 1998 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_STRING_H_
#define _BIRD_STRING_H_

#include <stdarg.h>
#include <string.h>
#include <strings.h>

#include "lib/resource.h"

int bsprintf(char *str, const char *fmt, ...);
int bvsprintf(char *str, const char *fmt, va_list args);
int bsnprintf(char *str, int size, const char *fmt, ...) ACCESS_WRITE(1, 2);
int bvsnprintf(char *str, int size, const char *fmt, va_list args) ACCESS_WRITE(1, 2);

char *mb_sprintf(pool *p, const char *fmt, ...);
char *mb_vsprintf(pool *p, const char *fmt, va_list args);
char *lp_sprintf(linpool *p, const char *fmt, ...);
char *lp_vsprintf(linpool *p, const char *fmt, va_list args);
#define tmp_sprintf(...)    lp_sprintf(tmp_linpool, __VA_ARGS__)
#define tmp_vsprintf(...)   lp_vsprintf(tmp_linpool, __VA_ARGS__)

int buffer_vprint(buffer *buf, const char *fmt, va_list args);
int buffer_print(buffer *buf, const char *fmt, ...);
void buffer_puts(buffer *buf, const char *str);

u64 bstrtoul10(const char *str, char **end);
u64 bstrtoul16(const char *str, char **end);
byte bstrtobyte16(const char *str);

int bstrhextobin(const char *s, byte *b);
int bstrbintohex(const byte *b, size_t len, char *buf, size_t size, char delim) ACCESS_READ(1, 2) ACCESS_WRITE(3, 4);

static inline const char *fmt_order(u64 value, int decimals, u64 kb_threshold)
{
  bool too_big = (value + 512 < 512ULL);

  u64 mv = value;
  int magnitude = 0;
  while (mv > kb_threshold)
  {
    magnitude++;
    mv = (mv + (too_big ? 0 : 512)) / 1024;
  }

  ASSERT_DIE(magnitude < 7);
  char suffix = " kMGTEP"[magnitude];
  while ((magnitude - 1) * 3 > decimals)
  {
    magnitude--;
    value = (value + (too_big ? 0 : 512)) / 1024;
    too_big = false;
  }

  if ((!decimals) || (suffix == ' '))
    return tmp_sprintf("%lu %c", value, suffix);

  u64 divisor = 1;
  for (int i=0; i<decimals; i++)
    divisor *= 10;

  u64 magdiv = 1;
  while (magnitude--)
    magdiv *= 1024;

  magdiv += (divisor / 2);
  magdiv /= divisor;
  value /= magdiv;

  return tmp_sprintf(
      tmp_sprintf("%%lu.%%0%ulu %%c", decimals),
      value / divisor, value % divisor, suffix);
}

int patmatch(const byte *pat, const byte *str);

static inline char *xbasename(const char *str)
{
  char *s = strrchr(str, '/');
  return s ? s+1 : (char *) str;
}

static inline char *
xstrdup(const char *c)
{
  size_t l = strlen(c) + 1;
  char *z = xmalloc(l);
  memcpy(z, c, l);
  return z;
}

static inline char *
lp_strdup(linpool *lp, const char *c)
{
  size_t l = strlen(c) + 1;
  char *z = lp_allocu(lp, l);
  memcpy(z, c, l);
  return z;
}

static inline void
memset32(void *D, u32 val, uint n)
{
  u32 *dst = D;
  uint i;

  for (i = 0; i < n; i++)
    dst[i] = val;
}

static inline int
bstrcmp(const char *s1, const char *s2)
{
  if (s1 && s2)
    return strcmp(s1, s2);
  else
    return !s2 - !s1;
}

static inline void *
bmemcpy(void *dest, const void *src, size_t n)
{
  if (n)
    return memcpy(dest, src, n);
  else
    return dest;
}

#define ROUTER_ID_64_LENGTH 23

#endif

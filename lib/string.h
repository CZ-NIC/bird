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

char *fmt_order(u64 value, uint decimals, u64 kb_threshold);

int bstrhextobin(const char *s, byte *b);
int bstrbintohex(const byte *b, size_t len, char *buf, size_t size, char delim) ACCESS_READ(1, 2) ACCESS_WRITE(3, 4);

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

static inline char *
lp_strcat(linpool *lp, const char *s1, const char *s2)
{
  size_t l1 = strlen(s1);
  size_t l2 = strlen(s2);
  char *z = lp_allocu(lp, l1 + l2 + 1);
  memcpy(z, s1, l1);
  memcpy(z + l1, s2, l2 + 1);
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

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
int bsnprintf(char *str, int size, const char *fmt, ...);
int bvsnprintf(char *str, int size, const char *fmt, va_list args);

int buffer_vprint(buffer *buf, const char *fmt, va_list args);
int buffer_print(buffer *buf, const char *fmt, ...);
void buffer_puts(buffer *buf, const char *str);

u64 bstrtoul10(const char *str, char **end);
u64 bstrtoul16(const char *str, char **end);

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

#define ROUTER_ID_64_LENGTH 23

#endif

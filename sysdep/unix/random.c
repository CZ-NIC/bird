/*
 *	BIRD Internet Routing Daemon -- Random Numbers
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

#include "sysdep/config.h"
#include "nest/bird.h"

#ifdef HAVE_GETRANDOM
#include <sys/random.h>
#endif


u32
random_u32(void)
{
  long int rand_low, rand_high;

  rand_low = random();
  rand_high = random();
  return (rand_low & 0xffff) | ((rand_high & 0xffff) << 16);
}


/* If there is no getrandom() / getentropy(), use /dev/urandom */
#if !defined(HAVE_GETRANDOM) && !defined(HAVE_GETENTROPY)

#define HAVE_URANDOM_FD 1
static int urandom_fd = -1;

int
read_urandom_fd(void *buf, uint count)
{
  if (urandom_fd < 0)
  {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
      die("Cannot open /dev/urandom: %m");
  }

  return read(urandom_fd, buf, count);
}
#endif


void
random_init(void)
{
  uint seed;

  /* Get random bytes to trip any errors early and to seed random() */
  random_bytes(&seed, sizeof(seed));

  srandom(seed);
}

void
random_bytes(void *buf, size_t count)
{
  ASSERT(count <= 256);

  while (count > 0)
  {
    int n = -1;

#if defined(HAVE_GETRANDOM)
    n = getrandom(buf, count, 0);
#elif defined(HAVE_GETENTROPY)
    n = getentropy(buf, count);
    n = !n ? (int) count : n;
#elif defined(HAVE_URANDOM_FD)
    n = read_urandom_fd(buf, count);
#endif

    if (n < 0)
    {
      if (errno == EINTR)
        continue;
      die("Cannot get random bytes: %m");
    }

    buf += n;
    count -= n;
  }
}

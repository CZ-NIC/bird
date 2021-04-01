/*
 *	BIRD Internet Routing Daemon -- Random Numbers
 *
 *	(c) 2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "sysdep/config.h"

#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef HAVE_LINUX_RANDOM_H
#  include <linux/random.h>
#endif
#if defined(HAVE_SYS_RANDOM_H) && (defined(HAVE_GETRANDOM) || defined(HAVE_GETENTROPY))
#    include <sys/random.h>
#endif

#include "nest/bird.h"

u32
random_u32(void)
{
  long int rand_low, rand_high;

  rand_low = random();
  rand_high = random();
  return (rand_low & 0xffff) | ((rand_high & 0xffff) << 16);
}

void
random_init()
{
  char buf;
  /* get a single random byte to trip any errors early */
  random_bytes(&buf, sizeof(buf));
}

#if defined(HAVE_GETRANDOM) || defined(HAVE_GENTROPY)
int
random_bytes(char *buf, size_t size)
{
  int n;
  int flags = 0;
  while (0 < size) {
#if defined(HAVE_GETRANDOM)
    n = getrandom(buf, size, flags);
#else
    n = getentropy(buf, size);
#endif
    if (n < 0) {
      if (errno == EINTR)
        continue;
      die("Couldn't get random bytes: %m");
    }
    buf += n;
    size -= n;
  }

  return 0;
}

void random_close(void) {}

#else

static int urandom_fd = -1;
int random_bytes(char *buf, size_t size)
{
  int n;

  if (urandom_fd < 0)
  {
    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (urandom_fd < 0)
      die("Couldn't open /dev/urandom: %m");
  }

  do
  {
    n = read(urandom_fd, buf, size);
    if (n <= 0) {
      if (errno == EINTR)
        continue;
      die("Couldn't read from /dev/urandom: %m");
    }
    buf += n;
    size -= n;
  } while (size > 0);

  return 0;
}

void
random_close(void)
{
  if (urandom_fd >= 0) {
    close(urandom_fd);
    urandom_fd = -1;
  }
}
#endif

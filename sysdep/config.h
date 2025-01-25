/*
 *	This file contains all parameters dependent on the
 *	operating system and build-time configuration.
 */

#ifndef _BIRD_CONFIG_H_
#define _BIRD_CONFIG_H_

/* BIRD version */
#ifndef BIRD_VERSION
#error "BIRD_VERSION not defined"
#endif

/* ... is a string literal at least of 4 characters */
_Static_assert(sizeof(BIRD_VERSION) >= 4, BIRD_VERSION);
_Static_assert(sizeof(BIRD_VERSION "") == sizeof(BIRD_VERSION), BIRD_VERSION);

/* Include parameters determined by configure script */
#include "sysdep/autoconf.h"

/* Include OS configuration file as chosen in autoconf.h */
#include SYSCONF_INCLUDE

#ifndef MACROS_ONLY

/*
 *  Of course we could add the paths to autoconf.h, but autoconf
 *  is stupid and puts make-specific substitutious to the paths.
 */
#include "sysdep/paths.h"

/* Types */

#include <stdbool.h>
#include <stdint.h>
typedef int8_t s8;
typedef uint8_t u8;
typedef int16_t s16;
typedef uint16_t u16;
typedef int32_t s32;
typedef uint32_t u32;
typedef int64_t s64;
typedef uint64_t u64;
typedef uint8_t byte;
typedef uint16_t word;
typedef unsigned int uint;

#endif

#endif

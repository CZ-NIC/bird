/*
 *	BIRD Library -- Alloca.h
 *
 *	(c) 2004 Ondrej Filip <feela@network.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ALLOCA_H_
#define _BIRD_ALLOCA_H_

#ifdef HAVE_ALLOCA_H
#include <alloca.h>
#else
#include <stdlib.h>
#endif

#define allocz(len) ({ void *_x = alloca(len); memset(_x, 0, len); _x; })

#define alloca_copy(src,len) ({ void *_x = alloca(len); memcpy(_x, src, len); })

#endif

/*
 *	BIRD -- x86-specific calls
 *
 *	(c) 2019 Maria Matejka <mq@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_ASM_H_
#define _BIRD_ASM_H_

#define CPU_RELAX()  __asm__ __volatile__ ("rep; nop" : : : "memory")

#endif

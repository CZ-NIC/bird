/*
 *	BIRD Internet Routing Daemon -- MPLS manipulation
 *
 *	(c) 2016 Jan Matejka <mq@ucw.cz>
 *	(c) 2016 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_MPLS_H_
#define _BIRD_MPLS_H_

#define MPLS_STACK_LENGTH   8 /* Adjust this if you need deeper MPLS stack */

typedef struct mpls_stack {
  u8 len;
  u32 label[MPLS_STACK_LENGTH];
} mpls_stack;

#endif

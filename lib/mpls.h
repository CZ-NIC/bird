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
#define MPLS_PXLEN	    20 /* Length of the label in bits. Constant. */
#define MPLS_LABEL_MAX	    ((1<<MPLS_PXLEN)-1) /* Maximal possible label value. */

/*
 *   RFC 3032 updated by RFC 5462:
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Label
 *   |                Label                  | TC  |S|       TTL     | Stack
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ Entry
 *
 *                       Label:  Label Value, 20 bits
 *                       TC:     Traffic Class, 3 bits
 *                       S:      Bottom of Stack, 1 bit
 *                       TTL:    Time to Live, 8 bits
 */

typedef struct mpls_stack {
  u8 len;
  u32 label[MPLS_STACK_LENGTH];
} mpls_stack;

static inline char * const mpls_hton(mpls_stack s) {
  static char buf[MPLS_STACK_LENGTH*4];
  int i;
  for (i = 0; i < s.len; i++) {
    buf[i*4 + 0] = s.label[i] >> 12;
    buf[i*4 + 1] = s.label[i] >> 4;
    buf[i*4 + 2] = (s.label[i] << 4) | (i == s.len - 1 ? 0x1 : 0);
    buf[i*4 + 3] = 0;
  }
  return buf;
}

static inline int mpls_buflen(const char *buf) {
  // Looking for the Bottom of Stack set to 4.
  int i;
  for (i = 0; !(buf[i++*4 + 2] & 0x1); );
  return i*4;
}

static inline mpls_stack mpls_ntoh(const char *buf) {
  mpls_stack s = { .len = mpls_buflen(buf) };
  int i;
  for (i = 0; i < s.len; i++)
    s.label[i] = (buf[i*4 + 0] << 12) | (buf[i*4 + 1] << 4) | (buf[i*4 + 2] >> 4);
  return s;
}

#endif

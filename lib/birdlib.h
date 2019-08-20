/*
 *	BIRD Library
 *
 *	(c) 1998--2004 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_BIRDLIB_H_
#define _BIRD_BIRDLIB_H_

#include "lib/alloca.h"

/* Ugly structure offset handling macros */

struct align_probe { char x; long int y; };

#define OFFSETOF(s, i) ((size_t) &((s *)0)->i)
#define SKIP_BACK(s, i, p) ((s *)((char *)p - OFFSETOF(s, i)))
#define BIRD_ALIGN(s, a) (((s)+a-1)&~(a-1))
#define CPU_STRUCT_ALIGN (sizeof(struct align_probe))

/* Utility macros */

#define MIN_(a,b) (((a)<(b))?(a):(b))
#define MAX_(a,b) (((a)>(b))?(a):(b))

#ifndef PARSER
#undef MIN
#undef MAX
#define MIN(a,b) MIN_(a,b)
#define MAX(a,b) MAX_(a,b)
#endif

#define U64(c) UINT64_C(c)
#define ABS(a)   ((a)>=0 ? (a) : -(a))
#define DELTA(a,b) (((a)>=(b))?(a)-(b):(b)-(a))
#define ARRAY_SIZE(a) (sizeof(a)/sizeof(*(a)))
#define BYTES(n) ((((uint) (n)) + 7) / 8)
#define CALL(fn, args...) ({ if (fn) fn(args); })
#define ADVANCE(w, r, l) ({ r -= (l); w += (l); })

static inline int uint_cmp(uint i1, uint i2)
{ return (int)(i1 > i2) - (int)(i1 < i2); }

static inline int u64_cmp(u64 i1, u64 i2)
{ return (int)(i1 > i2) - (int)(i1 < i2); }


/* Bitfield macros */

/* b is u32 array (or ptr), l is size of it in bits (multiple of 32), p is 0..(l-1) */
#define BIT32_VAL(p)		(((u32) 1) << ((p) % 32))
#define BIT32_TEST(b,p)		((b)[(p)/32] & BIT32_VAL(p))
#define BIT32_SET(b,p)		((b)[(p)/32] |= BIT32_VAL(p))
#define BIT32_CLR(b,p)		((b)[(p)/32] &= ~BIT32_VAL(p))
#define BIT32_ZERO(b,l)		memset((b), 0, (l)/8)

/* The same, but counting bits from MSB */
#define BIT32R_VAL(p)		((((u32) 1) << 31) >> ((p) % 32))
#define BIT32R_TEST(b,p)	((b)[(p)/32] & BIT32R_VAL(p))
#define BIT32R_SET(b,p)		((b)[(p)/32] |= BIT32R_VAL(p))
#define BIT32R_CLR(b,p)		((b)[(p)/32] &= ~BIT32R_VAL(p))
#define BIT32R_ZERO(b,l)	memset((b), 0, (l)/8)

#ifndef NULL
#define NULL ((void *) 0)
#endif

/* Macros for gcc attributes */

#define NORET __attribute__((noreturn))
#define UNUSED __attribute__((unused))
#define PACKED __attribute__((packed))

#ifndef HAVE_THREAD_LOCAL
#define _Thread_local
#endif

/* Microsecond time */

typedef s64 btime;
//typedef s64 bird_clock_t;

#define S_	* (btime) 1000000
#define MS_	* (btime) 1000
#define US_	* (btime) 1
#define TO_S	/1000000
#define TO_MS	/1000
#define TO_US	/1

#ifndef PARSER
#define S	S_
#define MS	MS_
#define US	US_
#define NS	/1000
#endif

#define TIME_INFINITY ((s64) 0x7fffffffffffffff)


/* Rate limiting */

struct tbf {
  btime timestamp;			/* Last update */
  u64 count;				/* Available micro-tokens */
  u16 burst;				/* Max number of tokens */
  u16 rate;				/* Rate of replenishment (tokens / sec) */
  u32 drop;				/* Number of failed request since last successful */
};

/* Default TBF values for rate limiting log messages */
#define TBF_DEFAULT_LOG_LIMITS { .rate = 1, .burst = 5 }

int tbf_limit(struct tbf *f);


/* Logging and dying */

typedef struct buffer {
  byte *start;
  byte *pos;
  byte *end;
} buffer;

#define STACK_BUFFER_INIT(buf,size)		\
  do {						\
    buf.start = alloca(size);			\
    buf.pos = buf.start;			\
    buf.end = buf.start + size;			\
  } while(0)

#define LOG_BUFFER_INIT(buf)			\
  STACK_BUFFER_INIT(buf, LOG_BUFFER_SIZE)

#define LOG_BUFFER_SIZE 1024

#define log log_msg
void log_commit(int class, buffer *buf);
void log_msg(const char *msg, ...);
void log_rl(struct tbf *rl, const char *msg, ...);
void die(const char *msg, ...) NORET;
void bug(const char *msg, ...) NORET;

#define L_DEBUG "\001"			/* Debugging messages */
#define L_TRACE "\002"			/* Protocol tracing */
#define L_INFO "\003"			/* Informational messages */
#define L_REMOTE "\004"			/* Remote protocol errors */
#define L_WARN "\005"			/* Local warnings */
#define L_ERR "\006"			/* Local errors */
#define L_AUTH "\007"			/* Authorization failed etc. */
#define L_FATAL "\010"			/* Fatal errors */
#define L_BUG "\011"			/* BIRD bugs */

void debug(const char *msg, ...);	/* Printf to debug output */

/* Debugging */

#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
#define DBG(x, y...) debug(x, ##y)
#else
#define DBG(x, y...) do { } while(0)
#endif

#ifdef DEBUGGING
#define ASSERT(x) do { if (!(x)) bug("Assertion '%s' failed at %s:%d", #x, __FILE__, __LINE__); } while(0)
#else
#define ASSERT(x) do { if (!(x)) log(L_BUG "Assertion '%s' failed at %s:%d", #x, __FILE__, __LINE__); } while(0)
#endif

#ifdef DEBUGGING
asm(
    ".pushsection \".debug_gdb_scripts\", \"MS\",@progbits,1\n"
    ".byte 1\n" /* Python */
    ".asciz \"bird-gdb.py\"\n"
    ".popsection\n"
   );
#endif

/* Pseudorandom numbers */

u32 random_u32(void);

#endif

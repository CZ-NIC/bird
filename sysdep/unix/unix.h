/*
 *	BIRD -- Declarations Common to Unix Port
 *
 *	(c) 1998--2000 Martin Mares <mj@ucw.cz>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_UNIX_H_
#define _BIRD_UNIX_H_

#include <sys/socket.h>

struct pool;
struct iface;
struct birdsock;
struct rfile;

/* main.c */

extern char *bird_name;
void async_config(void);
void async_dump(void);
void async_shutdown(void);
void cmd_check_config(char *name);
void cmd_reconfig(char *name, int type, int timeout);
void cmd_reconfig_confirm(void);
void cmd_reconfig_undo(void);
void cmd_shutdown(void);

#define UNIX_DEFAULT_CONFIGURE_TIMEOUT	300

#define UNIX_DEFAULT_LATENCY_LIMIT	(1 S_)
#define UNIX_DEFAULT_WATCHDOG_WARNING	(5 S_)

/* io.c */

#define ERR(c) do { s->err = c; return -1; } while (0)
#define ERR2(c) do { s->err = c; goto err; } while (0)
#define ERR_MSG(c) do { errno = 0; s->err = c; return -1; } while (0)


#define SOCKADDR_SIZE 32

typedef struct sockaddr_bird {
  struct sockaddr sa;
  char padding[SOCKADDR_SIZE - sizeof(struct sockaddr)];
} sockaddr;


#ifdef IPV6
#define BIRD_AF AF_INET6
#define ipa_from_sa(x) ipa_from_sa6(x)
#else
#define BIRD_AF AF_INET
#define ipa_from_sa(x) ipa_from_sa4(x)
#endif


/* This is sloppy hack, it should be detected by configure script */
/* Linux systems have it defined so this is definition for BSD systems */
#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif


static inline ip_addr ipa_from_in4(struct in_addr a UNUSED6)
{ return ipa_from_u32(ntohl(a.s_addr)); }

static inline ip_addr ipa_from_in6(struct in6_addr a UNUSED4)
{ return ipa_build6(ntohl(a.s6_addr32[0]), ntohl(a.s6_addr32[1]), ntohl(a.s6_addr32[2]), ntohl(a.s6_addr32[3])); }

static inline ip_addr ipa_from_sa4(sockaddr *sa UNUSED6)
{ return ipa_from_in4(((struct sockaddr_in *) sa)->sin_addr); }

static inline ip_addr ipa_from_sa6(sockaddr *sa UNUSED4)
{ return ipa_from_in6(((struct sockaddr_in6 *) sa)->sin6_addr); }

static inline struct in_addr ipa_to_in4(ip_addr a)
{ return (struct in_addr) { htonl(ipa_to_u32(a)) }; }

#ifdef IPV6
static inline struct in6_addr ipa_to_in6(ip_addr a)
{ return (struct in6_addr) { .s6_addr32 = { htonl(_I0(a)), htonl(_I1(a)), htonl(_I2(a)), htonl(_I3(a)) } }; }
#else
/* Temporary dummy */
static inline struct in6_addr ipa_to_in6(ip_addr a UNUSED)
{ return (struct in6_addr) { .s6_addr32 = { 0, 0, 0, 0 } }; }
#endif

void sockaddr_fill(sockaddr *sa, int af, ip_addr a, struct iface *ifa, uint port);
int sockaddr_read(sockaddr *sa, int af, ip_addr *a, struct iface **ifa, uint *port);


#ifndef SUN_LEN
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path) + strlen ((ptr)->sun_path))
#endif

extern volatile int async_config_flag;
extern volatile int async_dump_flag;
extern volatile int async_shutdown_flag;

void io_init(void);
void io_loop(void);
void io_log_dump(void);
int sk_open_unix(struct birdsock *s, char *name);
struct rfile *rf_open(struct pool *, char *name, char *mode);
void *rf_file(struct rfile *f);
int rf_fileno(struct rfile *f);
void test_old_bird(char *path);


/* krt.c bits */

void krt_io_init(void);

/* log.c */

void main_thread_init(void);
void log_init_debug(char *);		/* Initialize debug dump to given file (NULL=stderr, ""=off) */
void log_switch(int debug, list *l, char *); /* Use l=NULL for initial switch */

struct log_config {
  node n;
  uint mask;				/* Classes to log */
  void *fh;				/* FILE to log to, NULL=syslog */
  int terminal_flag;
};

#endif

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <string.h>

#include "nest/bird.h"
#include "lib/lists.h"
#include "lib/resource.h"
#include "lib/timer.h"
#include "lib/socket.h"
#include "lib/event.h"
#include "lib/string.h"
#include "nest/iface.h"
#include "lib/string.h"

#include "lib/unix.h"


//#define PKT_MAGIC 0x12345678
#define PKT_MAGIC 42

#define PKT_PORT 100
#define PKT_VALUE 0

struct my_packet
{
  u32 magic;
  u32 value;
  u32 count;
};

int cf_mcast;		/* Set up multicast */
int cf_bcast;		/* Enable broadcast */
int cf_bind;		/* Bind by address */
uint cf_count;		/* How many packets send */
uint counter;		/* global counter of send/recv packets */
uint cf_value;		/* a value in packet */
uint cf_ttl;

sock *skt_parse_args(int argc, char **argv, int is_send);
void bird_init(void);
void skt_open(sock *s);

/* implementation in io.c */
int sk_write(sock *s);
int sk_read(sock *s);

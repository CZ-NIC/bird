#include "common.h"

int
rcv_hook(sock *sk, int size)
{
  struct my_packet *raw;
  if (sk->type == SK_IP)
    raw = (void *) sk_rx_buffer(sk, &size);
  else
    raw = (void *) sk->rbuf;

  if (size != sizeof(struct my_packet))
  {
    printf("Bad size of rcv packet %d \n", size);
    return 1;
  }

  struct my_packet pkt = {
      .magic = ntohl(raw->magic),
      .value = ntohl(raw->value),
      .count = ntohl(raw->count),
  };

  char *ifa_name = if_find_by_index(sk->lifindex) ? if_find_by_index(sk->lifindex)->name : "UNKNOWN";

  char buf[1024];

  bsnprintf(buf, sizeof(buf), "%I:%u -> %I ifa%u %s: ", sk->faddr, sk->fport, sk->laddr, sk->lifindex, ifa_name);
  char *pos = buf + strlen(buf);

  if (pkt.magic == (u32)PKT_MAGIC)
    bsnprintf(pos, pos-buf, "pkt %d/%d, ttl %d", pkt.value, pkt.count, sk->ttl);
  else
    bsnprintf(pos, pos-buf, "recv foreign of len %d", size);

  printf("%s\n", buf);

  return 1; /* clear buffer */
}

int
main(int argc, char **argv)
{
  bird_init();

  sock *s = skt_parse_args(argc, argv, 0);
  s->rx_hook = rcv_hook;
  s->rbsize = 1500;
  s->flags |= SKF_LADDR_RX | SKF_TTL_RX | SKF_PKTINFO;

  skt_open(s);

  while (1)
  {
    sk_read(s);
    usleep(20000);
  }
}


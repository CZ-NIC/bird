#include "common.h"

int
rcv_hook(sock *sk, int size)
{
  struct my_packet *raw;
  char ifa_name[IF_NAMESIZE];
  char buf[1024];

  if (cf_count && ++counter > cf_count)
    exit(0);

  if (sk->type == SK_IP)
    raw = (void *) sk_rx_buffer(sk, &size);
  else
    raw = (void *) sk->rbuf;

  if (size != sizeof(struct my_packet))
  {
    printf("Received a packet with unexpected length of %d bytes \n", size);
    return 1;
  }

  struct my_packet pkt = {
      .magic = ntohl(raw->magic),
      .value = ntohl(raw->value),
      .count = ntohl(raw->count),
  };

  if (!if_indextoname(sk->lifindex, ifa_name))
  {
    perror("if_indextoname");
    snprintf(ifa_name, sizeof(ifa_name), "???");
  }

  bsnprintf(buf, sizeof(buf), "%I:%u -> %I ifa(%u) %s: ", sk->faddr, sk->fport, sk->laddr, sk->lifindex, ifa_name);
  char *pos = buf + strlen(buf);
  if (pkt.magic == (u32)PKT_MAGIC)
    bsnprintf(pos, pos-buf, "pkt %d/%d, ttl %d", pkt.value, pkt.count, sk->rcv_ttl);
  else
    bsnprintf(pos, pos-buf, "magic value does not pass: recv %u, expected %u", pkt.magic, (u32)PKT_MAGIC);

  printf("%s\n", buf);

  /* Clear receive buffer */
  return 1;
}

int
main(int argc, char *argv[])
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


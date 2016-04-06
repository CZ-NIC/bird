#include "common.h"

static int
do_sendmsg(sock *s, void *pkt, size_t len)
{
  memcpy(s->ttx, pkt, len);
  s->tpos = s->ttx + len;

  if (cf_count && ++counter > cf_count)
    exit(0);

  return sk_write(s);
}

static void
connected_hook(sock *s)
{
  printf("Start sending...\n");
  s->tx_hook = NULL;
}

int
main(int argc, char *argv[])
{
  socktest_bird_init();

  sock *s = socktest_parse_args(argc, argv, 1);
  s->tx_hook = connected_hook;
  s->tbsize = 1500;
  s->tos = IP_PREC_INTERNET_CONTROL;

  socktest_open(s);

  struct socktest_packet pkt = {
      .magic = htonl(PKT_MAGIC),
      .value = htonl(cf_value),
  };

  int count = 0;
  while (1)
  {
    pkt.count = htonl(++count);
    do_sendmsg(s, &pkt, sizeof(pkt));

    usleep(200000);
  }
}

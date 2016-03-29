#include "conf/conf.h"
#include "nest/locks.h"
#include "nest/route.h"
#include "lib/krt.h"

#include "common.h"

static void
parse_addr(char *src, ip_addr *dst)
{
  if (!ipa_pton(src, dst))
  {
    printf("Invalid address %s\n", src);
    exit(-1);
  }
}

static void
parse_int(const char *src, int *dst)
{
  errno = 0;
  *dst = strtol(src, NULL, 10);
  if (errno)
  {
    printf("Invalid number %s\n", src);
    exit(-1);
  }
}

void
err_hook(sock *s, int err)
{
  if (!err)
  {
    printf("Sock EOF \n");
    return;
  }

  printf("Err(%d): %s \n", err, s->err);
  exit(1);
}

void
skt_open(sock *s)
{
  if (sk_open(s) < 0)
    SKT_ERR(s->err);

  sk_set_ttl(s, cf_ttl);

  if (cf_mcast)
    sk_setup_multicast(s);

  if (cf_bcast)
    sk_setup_broadcast(s);
}

sock *
skt_parse_args(int argc, char **argv, int is_send)
{
  int is_recv = !is_send;
  const char *opt_list = is_send ? "umbRi:l:B:p:v:t:" : "um:bRi:l:B:p:v:t:";
  int c;

  cf_value = PKT_VALUE;
  cf_ttl = 1;
  uint port = PKT_PORT;

  sock *s = sk_new(&root_pool);

  /* Raw socket is default type */
  s->type = SK_IP;

  s->err_hook = err_hook;

  while ((c = getopt(argc, argv, opt_list)) >= 0)
    switch (c)
    {
    case 'u':
      s->type = SK_UDP;
      break;
    case 'm':
      cf_mcast = 1;
      if (is_recv)
	parse_addr(optarg, &s->daddr);
      break;
    case 'b':
      cf_bcast = 1;
      break;
    case 'R':
      cf_route = 1;
      break;
    case 'i':
      s->iface = if_get_by_name(optarg);
      break;
    case 'l':
      parse_addr(optarg, &s->saddr);	/* FIXME: Cannot set local address and bind address together */
      break;
    case 'B':
      parse_addr(optarg, &s->saddr);	/* FIXME: Cannot set local address and bind address together */
      s->flags |= SKF_BIND;
      cf_bind = 1;
      break;
    case 'p':
      parse_int(optarg, &port);
      break;
    case 'v':
      parse_int(optarg, &cf_value);
      break;
    case 't':
      parse_int(optarg, &cf_ttl);
      break;

    default:
      goto usage;
    }

  if (is_recv && s->type == SK_UDP)
    s->sport = port;
  else
    s->dport = port;

  if (optind + is_send != argc)
    goto usage;

  if (is_send)
    parse_addr(argv[optind], &s->daddr);

  return s;

 usage:
  printf("Usage: %s [-u] [-m%s|-b] [-B baddr] [-R] [-i iface] [-l addr] [-p port] [-v value] [-t ttl]%s\n",
	 argv[0], is_recv ? " maddr" : "", is_send ? " daddr" : "");
  exit(1);
}

void
bird_init(void)
{
  resource_init();
  io_init();
  if_init();
}

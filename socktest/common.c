#include "conf/conf.h"
#include "nest/locks.h"
#include "nest/route.h"
#include "lib/krt.h"

#include "common.h"

static ip_addr
parse_addr(char *src)
{
  ip_addr dst;
  if (!ipa_pton(src, &dst))
  {
    printf("Invalid address %s\n", src);
    exit(-1);
  }
  return dst;
}

static uint
parse_uint(const char *src)
{
  errno = 0;
  uint dst = strtoul(src, NULL, 10);
  if (errno)
  {
    printf("Invalid number %s\n", src);
    exit(-1);
  }
  return dst;
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
  {
    perror(s->err);
    exit(1);
  }

  if (cf_mcast)
  {
    sk_setup_multicast(s);	/* transmission */
    sk_join_group(s, s->daddr);	/* reception */
  }

  if (cf_bcast)
    sk_setup_broadcast(s);
}

sock *
skt_parse_args(int argc, char *argv[], int is_send)
{
  int is_recv = !is_send;
  const char *opt_list = is_send ? "bumi:l:p:v:t:c:B:" : "bum:i:l:p:v:t:c:B:";
  int c;

  /* Set defaults */
  uint port = PKT_PORT;
  cf_value = PKT_VALUE;
  cf_mcast = cf_bcast = cf_bind = cf_count = counter = 0;

  /* Create socket */
  sock *s = sk_new(&root_pool);
  s->type = SK_IP;
  s->err_hook = err_hook;

  while ((c = getopt(argc, argv, opt_list)) >= 0)
    switch (c)
    {
    case 'u':
      s->type = SK_UDP;
      break;
    case 'c':
      cf_count = parse_uint(optarg);
      break;
    case 'm':
      cf_mcast = 1;
      if (is_recv)
	s->daddr = parse_addr(optarg);
      break;
    case 'b':
      cf_bcast = 1;
      break;
    case 'i':
      s->iface = if_get_by_name(optarg);
      s->iface->index = if_nametoindex(optarg);
      if (s->iface->index == 0)
      {
	printf("No interface exists with the name %s \n", optarg);
	exit(1);
      }
      break;
    case 'B':
      cf_bind = 1;
      s->flags |= SKF_BIND;
      /* fall through */
    case 'l':
      if (ipa_nonzero(s->saddr))
	printf("Redefine source address, don't use -l and -B together \n");
      s->saddr = parse_addr(optarg);
      break;
    case 'p':
      port = parse_uint(optarg);
      break;
    case 'v':
      cf_value = parse_uint(optarg);
      break;
    case 't':
      s->ttl = parse_uint(optarg);
      break;

    default:
      goto usage;
    }

  if (is_recv && s->type == SK_UDP)	/* XXX: Weird */
    s->sport = port;
  else
    s->dport = port;

  if (optind + is_send != argc)
    goto usage;

  if (is_send)
    s->daddr = parse_addr(argv[optind]);

  return s;

 usage:
  printf("Usage: %s [-u] [-c count] [-m%s|-b] [-B bind_addr] [-i iface] [-l fake_local_addr] [-p port] [-v value] [-t ttl]%s\n",
	 argv[0], is_recv ? " maddr" : "", is_send ? " daddr" : "");
  exit(1);
}

static void
scan_infaces(void)
{
  /* create mockup config */
  struct config *c = config_alloc("mockup");
  init_list(&c->protos);
  cfg_mem = c->mem;
  new_config = c;
  new_config->master_rtc = mb_allocz(&root_pool, sizeof(struct rtable_config));

  /* create mockup device protocol */
  protos_build();
  proto_build(&proto_unix_iface);
  struct proto_config *kif_config = kif_init_config(SYM_PROTO);
  kif_config->table = new_config->master_rtc;
  struct proto *krt = proto_unix_iface.init(kif_config);

  /* scan interfaces */
  proto_unix_iface.start(krt);
}

void
bird_init(void)
{
  log_switch(1, NULL, NULL);
  resource_init();
  io_init();
  if_init();
  scan_infaces();
}

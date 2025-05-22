
#include <stdio.h>

#include "mrt.h"
#include "mrt_load.h"


byte
mrtload_one(FILE *fp, u64 *remains)
{
  remains[0]--;
  return fgetc(fp);
}

void
mrtload_n_octet(FILE *fp, u64 *remains, byte *buff, int n)
{
  for (int i = 0; i < n; i++)
    buff[i] = fgetc(fp);

  remains[0] = remains[0] - n;
}

u64
mrtload_four_octet(FILE *fp, u64 *remains)
{
  u64 ret = 0;

  for (int i = 0; i < 4; i++)
  {
    ret = ret << 8;
    ret += fgetc(fp);
  }

  remains[0] = remains[0] - 4;

  return ret;
}

void
mrtload_ip(FILE *fp, u64 *remains, ip_addr *addr, bool is_ip6)
{
  if (is_ip6)
    for (int i = 0; i < 4; i++)
      addr->addr[i] = mrtload_four_octet(fp, remains);
  else
  {
    addr->addr[0] = addr->addr[1] = addr->addr[2] = 0;
    addr->addr[3] = mrtload_four_octet(fp, remains);
  }
}

u32
mrtload_two_octet(FILE *fp, u64 *remains)
{
  remains[0] = remains[0] - 2;
  return (fgetc(fp) << 8) + fgetc(fp);
}

void
mrt_parse_error(struct bgp_parse_state * ps UNUSED, uint e UNUSED)
{
  log(L_WARN "mrt load: run into a parsing error");
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Peer AS Number        |        Local AS Number        |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |        Interface Index        |        Address Family         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Peer IP Address (variable)               |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Local IP Address (variable)              |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    BGP Message... (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Figure 12: BGP4MP_MESSAGE Subtype
*/
void
mrt_parse_bgp_message(FILE *fp, u64 *remains, bool as4)
{
  u64 peer_as, local_as;
  if (as4)
  {
    peer_as = mrtload_four_octet(fp, remains);
    local_as = mrtload_four_octet(fp, remains);
  } else
  {
    peer_as = mrtload_two_octet(fp, remains);
    local_as = mrtload_two_octet(fp, remains);
  }

  int interface_id = mrtload_two_octet(fp, remains);
  int addr_fam = mrtload_two_octet(fp, remains);

  ip_addr peer_addr, local_addr;
  mrtload_ip(fp, remains, &peer_addr, addr_fam == 2);
  mrtload_ip(fp, remains, &local_addr, addr_fam == 2);

  log("peer as %lx local as %lx interface %x add fam %i peer %I loc %I", peer_as, local_as, interface_id, addr_fam, peer_addr, local_addr);
}

static void
mrt_rx_end_mark(struct bgp_parse_state *s UNUSED, u32 afi UNUSED)
{
  /* Do nothing */
}

bool
mrt_get_channel_to_parse(struct bgp_parse_state *s UNUSED, u32 afi UNUSED)
{
  struct mrtload_proto *p = SKIP_BACK(struct mrtload_proto, p, s->p);
  s->channel = &p->channel->c;
  s->last_id = 0;
  s->last_src = s->p->main_source;
  s->desc = p->channel->desc;
  s->channel->proto = s->p;
  channel_set_state(s->channel, CS_START);
  channel_set_state(s->channel, CS_UP);
  return true;
}

static void
mrt_apply_mpls_labels(struct bgp_parse_state *s UNUSED, rta *a UNUSED, u32 *labels UNUSED, uint lnum UNUSED)
{
  /* Do nothing */
}

static void
mrt_parse_bgp4mp_message(FILE *fp, u64 *remains, bool as4, struct proto *P)
{
  mrt_parse_bgp_message(fp, remains, as4);

  if (*remains < 19)
  {
    log(L_WARN "MRT parse BGP message: BGP message is too short (%i)", *remains);
    return;
  }

  for (int i = 0; i < 16; i++) /* skip marker */
    fgetc(fp);

  remains[0] = remains[0] - 16;
  u64 length = mrtload_two_octet(fp, remains) - 16 - 2 -1; /* length without header (marker, length, type) */
  int type = mrtload_one(fp, remains);

  if (type != PKT_UPDATE)
    return;

  /* This is usually done in proto_do_up, but the protocol will be used immediately */
  P->main_source = rt_get_source(P, 0);
  rt_lock_source(P->main_source);

  struct bgp_parse_state s = {
    .pool = lp_new(P->pool),
    .parse_error = mrt_parse_error,
    .end_mark = mrt_rx_end_mark,
    .get_channel = mrt_get_channel_to_parse,
    .apply_mpls_labels = mrt_apply_mpls_labels,
    .is_mrt_parse = 1,
    .p = P,
  };

  byte buf[length];
  ASSERT_DIE(length <= remains[0]);
  mrtload_n_octet(fp, remains, buf, length);
  ea_list *ea = NULL;
  bgp_parse_update(&s, buf, length, &ea);
}

int
mrt_parse_general_header(FILE *fp, struct proto *P)
{
  char is_eof = fgetc(fp);
  u64 timestamp = is_eof;

  if (is_eof == EOF)
    return 0;
  else
  {
    for (int i = 0; i < 3; i++)
    {
      timestamp = timestamp << 8;
      timestamp += fgetc(fp);
    }
  }

  int type = (fgetc(fp) << 8) + fgetc(fp);
  int subtype = (fgetc(fp) << 8) + fgetc(fp);
  u64 length = 0;

  for (int i = 0; i < 4; i++)
  {
    length = length << 8;
    length += fgetc(fp);
  }
  u64 remains = length;

  /* We do not load MRT_TABLE_DUMP_V2 type and MRT_BGP4MP_STATE_CHANGE_AS4. */
  if (type == MRT_BGP4MP)
  {
    switch (subtype)
    {
      case (MRT_BGP4MP_MESSAGE):
      case (MRT_BGP4MP_MESSAGE_LOCAL):
      case (MRT_BGP4MP_MESSAGE_ADDPATH):
        mrt_parse_bgp4mp_message(fp, &remains, false, P);
        break;
      case (MRT_BGP4MP_STATE_CHANGE_AS4):
        break;
      case (MRT_BGP4MP_MESSAGE_AS4):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH):
      case (MRT_BGP4MP_MESSAGE_AS4_ADDPATH):
        mrt_parse_bgp4mp_message(fp, &remains, true,  P);
        break;
    }
  }

  ASSERT_DIE(remains <= length);

  for (u64 i = 0; i < remains; i++)
    fgetc(fp);

  return 1;
}

void
mrtload(struct proto *P)
{
  struct mrt_config *cf = SKIP_BACK(struct mrt_config, c, P->cf);
  FILE *fp = fopen(cf->filename, "r");

  if (fp == NULL)
  {
    log(L_WARN "Can not open file %s", fp);
    return;
  }

  /* Parsing mrt headers in loop. MRT_BGP4MP messages are loaded, the rest is skipped. */
  while (mrt_parse_general_header(fp, P));
}

void
mrtload_check_config(struct proto_config *CF, struct bgp_channel_config *CC)
{
  struct mrtload_config *cf = (void *) CF;

  if (!cf->table_cf)
    cf_error("Table not specified");

  if (!cf->filename)
    cf_error("File not specified");

  if (!CC->desc)
    cf_error("Afi not specified.");
}

static struct proto *
mrtload_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct mrtload_config *mlc = (struct mrtload_config *) CF;
  proto_add_channel(P, &mlc->channel_cf->c);

  return P;
}

static int
mrtload_start(struct proto *P)
{
  struct mrtload_proto *p = (void *) P;
  struct mrtload_config *cf = (void *) (P->cf);

  p->channel = (void *) proto_add_channel(P, &cf->channel_cf->c);

  p->channel->afi = cf->channel_cf->afi;
  p->channel->desc = cf->channel_cf->desc;
  p->channel->c.channel = &channel_mrtload;
  p->channel->c.table = cf->table_cf->table;

  if (cf->channel_cf->igp_table_ip4)
    p->channel->igp_table_ip4 = cf->channel_cf->igp_table_ip4->table;

  if (cf->channel_cf->igp_table_ip6)
    p->channel->igp_table_ip6 = cf->channel_cf->igp_table_ip6->table;

  mrtload(P);

  return PS_UP;
}


static int
mrtload_shutdown(struct proto *P)
{
  struct mrtload_proto *p = (void *) P;
  proto_notify_state(&p->p, PS_DOWN);
  return PS_DOWN;
}

static int
mrtload_reconfigure(struct proto *P, struct proto_config *CF)
{
  //TODO where do we want reload mrt ?
  P->cf = CF;
  mrtload(P);

  return 1;
}


static void
mrtload_copy_config(struct proto_config *dest UNUSED, struct proto_config *src UNUSED)
{
  /* Do nothing */
}

static int
mrtload_channel_start(struct channel *C)
{
  struct mrtload_proto *p = (void *) C->proto;
  struct bgp_channel *c = (void *) C;
  c->pool = p->p.pool;
  return 0;
}

void
mrtload_postconfig(struct proto_config *CF)
{
  struct mrtload_config *cf = (void *) CF;
  if (cf->channel_cf->c.in_filter != FILTER_ACCEPT)
    cf_error("MRT load channel in filter must be set to accept");
  if (cf->channel_cf->c.out_filter != FILTER_REJECT)
    cf_error("MRT load channel out filter must be set to reject");
}


static int
mrtload_channel_reconfigure(struct channel *C UNUSED, struct channel_config *CC UNUSED,
    int *import_changed UNUSED, int *export_changed UNUSED)
{
 struct bgp_channel *c = (void *) C;
 struct bgp_channel_config *new = (void *) CC;
 struct bgp_channel_config *old = c->cf;

 if (old->afi != new->afi)
   return 0;
 if (old->desc != new->desc)
   return 0;
 if (old->c.table != new->c.table)
   return 0;

 if (old->igp_table_ip4)
   if (!new->igp_table_ip4 || old->igp_table_ip4->table != new->igp_table_ip4->table)
     return 0;

 if (old->igp_table_ip6)
   if (!new->igp_table_ip6 || old->igp_table_ip6->table != new->igp_table_ip6->table)
     return 0;

  c->cf = new;
  return 1;
}

const struct channel_class channel_mrtload = {
  .channel_size =	sizeof(struct bgp_channel),
  .config_size =	sizeof(struct bgp_channel_config),
  .init =		bgp_channel_init,
  .start =		mrtload_channel_start,
  .shutdown =		bgp_channel_shutdown,
  .cleanup =		bgp_channel_cleanup,
  .reconfigure =	mrtload_channel_reconfigure,
};


struct protocol proto_mrtload = {
  .name =		"mrtload",
  .template =		"mrt%d",
  .class =		PROTOCOL_MRTLOAD,
  .proto_size =		sizeof(struct mrtload_proto),
  .config_size =	sizeof(struct mrt_config),
  .init =		mrtload_init,
  .start =		mrtload_start,
  .shutdown =		mrtload_shutdown,
  .reconfigure =	mrtload_reconfigure,
  .postconfig =         mrtload_postconfig,
  .copy_config =	mrtload_copy_config,
  .channel_mask =	NB_IP | NB_VPN | NB_FLOW | NB_MPLS,
};

void
mrtload_build(void)
{
  proto_build(&proto_mrtload);
}

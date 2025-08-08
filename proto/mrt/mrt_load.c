
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
  {
    for (int i = 0; i < 4; i++)
      addr->addr[i] = mrtload_four_octet(fp, remains);
  }
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
  bug(L_WARN "mrt load: run into a parsing error");
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
mrtload_fill_parse_state(struct mrtload_proto *p, struct bgp_parse_state *s)
{
  s->proto_name = p->p.name;
  s->pool = lp_new(p->p.pool);
  s->parse_error = mrt_parse_error;
  s->end_mark = mrt_rx_end_mark;
  s->get_channel = mrt_get_channel_to_parse;
  s->apply_mpls_labels = mrt_apply_mpls_labels;
  s->is_mrt_parse = 1;
  s->p = &p->p;
  s->desc = p->channel->desc; // desc is set later in bgp, but we need afi to compare
}

struct mrtload_route_ctx *
mrtload_create_ctx(struct mrtload_proto *p, int addr_fam, int local_as, int peer_as, ip_addr local_ip, ip_addr remote_ip, u8 is_internal)
{
  struct mrtload_route_ctx *route_attrs = (struct mrtload_route_ctx *) mb_allocz(p->ctx_pool, sizeof(struct mrtload_route_ctx));
 
  route_attrs->src = rt_get_source(&p->p, p->source_cnt);
  rt_lock_source(route_attrs->src);
  p->source_cnt++;
 
  route_attrs->addr_fam = addr_fam;
  route_attrs->ctx.local_as = local_as;
  route_attrs->ctx.remote_as = peer_as;
  route_attrs->ctx.local_ip = local_ip;
  route_attrs->ctx.remote_ip = remote_ip;
  route_attrs->ctx.is_internal = is_internal;

  route_attrs->ctx.bgp_rte_ctx.proto_class = PROTOCOL_BGP;
  route_attrs->ctx.bgp_rte_ctx.rte_better = bgp_rte_better;
  route_attrs->ctx.bgp_rte_ctx.rte_recalculate = NULL; //cf->deterministic_med ? bgp_rte_recalculate
  route_attrs->ctx.bgp_rte_ctx.format = bgp_format_rte_ctx;

    // TODO: this is not the correct setting
  route_attrs->ctx.local_id = proto_get_router_id(p->p.cf);
  route_attrs->ctx.remote_id = 0;
  route_attrs->ctx.rr_client = 0;
  route_attrs->ctx.rs_client = 0;
  route_attrs->ctx.is_interior = route_attrs->ctx.is_internal;  //TODO this should be loaded from somewhere

  return route_attrs;
}

/*
0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Peer Index            |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Originated Time                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |      Attribute Length         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                    BGP Attributes... (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

void
mrt_parse_rib_entry(struct mrtload_proto *p, FILE *fp, byte *prefix_data, uint prefix_data_len, u64 *remains, bool add_path, u32 afi)
{
  struct bgp_parse_state s;
  memset(&s, 0, sizeof(struct bgp_parse_state));
  mrtload_fill_parse_state(p, &s);
  s.last_src = p->p.main_source;
  /* All AS numbers in the AS_PATH attribute MUST be encoded as 4-byte AS numbers. */
  s.as4_session = 1;
  s.allow_as_sets = 1; /* If not set to 1 and there is an as_set, bird will crash */
  s.channel = &p->channel->c;

  int peer_index = mrtload_two_octet(fp, remains);
  mrtload_four_octet(fp, remains); /* originated time - but for table load time is not relevant */
  ASSERT_DIE(peer_index <= p->table_peers_count);
  struct mrtload_peer_entry *peer = &p->table_peers[peer_index];
  s.proto_attrs = &peer->route_attrs->ctx;
 
  if (afi != 0)
  {
    if (afi != peer->afi)
      return;
  } else
    afi = peer->afi;

  if (add_path)
    s.add_path = mrtload_four_octet(fp, remains);

  u64 attr_len = mrtload_two_octet(fp, remains);
  byte data[attr_len];
  mrtload_n_octet(fp, remains, data, attr_len);

  if (afi != p->addr_fam)
    return;

  ea_list *ea = bgp_decode_attrs(&s, data, attr_len);

  /* 
   * In order to reuse bgp functions, prefix is parsed peer_count times.
   * It is not the fastest way, but it is much safer and comfortable way.
   */
  rta *a = allocz(RTA_MAX_SIZE);

  a->source = RTS_BGP;
  a->scope = SCOPE_UNIVERSE;
  a->from = s.remote_ip;
  a->eattrs = ea;
  a->pref = s.channel->preference;
  a->dest = RTD_UNREACHABLE;

  s.desc->decode_next_hop(&s, s.ip_next_hop_data, s.ip_next_hop_len, a);
  bgp_finish_attrs(&s, a);

  s.desc->decode_nlri(&s, prefix_data, prefix_data_len, a);

  rta_free(a);
}

/*

        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Sequence Number                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |    Address Family Identifier  |Subsequent AFI |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |     Network Layer Reachability Information (variable)         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Entry Count           |  RIB Entries (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 9: RIB_GENERIC Entry Header
*/

void
mrt_parse_rib_generic(struct mrtload_proto *p, FILE *fp, u64 *remains, bool add_path)
{
  mrtload_four_octet(fp, remains); /* sequence number */
  int afi = mrtload_two_octet(fp, remains);
  mrtload_one(fp, remains); /* safi */

  u8 nlri_len = mrtload_one(fp, remains);
  nlri_len = (nlri_len + 7)/8;
  byte prefix[nlri_len];
  mrtload_n_octet(fp, remains, prefix, nlri_len);
  u16 entry_count = mrtload_two_octet(fp, remains);

  for (int i = 0; i < entry_count; i++)
    mrt_parse_rib_entry(p, fp, prefix, nlri_len, remains, add_path, afi);
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Sequence Number                       |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       | Prefix Length |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Prefix (variable)                      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |         Entry Count           |  RIB Entries (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-
*/
void
mrt_parse_rib4_unicast(struct mrtload_proto *p, FILE *fp, u64 *remains, bool add_path)
{
  mrtload_four_octet(fp, remains); /* sequence number */
  u8 pref_len = mrtload_one(fp, remains);
  byte prefix[(pref_len + 7)/8 +1];
  prefix[0] = pref_len;
  pref_len = (pref_len + 7)/8;
  mrtload_n_octet(fp, remains, &(prefix[1]), pref_len);
  pref_len ++; /* include the lenght od pref_len itself */
  int entry_count = mrtload_two_octet(fp, remains);

  for (int i = 0; i < entry_count; i++)
    mrt_parse_rib_entry(p, fp, prefix, pref_len, remains, add_path, 0);
}

/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |   Peer Type   |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                         Peer BGP ID                           |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                   Peer IP Address (variable)                  |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                        Peer AS (variable)                     |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                          Figure 6: Peer Entries
*/

void
mrt_parse_peer(struct mrtload_proto *p, FILE *fp, u64 *remains, struct mrtload_peer_entry *peer)
{
  int peer_type = mrtload_one(fp, remains);
  peer->afi = (peer_type & 1) ? AFI_IPV6 : AFI_IPV4;
  peer->peer_id = mrtload_four_octet(fp, remains);
  mrtload_ip(fp, remains, &peer->peer_ip, peer_type & MRT_PEER_TYPE_IPV6);

  if (peer_type & MRT_PEER_TYPE_32BIT_ASN)
    peer->peer_as = mrtload_four_octet(fp,remains);
  else
    peer->peer_as = mrtload_two_octet(fp, remains);

  peer->route_attrs = mrtload_create_ctx(p, p->addr_fam, p->local_as, peer->peer_as, p->local_ip, peer->peer_ip, p->is_internal);
}


/*
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |                      Collector BGP ID                         |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |       View Name Length        |     View Name (variable)      |
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
       |          Peer Count           |    Peer Entries (variable)
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Figure 5: PEER_INDEX_TABLE Subtype
*/

void
mrt_parse_peer_index_table(struct mrtload_proto *p, FILE *fp, u64 *remains)
{
  mrtload_four_octet(fp, remains); /* Collector BGP ID, in mrt.c config->router_id */
  int name_len = mrtload_two_octet(fp, remains);
  char name[name_len + 1];
  name[name_len] = 0;
  mrtload_n_octet(fp, remains, name, name_len);
  int peer_count = mrtload_two_octet(fp, remains);

  if (p->table_peers)
    mb_free(p->table_peers);

  p->table_peers = mb_alloc(p->p.pool, sizeof(struct mrtload_peer_entry) * peer_count);
  p->table_peers_count = peer_count;

  for (int i = 0; i < peer_count; i++)
    mrt_parse_peer(p, fp, remains, &p->table_peers[i]);
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
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-

                     Figure 12: BGP4MP_MESSAGE Subtype
*/
struct mrtload_route_ctx *
mrt_parse_bgp_message(FILE *fp, u64 *remains, bool as4, bool insert_hash, struct mrtload_proto *p)
{
  u64 peer_as;
  u64 local_as;
  ip_addr remote_ip;
  ip_addr local_ip;

  if (as4)
  {
    peer_as = mrtload_four_octet(fp, remains);
    local_as = mrtload_four_octet(fp, remains);
  } else
  {
    peer_as = mrtload_two_octet(fp, remains);
    local_as = mrtload_two_octet(fp, remains);
  }

  int is_internal = (peer_as == local_as);
  mrtload_two_octet(fp, remains); /* Interface index. It might be usefull,
      but "is OPTIONAL and MAY be zero" */
  int addr_fam = mrtload_two_octet(fp, remains);

  mrtload_ip(fp, remains, &remote_ip, addr_fam == 2);
  mrtload_ip(fp, remains, &local_ip, addr_fam == 2);

  struct mrtload_route_ctx *route_attrs = HASH_FIND(p->ctx_hash, MRTLOAD_CTX, peer_as, local_as, remote_ip, local_ip);

  if (!route_attrs && insert_hash)
  {
    route_attrs = mrtload_create_ctx(p, addr_fam, local_as, peer_as, local_ip, remote_ip, is_internal);

    HASH_INSERT(p->ctx_hash, MRTLOAD_CTX, route_attrs);
  }
  return route_attrs;
}

void
mrt_parse_bgp4mp_change_state(struct mrtload_proto *p, FILE *fp, u64 *remains, bool as4)
{
  struct mrtload_route_ctx *ra = mrt_parse_bgp_message(fp, remains, as4, false, p);
  mrtload_two_octet(fp, remains); /* old state */
  int new_state = mrtload_two_octet(fp, remains);

  if (new_state == 1 && ra && ra->addr_fam == (int)(p->channel->afi >> 16)) /* state 1 - Idle (rfc 1771) */
  {
    FIB_WALK(&p->channel->c.table->fib, net, n)
    {
      rte *e = n->routes;
 
      while(e)
      {
        rte *next = e->next;

        if (e->sender == &p->channel->c && e->src == ra->src)
          rte_update2(&p->channel->c, e->net->n.addr, NULL, p->p.main_source);

        e = next;
      }
    }
    FIB_WALK_END;
  
    HASH_DO_REMOVE(p->ctx_hash, MRTLOAD_CTX, &ra);
    mb_free(ra);
  }
}

static void
mrt_parse_bgp4mp_message(struct mrtload_proto *p, FILE *fp, u64 *remains, bool as4)
{
  struct mrtload_route_ctx *proto_attrs = mrt_parse_bgp_message(fp, remains, true, as4, p);

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

  /* in case of new peer, the peer has already been added to hash table 
   * (TODO: it was added to hash table without considering the PKT type) */
  if (type != PKT_UPDATE)
    return;

  struct bgp_parse_state s = {
    .as4_session = as4,
    .last_src = proto_attrs->src,
    .proto_attrs = &proto_attrs->ctx,
  };
 
  mrtload_fill_parse_state(p, &s);

  byte buf[length];
  ASSERT_DIE(length <= remains[0]);
  mrtload_n_octet(fp, remains, buf, length);
  ea_list *ea = NULL;
  bgp_parse_update(&s, buf, length, &ea);
}

u64
mrt_parse_timestamp(FILE *fp)
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
  return timestamp;
}

int
mrt_parse_general_header(FILE *fp, struct mrtload_proto *p)
{
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
        mrt_parse_bgp4mp_change_state(p, fp, &remains, false);
        break;
      case (MRT_BGP4MP_MESSAGE_LOCAL):
      case (MRT_BGP4MP_MESSAGE_ADDPATH):
        mrt_parse_bgp4mp_message(p, fp, &remains, false);
        break;
      case (MRT_BGP4MP_STATE_CHANGE_AS4):
        mrt_parse_bgp4mp_change_state(p, fp, &remains, true);
        break;
      case (MRT_BGP4MP_MESSAGE_AS4):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH):
      case (MRT_BGP4MP_MESSAGE_AS4_ADDPATH):
        mrt_parse_bgp4mp_message(p, fp, &remains, true);
        break;
      default:
        log(L_WARN "mrtload: unknown mrt table dump subtype %i", subtype);
    }
  } else if (type == MRT_TABLE_DUMP_V2)
  {
    switch (subtype)
    {
      case (MRT_PEER_INDEX_TABLE):
        mrt_parse_peer_index_table(p, fp, &remains);
        break;
      case (MRT_RIB_IPV4_UNICAST):
      case (MRT_RIB_IPV6_UNICAST):
      case (MRT_RIB_IPV4_MULTICAST):
      case (MRT_RIB_IPV6_MULTICAST):
        mrt_parse_rib4_unicast(p, fp, &remains, false);
        break;
      case (MRT_RIB_IPV4_UNICAST_ADDPATH):
      case (MRT_RIB_IPV6_UNICAST_ADDPATH):
      case (MRT_RIB_IPV4_MULTICAST_ADDPATH):
      case (MRT_RIB_IPV6_MULTICAST_ADDPATH):
        mrt_parse_rib4_unicast(p, fp, &remains, true);
        break;
      case (MRT_RIB_GENERIC):
        mrt_parse_rib_generic(p, fp, &remains, false);
        break;
      case (MRT_RIB_GENERIC_ADDPATH):
        mrt_parse_rib_generic(p, fp, &remains, true);
        break;
      default:
        log(L_WARN "mrtload: unknown mrt table dump subtype %i", subtype);
    }
  } else
    log(L_WARN "mrtload: unknown mrt table type %i", type);


  ASSERT_DIE(remains <= length);

  for (u64 i = 0; i < remains; i++)
    fgetc(fp);

  return length;
}

void
mrtload_hook(timer *tm)
{
  struct mrtload_proto *p = tm->data;
  int loaded = 0;
  btime stamp;

  while (loaded < 1<<14)
  {
    loaded += mrt_parse_general_header(p->parsed_file, p);
    stamp = mrt_parse_timestamp(p->parsed_file); /* timestamp from next header */
 
    if (stamp == 0)
      return;
  }

  tm_start(p->load_timer, 10000);
}

void
mrtload_hook_replay(timer *tm)
{
  struct mrtload_proto *p = tm->data;
  int loaded = 0;
  s64 time = p->next_time;

  while (time == p->next_time && loaded < 1<<14)
  {
    loaded += mrt_parse_general_header(p->parsed_file, p);
    time = mrt_parse_timestamp(p->parsed_file); /* timestamp from next header */
  }

  /* mrt time is in seconds, bird count in microseconds */
  s64 shift_from_start = ((time - p->zero_time) * 1000000) / p->time_replay;
  s64 wait_time = shift_from_start + p->start_time - current_time();
  p->next_time = time;

  tm_start(p->load_timer, wait_time);
}

void
mrtload(struct mrtload_proto *p)
{
  struct mrtload_config *cf = (void *) (p->p.cf);
  p->parsed_file = fopen(cf->filename, "r");

  if (p->parsed_file == NULL)
  {
    log(L_WARN "Can not open file %s", cf->filename);
    return;
  }

  p->load_timer->data = p;
 
  if (!cf->time_replay)
  {
    p->load_timer->hook = mrtload_hook;

    if (mrt_parse_timestamp(p->parsed_file))
      tm_start(p->load_timer, 0);
    return;
  }

  p->load_timer->hook = mrtload_hook_replay;
  p->time_replay = cf->time_replay;
  p->start_time = current_time();
  p->zero_time = mrt_parse_timestamp(p->parsed_file);
  p->next_time = p->zero_time;

  if (p->zero_time)
    tm_start(p->load_timer, 0);
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

  p->deterministic_med = cf->deterministic_med;
  p->default_local_pref = cf->default_local_pref;
  p->compare_path_lengths = cf->compare_path_lengths;
  p->confederation = cf->confederation;
  p->med_metric = cf->med_metric;
  p->default_med = cf->default_med;
  p->igp_metric = cf->igp_metric;
  p->prefer_older = cf->prefer_older;
  p->channel = (void *) proto_add_channel(P, &cf->channel_cf->c);

  p->channel->afi = cf->channel_cf->afi;
  p->channel->desc = cf->channel_cf->desc;
  p->channel->c.channel = &channel_mrtload;
  p->channel->c.table = cf->table_cf->table;
  p->addr_fam = cf->table_cf->table->addr_type;
  p->ctx_pool = rp_new(P->pool, "Mrtload route ctx");
  p->source_cnt = 0;
  p->load_timer = tm_new(P->pool);
  HASH_INIT(p->ctx_hash, p->ctx_pool, 10);

  ASSERT_DIE(cf->table_cf->table);
  struct rtable_config **def_tables = cf->c.global->def_tables;

  if (cf->table_cf->table->addr_type == NET_IP4)
  {
    p->channel->igp_table_ip4 = cf->table_cf->table;
    p->channel->igp_table_ip6 = def_tables[NET_IP6]->table;
  }

  if (cf->table_cf->table->addr_type == NET_IP6)
  {
    p->channel->igp_table_ip6 = cf->table_cf->table;
    p->channel->igp_table_ip4 = def_tables[NET_IP4]->table;
  }

  ASSERT_DIE(p->channel->igp_table_ip6 || p->channel->igp_table_ip4);

  mrtload(p);

  return PS_UP;
}


static int
mrtload_shutdown(struct proto *P)
{
  struct mrtload_proto *p = (void *) P;

  FIB_WALK(&p->channel->c.table->fib, net, n)
  {
    rte *e = n->routes;
    while(e)
    {
      rte *next = e->next;
      rte_update2(&p->channel->c, e->net->n.addr, NULL, P->main_source);
      e = next;
    }
  }
  FIB_WALK_END;

  HASH_FREE(p->ctx_hash);

  if (p->table_peers)
  {
    for (int i = 0; i < p->table_peers_count; i++)
      mb_free(p->table_peers[i].route_attrs);
    mb_free(p->table_peers);
  }

  proto_notify_state(&p->p, PS_DOWN);
  return PS_DOWN;
}

static int
mrtload_reconfigure(struct proto *P, struct proto_config *CF)
{
  P->cf = CF;
  struct mrtload_proto *p = (void *) P;
  mrtload(p);

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

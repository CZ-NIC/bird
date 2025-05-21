
#include "mrt.h"
#include <stdio.h>


byte
mrt_load_one(FILE *fp, u64 *remains)
{
  remains[0]--;
  return fgetc(fp);
}

void
mrt_load_n_octet(FILE *fp, u64 *remains, byte *buff, int n)
{
  for (int i = 0; i < n; i++)
    buff[i] = fgetc(fp);
  remains[0] = remains[0] - n;
}

u64
mrt_load_four_octet(FILE *fp, u64 *remains)
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
mrt_load_ip(FILE *fp, u64 *remains, ip_addr *addr, bool is_ip6)
{
  if (is_ip6)
    for (int i = 0; i < 4; i++)
      addr->addr[i] = mrt_load_four_octet(fp, remains);
  else
  {
    addr->addr[0] = addr->addr[1] = addr->addr[2] = 0;
    addr->addr[3] = mrt_load_four_octet(fp, remains);
  }
}

u32
mrt_load_two_octet(FILE *fp, u64 *remains)
{
  remains[0] = remains[0] - 2;
  return (fgetc(fp) << 8) + fgetc(fp);
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
mrt_parse_peer(FILE *fp, u64 *remains)
{
  int peer_type = mrt_load_one(fp, remains);
  u64 peer_bgp_id = mrt_load_four_octet(fp, remains);
  ip_addr addr;
  u64 peer_as;
  mrt_load_ip(fp, remains, &addr, peer_type & MRT_PEER_TYPE_IPV6);

  if (peer_type & MRT_PEER_TYPE_32BIT_ASN)
    peer_as = mrt_load_four_octet(fp,remains);
  else
    peer_as = mrt_load_two_octet(fp, remains);
  log("peer type %i, bgp id %li adddr %I as %li", peer_type, peer_bgp_id, addr, peer_as);
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
mrt_parse_peer_index_table(FILE *fp, u64 *remains)
{
  u64 collector = mrt_load_four_octet(fp, remains);
  int name_len = mrt_load_two_octet(fp, remains);
  log("name len %i collector %lx", name_len, collector);
  char name[name_len + 1];
  name[name_len] = 0;
  mrt_load_n_octet(fp, remains, name, name_len);
  int peer_count = mrt_load_two_octet(fp, remains);
  log("name %s, count %i", name, peer_count);

  for (int i = 0; i < peer_count; i++)
    mrt_parse_peer(fp, remains);
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
mrt_parse_rib_entry(FILE *fp, u64 *remains, bool add_path)
{
  int peer_index = mrt_load_two_octet(fp, remains);
  u64 orig_time = mrt_load_four_octet(fp, remains);
  u64 path_id;

  if (add_path)
    path_id = mrt_load_four_octet(fp, remains);

  int attr_len = mrt_load_two_octet(fp, remains);
  log("rib entry index %lx, time %lx, attr len %i (rem %li) path %li", peer_index, orig_time, attr_len, *remains, path_id);
  //TODO how are encoded the attrs?
  remains[0] = remains[0] - attr_len;

  for (int i = 0; i < attr_len; i++)
    fgetc(fp);
}


void
mrt_parse_rib_generic(FILE *fp, u64 *remains)
{
  u64 seq_num = mrt_load_four_octet(fp, remains);
  int addr_fam_id = mrt_load_two_octet(fp, remains);
  int subs_afi = mrt_load_one(fp, remains);
  log("seq num %lx, fam %i, subs %i", seq_num, addr_fam_id, subs_afi);
  //TODO length of Network layer reachebility
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
       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
void
mrt_parse_rib4_unicast(FILE *fp, u64 *remains, bool add_path)
{
  u64 seq_num = mrt_load_four_octet(fp, remains);
  int pref_len = mrt_load_one(fp, remains);
  byte prefix[pref_len/8];
  mrt_load_n_octet(fp, remains, prefix, pref_len/8);
  int entry_count = mrt_load_two_octet(fp, remains);
  log("seq %lx, pref len %i, enties %i", seq_num, pref_len, entry_count);

  for (int i = 0; i < entry_count; i++)
    mrt_parse_rib_entry(fp, remains, add_path);
}


void
mrt_parse_error(struct bgp_parse_state * UNUSED, uint UNUSED)
{
  log("run into a parsing error");
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
    peer_as = mrt_load_four_octet(fp, remains);
    local_as = mrt_load_four_octet(fp, remains);
  } else
  {
    peer_as = mrt_load_two_octet(fp, remains);
    local_as = mrt_load_two_octet(fp, remains);
  }

  int interface_id = mrt_load_two_octet(fp, remains);
  int addr_fam = mrt_load_two_octet(fp, remains);

  ip_addr peer_addr, local_addr;
  mrt_load_ip(fp, remains, &peer_addr, addr_fam == 2);
  mrt_load_ip(fp, remains, &local_addr, addr_fam == 2);

  log("peer as %lx local as %lx interface %x add fam %i peer %I loc %I", peer_as, local_as, interface_id, addr_fam, peer_addr, local_addr);
}


void
mrt_parse_bgp4mp_message(FILE *fp, u64 *remains, bool as4)
{
  log("hereeeee bgp message");
  mrt_parse_bgp_message(fp, remains, as4);

  if (*remains < 23)
  {
    log(L_WARN "MRT parse BGP message: BGP message is too short (%i)", *remains);
    return;
  }

  for (int i = 0; i < 16; i++) // marker
    fgetc(fp);

  remains[0] = remains[0] - 16;
  int length = mrt_load_two_octet(fp, remains);
  int type = mrt_load_one(fp, remains);
  log("message type %i", type);

  if (type != PKT_UPDATE)
  {
    log("Another BGP type");
    return;
  }

  struct bgp_parse_state s = {
    .pool = lp_new(&root_pool),
  };
  byte buf[length];
  mrt_load_n_octet(fp, remains, buf, length);
  ea_list *ea = NULL;
  log("try to parse bgp update");
  bgp_parse_update(&s, buf, length, &ea, bgp_parse_error);
  log("ok, seems parsed?");
}


void
mrt_parse_bgp4mp_change_state(FILE *fp, u64 *remains, bool as4)
{
  mrt_parse_bgp_message(fp, remains, as4);
  int old_state = mrt_load_two_octet(fp, remains);
  int new_state = mrt_load_two_octet(fp, remains);
  log("old state %i new state %i", old_state, new_state);
}


int
mrt_parse_general_header(FILE *fp)
{
  char is_eof = fgetc(fp);
  u64 timestamp = is_eof;

  if (is_eof == EOF)
    return 0;
  else
  {
    for (int i = 0; i < 3; i++)
    {
      log("t %lx", timestamp);
      timestamp = timestamp << 8;
      timestamp += fgetc(fp);
    }
  }

  log("timestamp is %lx", timestamp);
  int type = (fgetc(fp) << 8) + fgetc(fp);
  int subtype = (fgetc(fp) << 8) + fgetc(fp);
  log("type is %i, subtype %x", type, subtype);
  u64 length = 0;

  for (int i = 0; i < 4; i++)
  {
    length = length << 8;
    length += fgetc(fp);
  }
  u64 remains = length;
  log("remains is %li", remains);

  if (type == MRT_TABLE_DUMP_V2)
  {
    switch (subtype)
    {
    case (MRT_PEER_INDEX_TABLE):
      mrt_parse_peer_index_table(fp, &remains);
      break;
    case (MRT_RIB_IPV4_UNICAST):
    case (MRT_RIB_IPV6_UNICAST):
    case (MRT_RIB_IPV4_MULTICAST):
    case (MRT_RIB_IPV6_MULTICAST):
      mrt_parse_rib4_unicast(fp, &remains, false);
      break;
    case (MRT_RIB_IPV4_UNICAST_ADDPATH):
    case (MRT_RIB_IPV6_UNICAST_ADDPATH):
    case (MRT_RIB_IPV4_MULTICAST_ADDPATH):
    case (MRT_RIB_IPV6_MULTICAST_ADDPATH):
      mrt_parse_rib4_unicast(fp, &remains, true);
      break;
    case (MRT_RIB_GENERIC):
    case (MRT_RIB_GENERIC_ADDPATH):
      mrt_parse_rib_generic(fp, &remains);
      break;
    default:
      bug("mrt: unknown mrt table dump subtype");
    }
  } else
  {
    ASSERT_DIE(type == MRT_BGP4MP);

    switch (subtype)
    {
      case (MRT_BGP4MP_MESSAGE):
      case (MRT_BGP4MP_MESSAGE_LOCAL):
      case (MRT_BGP4MP_MESSAGE_ADDPATH):
        mrt_parse_bgp4mp_message(fp, &remains, false);
        break;
      case (MRT_BGP4MP_STATE_CHANGE_AS4):
        mrt_parse_bgp4mp_change_state(fp, &remains, true);
        break;
      case (MRT_BGP4MP_MESSAGE_AS4):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL):
      case (MRT_BGP4MP_MESSAGE_AS4_LOCAL_ADDPATH):
      case (MRT_BGP4MP_MESSAGE_AS4_ADDPATH):
        mrt_parse_bgp4mp_message(fp, &remains, true);
        break;
    }
  }

  ASSERT_DIE(remains < length);

  for (u64 i = 0; i < remains; i++)
    fgetc(fp);

  return 1;
}


void
mrt_load(char *file)
{
  FILE *fp = fopen(file, "r");

  if (fp == NULL)
  {
    log(L_WARN "Can not open file %s", fp);
    return;
  }
  
  while (mrt_parse_general_header(fp));
}

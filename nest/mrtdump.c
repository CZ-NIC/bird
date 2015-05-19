/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/mrtdump.h"

void
mrt_msg_init(struct mrt_msg *msg, pool *mem_pool)
{
  msg->mem_pool = mem_pool;
  msg->msg_capacity = MRT_MSG_DEFAULT_CAPACITY;
  msg->msg_length = 0;
  msg->msg = mb_alloc(msg->mem_pool, msg->msg_capacity);
}

void
mrt_msg_free(struct mrt_msg *msg)
{
  mb_free(msg->msg);
}

static byte *
mrt_peer_index_table_get_peer_count(struct mrt_peer_index_table *pit_msg)
{
  struct mrt_msg * msg = pit_msg->msg;
  uint collector_bgp_id_size = 4;
  uint name_length_size = 2;
  uint name_size = pit_msg->name_length;
  uint peer_count_offset = collector_bgp_id_size + name_length_size + name_size;
  return &(msg->msg[peer_count_offset]);
}

static void
mrt_grow_msg_buffer(struct mrt_msg * msg, size_t min_required_capacity)
{
  msg->msg_capacity *= 2;
  if (min_required_capacity > msg->msg_capacity)
    msg->msg_capacity = min_required_capacity;
  msg->msg = mb_realloc(msg->msg, msg->msg_capacity);
}

static void
mrt_write_to_msg(struct mrt_msg * msg, const void *data, size_t data_size)
{
  if (data_size == 0)
    return;

  u32 i;
  for (i = 0; i < data_size; i++)
    debug("%02X ", ((byte*)data)[i]);
  debug("| ");

  size_t required_size = data_size + msg->msg_length;
  if (msg->msg_capacity < required_size)
    mrt_grow_msg_buffer(msg, required_size);

  memcpy(&msg->msg[msg->msg_length], data, data_size);
  msg->msg_length += data_size;
}
#define mrt_write_to_msg_(msg, data) mrt_write_to_msg(msg, &data, sizeof(data))

void
mrt_peer_index_table_init(struct mrt_peer_index_table *pit_msg, u32 collector_bgp_id, const char *name)
{
  struct mrt_msg * msg = pit_msg->msg;
  pit_msg->peer_count = 0;
  pit_msg->name_length = strlen(name);

  mrt_write_to_msg_(msg, collector_bgp_id);
  mrt_write_to_msg_(msg, pit_msg->name_length);
  mrt_write_to_msg(msg, name, pit_msg->name_length);
  mrt_write_to_msg_(msg, pit_msg->peer_count);
  debug("\n");
}

static void
mrt_peer_index_table_inc_peer_count(struct mrt_peer_index_table *pit_msg)
{
  pit_msg->peer_count++;
  byte *peer_count = mrt_peer_index_table_get_peer_count(pit_msg);
  put_u16(peer_count, pit_msg->peer_count);
}

void
mrt_peer_index_table_add_peer(struct mrt_peer_index_table *pit_msg, u32 peer_bgp_id, ip_addr *peer_ip_addr, u32 peer_as)
{
  struct mrt_msg * msg = pit_msg->msg;

  u8 peer_type = PEER_TYPE_AS_32BIT;
  if (sizeof(*peer_ip_addr) > sizeof(ip4_addr))
    peer_type |= PEER_TYPE_IPV6;

  mrt_write_to_msg_(msg, peer_type);
  mrt_write_to_msg_(msg, peer_bgp_id);
  mrt_write_to_msg_(msg, *peer_ip_addr);
  mrt_write_to_msg_(msg, peer_as);

  mrt_peer_index_table_inc_peer_count(pit_msg);
  debug("\n");
}

void
mrt_rib_table_init(struct mrt_rib_table *rt_msg, u32 sequence_number, u8 prefix_length, ip_addr *prefix)
{
  struct mrt_msg *msg = rt_msg->msg;

  rt_msg->entry_count = 0;

  mrt_write_to_msg_(msg, sequence_number);
  mrt_write_to_msg_(msg, prefix_length);
  mrt_write_to_msg_(msg, *prefix);
  mrt_write_to_msg_(msg, rt_msg->entry_count);
  debug("\n");
}

static byte *
mrt_rib_table_get_entry_count(struct mrt_rib_table *rt_msg)
{
  struct mrt_msg *msg = rt_msg->msg;
  u32 sequence_number_size = 4;
  u32 prefix_length_size = 1;

  u32 prefix_size = 4;
  if (rt_msg->type == RIB_IPV4_UNICAST)
    prefix_size = 4;
  else if (rt_msg->type == RIB_IPV6_UNICAST)
    prefix_size = 16;
  else
    bug("mrt_rib_table_get_entry_count: unknown RIB type!");

  u32 offset = sequence_number_size + prefix_length_size + prefix_size;
  return &msg->msg[offset];
}

static void
mrt_rib_table_inc_entry_count(struct mrt_rib_table *rt_msg)
{
  rt_msg->entry_count++;
  byte *entry_count = mrt_rib_table_get_entry_count(rt_msg);
  put_u16(entry_count, rt_msg->entry_count);
}

void
mrt_rib_table_add_entry(struct mrt_rib_table *rt_msg, const struct mrt_rib_entry *rib)
{
  struct mrt_msg *msg = rt_msg->msg;

  mrt_write_to_msg_(msg, rib->peer_index);
  mrt_write_to_msg_(msg, rib->originated_time);
  mrt_write_to_msg_(msg, rib->attributes_length);
  mrt_write_to_msg(msg, rib->attributes, rib->attributes_length);

  mrt_rib_table_inc_entry_count(rt_msg);
  debug("\n");
}

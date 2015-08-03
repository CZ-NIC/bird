/*
 *	BIRD -- Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#undef LOCAL_DEBUG

#include "nest/mrtdump.h"
#include "nest/route.h"

/*
 * MRTDump: Table Dump: Base
 */

static void
mrt_buffer_reset(struct mrt_buffer *buf)
{
  buf->msg_capacity = MRT_BUFFER_DEFAULT_CAPACITY;
  buf->msg_length = MRT_HDR_LENGTH;	/* Reserved for the main MRT header */
}

void
mrt_buffer_alloc(struct mrt_buffer *buf)
{
  mrt_buffer_reset(buf);
  buf->msg = mb_allocz(&root_pool, buf->msg_capacity);
}

void
mrt_buffer_free(struct mrt_buffer *buf)
{
  if (buf->msg != NULL)
  {
    mb_free(buf->msg);
    buf->msg = NULL;
  }
}

static void
mrt_buffer_enlarge(struct mrt_buffer *buf, size_t min_required_capacity)
{
  if (min_required_capacity > buf->msg_capacity)
  {
    buf->msg_capacity *= 2;
    if (min_required_capacity > buf->msg_capacity)
      buf->msg_capacity = min_required_capacity;
    buf->msg = mb_realloc(buf->msg, buf->msg_capacity);
  }
}

/*
 * Return pointer to the actual position in the msg buffer
 */
static byte *
mrt_buffer_get_cursor(struct mrt_buffer *buf)
{
  return &buf->msg[buf->msg_length];
}

static void
mrt_buffer_write_show_debug(struct mrt_buffer *buf, size_t data_size)
{
#if defined(LOCAL_DEBUG) || defined(GLOBAL_DEBUG)
  byte *data = mrt_buffer_get_cursor(buf) - data_size;
#endif
  DBG("(%d) ", data_size);
  u32 i;
  for (i = 0; i < data_size; i++)
    DBG("%02X ", data[i]);
  DBG("| ");
}

static void
mrt_buffer_put_raw(struct mrt_buffer *buf, const void *data, size_t data_size)
{
  if (data_size == 0)
    return;

  size_t required_size = data_size + buf->msg_length;
  mrt_buffer_enlarge(buf, required_size);

  memcpy(mrt_buffer_get_cursor(buf), data, data_size);
  buf->msg_length += data_size;

  mrt_buffer_write_show_debug(buf, data_size);
}

static void
mrt_buffer_put_ipa(struct mrt_buffer *buf, ip_addr addr, size_t write_size)
{
  ip_addr addr_network_formatted = ipa_hton(addr);
  mrt_buffer_put_raw(buf, &addr_network_formatted, write_size);
}

/*
 * The data will be transformed (put_u16(), put_u32(), ...) to the network format before writing
 */
static void
mrt_buffer_put_var(struct mrt_buffer *buf, const void *data, size_t data_size)
{
  if (data_size == 0)
    return;

  byte *actual_position;

  size_t required_size = data_size + buf->msg_length;
  mrt_buffer_enlarge(buf, required_size);

  switch (data_size)
  {
    case 8:
      put_u64(mrt_buffer_get_cursor(buf), *(u64*)data);
      break;
    case 4:
      put_u32(mrt_buffer_get_cursor(buf), *(u32*)data);
      break;
    case 2:
      put_u16(mrt_buffer_get_cursor(buf), *(u16*)data);
      break;
    case 1:
      actual_position = mrt_buffer_get_cursor(buf);
      *actual_position = *(byte*)data;
      break;
    default:
      log(L_WARN "Unexpected size %zu byte(s) of data. Allowed are 1, 2, 4 or 8 bytes.", data_size);
  }

  buf->msg_length += data_size;
  mrt_buffer_write_show_debug(buf, data_size);
}
#define mrt_buffer_put_var_autosize(msg, data) mrt_buffer_put_var(msg, &data, sizeof(data))

/*
 * MRTDump: Table Dump: Peer Index Table
 */

void
mrt_peer_index_table_header(struct mrt_peer_index_table *state, u32 collector_bgp_id, const char *name)
{
  struct mrt_buffer *buf = &state->msg;
  mrt_buffer_alloc(buf);

  state->peer_count = 0;
  u16 name_length = 0;
  if (name != NULL)
    name_length = strlen(name);

  mrt_buffer_put_var_autosize(buf, collector_bgp_id);
  mrt_buffer_put_var_autosize(buf, name_length);
  mrt_buffer_put_raw(buf, name, name_length);
  state->peer_count_offset = state->msg.msg_length;
  mrt_buffer_put_var(buf, &state->peer_count, sizeof(u16));
  DBG("\n");
}

static void
mrt_peer_index_table_inc_peer_count(struct mrt_peer_index_table *state)
{
  state->peer_count++;
  byte *peer_count = &state->msg.msg[state->peer_count_offset];
  put_u16(peer_count, state->peer_count);
}

void
mrt_peer_index_table_add_peer(struct mrt_peer_index_table *state, u32 peer_bgp_id, u32 peer_as, ip_addr peer_ip_addr)
{
  struct mrt_buffer *msg = &state->msg;

  u8 peer_type = MRT_PEER_TYPE_32BIT_ASN;
#ifdef IPV6
    peer_type |= MRT_PEER_TYPE_IPV6;
#endif

  mrt_buffer_put_var_autosize(msg, peer_type);
  mrt_buffer_put_var_autosize(msg, peer_bgp_id);
  mrt_buffer_put_ipa(msg, peer_ip_addr, sizeof(ip_addr));
  mrt_buffer_put_var_autosize(msg, peer_as);

  mrt_peer_index_table_inc_peer_count(state);
  DBG("\n");
}

void
mrt_peer_index_table_dump(struct mrt_peer_index_table *state, int file_descriptor)
{
  byte *msg = state->msg.msg;
  u32 msg_length = state->msg.msg_length;

  mrt_dump_message(file_descriptor, MRT_TABLE_DUMP_V2, MRT_PEER_INDEX_TABLE, msg, msg_length);
}

void
bgp_mrt_peer_index_table_free(struct mrt_peer_index_table *state)
{
  mrt_buffer_free(&state->msg);
}

/*
 * MRTDump: Table Dump: RIB Table
 */

static void
mrt_rib_table_reset(struct mrt_rib_table *state)
{
  state->entry_count = 0;
  state->entry_count_offset = 0;
  state->subtype = MRT_RIB_IPV4_UNICAST;
  mrt_buffer_reset(&state->msg);
}

void
mrt_rib_table_alloc(struct mrt_rib_table *state)
{
  mrt_buffer_alloc(&state->msg);
  mrt_rib_table_reset(state);
}

void
mrt_rib_table_header(struct mrt_rib_table *state, u32 sequence_number, u8 prefix_length, ip_addr prefix)
{
  mrt_rib_table_reset(state);

#ifdef IPV6
  state->subtype = MRT_RIB_IPV6_UNICAST;
#else
  state->subtype = MRT_RIB_IPV4_UNICAST;
#endif

  struct mrt_buffer *msg = &state->msg;
  mrt_buffer_put_var_autosize(msg, sequence_number);
  mrt_buffer_put_var_autosize(msg, prefix_length);

#define CEILING(a, b) (((a)+(b)-1) / (b))
  u32 prefix_bytes = CEILING(prefix_length, 8);
  mrt_buffer_put_ipa(msg, prefix, prefix_bytes);

  state->entry_count_offset = msg->msg_length;
  mrt_buffer_put_var_autosize(msg, state->entry_count);
  DBG("\n");
}

static void
mrt_rib_table_inc_entry_count(struct mrt_rib_table *state)
{
  state->entry_count++;
  byte *entry_count = &state->msg.msg[state->entry_count_offset];
  put_u16(entry_count, state->entry_count);
}

void
mrt_rib_table_add_entry(struct mrt_rib_table *state, const struct mrt_rib_entry *entry)
{
  struct mrt_buffer *msg = &state->msg;

  mrt_buffer_put_var_autosize(msg, entry->peer_index);
  mrt_buffer_put_var_autosize(msg, entry->originated_time);
  mrt_buffer_put_var_autosize(msg, entry->attributes_length);
  mrt_buffer_put_raw(msg, entry->attributes, entry->attributes_length);

  mrt_rib_table_inc_entry_count(state);
  DBG("\n");
}

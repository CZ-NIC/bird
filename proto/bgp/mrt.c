#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "nest/route.h"
#include "nest/iface.h"
#include "nest/cli.h"
#include "lib/socket.h"
#include "lib/ip.h"
#include "lib/unix.h"
#include "lib/krt.h"

#include "bgp.h"
#include "mrt.h"

/*
 * MRTDump: Table Dump V2: BGP Specific Part
 */

void
bgp_mrt_peer_index_table_dump(struct mrt_table_dump_ctx *state)
{
  struct proto *P;
  struct mrt_peer_index_table pit;
  u32 collector_bgp_id = config->router_id;

  mrt_peer_index_table_header(&pit, collector_bgp_id, state->rtable->name);

  mrt_peer_index_table_add_peer(&pit, 0, 0, IPA_NONE);	/* at index 0 is fake zeroed-peer for all non-BGP routes */

  WALK_LIST(P, active_proto_list)
  {
    if (P->proto_state == PS_UP && P->proto == &proto_bgp)
    {
      struct bgp_proto *p = (struct bgp_proto *) P;

      p->mrt_peer_index = pit.peer_count;
      ip_addr peer_ip = p->cf->remote_ip;
      mrt_peer_index_table_add_peer(&pit, p->remote_id, p->remote_as, peer_ip);
    }
  }

  mrt_peer_index_table_dump(&pit, fileno(state->rfile->f));
  mrt_buffer_free(&pit.msg);
}

static void
bgp_mrt_rib_table_dump(struct mrt_table_dump_ctx *state)
{
  byte *msg = state->rib_table.msg.msg;
  u32 msg_length = state->rib_table.msg.msg_length;
  mrt_dump_message(fileno(state->rfile->f), MRT_TABLE_DUMP_V2, state->rib_table.subtype, msg, msg_length);
}

/*
 * Usage:
 * 	struct mrt_table_dump_ctx ctx;
 * 	bgp_mrt_table_dump_init(rtable, &ctx);
 * 	while (ctx.state != MRT_STATE_COMPLETED)
 * 	  bgp_mrt_table_dump_step(&ctx);
 */
void
bgp_mrt_table_dump_step(struct mrt_table_dump_ctx *state)
{
  if (state->state == MRT_STATE_COMPLETED)
    return;

  uint max_work_size = 1;

  FIB_ITERATE_START(&state->rtable->fib, &state->fit, f)
  {
    if (!max_work_size--)
    {
      FIB_ITERATE_PUT(&state->fit, f);
      bgp_mrt_rib_table_dump(state);
      return;
    }

    net *n = (net *) f;
    mrt_rib_table_header(&state->rib_table, state->rib_sequence_number++, n->n.pxlen, n->n.prefix);

    rte *e;
    for (e = n->routes; e; e = e->next)
    {
      struct proto *P = e->attrs->src->proto;

      if (!is_route_good_for_table_dump(state, e))
	continue;

      u16 peer_index = 0; /* have to correspond with fake zeroed-peer in peer index table */
      uint attributes_length = 0;
      static byte attributes_buffer[BGP_ATTR_BUFFER_SIZE]; /* static intends to do better performance */

      if (P->proto == &proto_bgp)
      {
	struct bgp_proto *p = (struct bgp_proto *) P;

	if (p->mrt_peer_index == 0)
	{
	  log(L_INFO "%s: MRT Table Dump for %I/%u: Skipping not-indexed BPG RIB (local ASN: %u, remote ASN: %u)", p->p.name, n->n.prefix, n->n.pxlen, p->local_as, p->remote_as);
	  continue;
	}

	attributes_length = bgp_encode_attrs(p, attributes_buffer, e->attrs->eattrs, BGP_ATTR_BUFFER_SIZE);
	if (attributes_length == -1)
	{
	  log(L_WARN "%s: MRT Table Dump for %I/%u: Attribute list too long, let it blank", p->p.name, n->n.prefix, n->n.pxlen);
	  attributes_length = 0;
	}
	peer_index = p->mrt_peer_index;
      }

      struct mrt_rib_entry entry = {
	  .peer_index = peer_index,
	  .originated_time = (u32) bird_clock_to_unix_timestamp(e->lastmod),
	  .attributes_length = attributes_length,
	  .attributes = attributes_buffer
      };

      mrt_rib_table_add_entry(&state->rib_table, &entry);
    }
  } FIB_ITERATE_END(f);

  fit_get(&state->rtable->fib, &state->fit);
  mrt_buffer_free(&state->rib_table.msg);
  if (state->rfile)
    rfree(state->rfile);
  state->state = MRT_STATE_COMPLETED;
}

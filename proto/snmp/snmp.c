/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *      Parts of this file were auto-generated using mib2c
 *      using mib2c.create-dataset.conf
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/cli.h"

#include "proto/snmp/snmp.h"
#include "proto/snmp/subagent.h"
#include "proto/snmp/bgp_mib.h"

static struct proto *
snmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct snmp_proto *p = (void *) P;

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  return P;
}

void start_multihook(void)
{
  /* init bgp MIB table */
  snmp_init_bgp_table();

  /* init ospf MIB table */
  //snmp_inti_ospf_table();
}

static int
snmp_start(struct proto *P)
{
  /* init MIB tables */
  if (snmp_start_subagent(start_multihook))
    return PS_UP;
  else
    return PS_DOWN;
}

static int
snmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  return 0;
}

static void
snmp_show_proto_info(struct proto *P)
{
  struct snmp_proto *sp = (void *) P;
  struct snmp_config *c = (void *) P->cf;

  cli_msg(-1006, "  BGP peers");
  struct snmp_bond *bond;
  WALK_LIST(bond, c->bgp_entries)
  {
    struct proto_config *cf = P->cf;
    struct bgp_config *bcf = (struct bgp_config *) cf;
    struct proto_config *pcf = (void *) bond->proto;
    struct proto *p = cf->proto;
    struct bgp_proto *bp = (struct bgp_proto *) cf->proto;
    struct bgp_conn *conn = bp->conn;

    cli_msg(-1006, "    name: %s", cf->name);
    cli_msg(-1006, "");
    cli_msg(-1006, "    rem. identifier: %u", bp->remote_id);
    // learn more !!
    cli_msg(-1006, "    admin status: %s", (p->disabled) ? "start" :
	      "stop");
    // version ?
    cli_msg(-1006, "    version: ??, likely 4");
    cli_msg(-1006, "    local ip: %u", bcf->local_ip);
    cli_msg(-1006, "    remote ip: %u", bcf->remote_ip);
    cli_msg(-1006, "    local port: %u", bcf->local_port);
    cli_msg(-1006, "    remote port: %u", bcf->remote_port);
    if (conn) {
      cli_msg(-1006, "    state: %u", conn->state);
      cli_msg(-1006, "    remote as: %u", conn->remote_caps->as4_number);
    }
    cli_msg(-1006, "    in updates: %u", bp->stats.rx_updates);
    cli_msg(-1006, "    out updates: %u", bp->stats.tx_updates);
    cli_msg(-1006, "    in total: %u", bp->stats.rx_messages);
    cli_msg(-1006, "    out total: %u", bp->stats.tx_messages);
    cli_msg(-1006, "    fsm transitions: %u",
bp->stats.fsm_established_transitions);

    // not supported yet
    cli_msg(-1006, "    fsm total time: --");
    cli_msg(-1006, "    retry interval: %u", bcf->connect_retry_time);

    if (conn) {
      cli_msg(-1006, "    hold time: %u", conn->hold_time);
      cli_msg(-1006, "    keep alive: %u", conn->keepalive_time );
    }

    cli_msg(-1006, "    hold configurated: %u", bcf->hold_time );
    cli_msg(-1006, "    keep alive config: %u", bcf->keepalive_time );

    // unknown
    cli_msg(-1006, "    min AS origin. int.: --");
    cli_msg(-1006, "    min route advertisement: %u", 0 );
    cli_msg(-1006, "    in update elapsed time: %u", 0 );

    if (!conn)
      cli_msg(-1006, "  no default connection");

    cli_msg(-1006, "  outgoinin_conn state %u", bp->outgoing_conn.state + 1);
    cli_msg(-1006, "  incoming_conn state: %u", bp->incoming_conn.state + 1);
  }
}


void
shutdown_multihook(void)
{
  snmp_del_bgp_table();
  //snmp_del_ospf_table();
}

/* snmp_shutdown already occupied by net-snmp */
void
snmp_shutdown_(struct proto *P)
{
  snmp_stop_subagent(shutdown_multihook);
}

struct protocol proto_snmp = {
  .name =		"Snmp",
  .template =		"snmp%d",
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct snmp_proto),
  .config_size =	sizeof(struct snmp_config),
  .init =		snmp_init,
  .start =		snmp_start,
  .reconfigure =	snmp_reconfigure,
  .shutdown =		snmp_shutdown_,
  .show_proto_info = 	snmp_show_proto_info,
};

/* strange name because conflict with net-snmp lib snmp_lib() */
void
snmp_build_(void)
{
  proto_build(&proto_snmp);
}

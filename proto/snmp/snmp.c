/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "nest/cli.h"

#include "proto/snmp/snmp.h"

static struct proto *
snmp_init(struct proto_config *CF)
{
  struct proto *P = proto_new(CF);
  struct snmp_proto *p = (void *) P;

  p->rl_gen = (struct tbf) TBF_DEFAULT_LOG_LIMITS;

  return P;
}

static int
snmp_start(struct proto *P)
{
  struct channel_config *cc;
  WALK_LIST(cc, P->cf->channels)
  {
    struct channel *c = NULL;
    proto_configure_channel(P, &c, cc);
  }

  return PS_UP;
}

static int
snmp_reconfigure(struct proto *P, struct proto_config *CF)
{
  return 0;
}

static void
snmp_show_proto_info(struct proto *P)
{
  //struct stats_proto *p = (void *) P;

  struct snmp_channel *sc;

  WALK_LIST(sc, P->channels)
  {
    cli_msg(-1006, "  Channel %s", sc->c.name);

    if (!P->disabled)
    {
      cli_msg(-1006, "    enabled");
    }
    else
      cli_msg(-1006, "    disabled");
  }
}

static int
snmp_channel_start(struct channel *C)
{
  return 0;
}

static void
snmp_channel_shutdown(struct channel *C)
{

}

struct channel_class channel_snmp = {
  .channel_size =	sizeof(struct snmp_channel),
  .config_size =	sizeof(struct snmp_channel_config),
  .start =		snmp_channel_start,
  .shutdown =		snmp_channel_shutdown,
};

struct protocol proto_snmp = {
  .name =		"Snmp",
  .template =		"snmp%d",
  .channel_mask =	NB_ANY,
  .proto_size =		sizeof(struct snmp_proto),
  .config_size =	sizeof(struct snmp_config),
  .init =		snmp_init,
  .start =		snmp_start,
  .reconfigure =	snmp_reconfigure,
  .show_proto_info = 	snmp_show_proto_info,
};

void
snmp_build(void)
{
  proto_build(&proto_snmp);
}

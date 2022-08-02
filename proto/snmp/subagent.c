/*
 *	BIRD -- Simple Network Management Protocol (SNMP)
 *
 *      (c) 2022 Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *      (c) 2022 CZ.NIC z.s.p.o
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 *
 *      Parts of this file were auto-generated from net-snmp-config
 */

#include <net-snmp/net-snmp-config.h>

#ifdef HAVE_SIGNAL
#include <signal.h>
#endif

#ifdef HAV_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

extern int netsnmp_running;

int
snmp_start_subagent(void (*hook)(void))
{
  /* subagent mode */
  netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
			 NETSNMP_DS_AGENT_ROLE, 1);

  /* forking netsnmp mechanism  * /
    if (netsnmp_daemonize(1, snmp_stderrolog_status()) != 0)
      return 0;   // start FAILED
   */

  /* for Win32 only */
  SOCK_STARTUP;

  /* init library */
  init_agent("bird");

  if (hook)
    hook();

  /* used for loading config 'bird-snmp.conf' */
  init_snmp("bird-snmp");

  return 1;   // SUCCESS
}

void
snmp_agent_reconfigure(void)
{
  free_config();
  read_configs();
}

void
snmp_shutdown_subagent(void (*hook)(void))
{
  /* at shutdown time */
  snmp_shutdown("bird");

  /* shutdown hook */
  if (hook)
    hook();

  /* shutdown the agent library */
  shutdown_agent();

  /* for Win32 only */
  SOCK_CLEANUP;
}

void
snmp_stop_subagent(void (*hook)(void))
{
  /* at shutdown time */
  snmp_shutdown("bird");

  /* deinitialize MIB code */
  if (hook)
    hook();

  /* shutdown the agent library */
  shutdown_agent();
}

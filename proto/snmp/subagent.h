#ifndef _BIRD_SNMP_SUBAGENT_H_
#define _BIRD_SNMP_SUBAGENT_H_

int snmp_start_subagent(void (*hook)(void));
void snmp_agent_reconfigure(void);
void snmp_stop_subagent(void (*hook)(void));

#endif

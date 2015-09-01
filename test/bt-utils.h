/*
 *	BIRD Test -- Utils for testing parsing configuration file
 *
 *	(c) 2015 CZ.NIC z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRDTEST_UTILS_H_
#define _BIRDTEST_UTILS_H_

#include "sysdep/config.h"

#define PRIip4 "%d.%d.%d.%d"
#ifdef DEBUGGING
#  define ARGip4(x) ((x).addr >> 24) & 0xff, ((x).addr >> 16) & 0xff, ((x).addr >> 8) & 0xff, (x).addr & 0xff
#else
#  define ARGip4(x) ((x) >> 24) & 0xff, ((x) >> 16) & 0xff, ((x) >> 8) & 0xff, (x) & 0xff
#endif
#define PRIip6 "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X"
#define ARGip6_HIGH(x,i) (((x).addr[(i)] >> 16) & 0xffff)
#define ARGip6_LOW(x,i)  ((x).addr[(i)] & 0xffff)
#define ARGip6_BOTH(x,i) ARGip6_HIGH(x,i), ARGip6_LOW(x,i)
#define ARGip6(x) ARGip6_BOTH((x), 0), ARGip6_BOTH((x), 1), ARGip6_BOTH((x), 2), ARGip6_BOTH((x), 3)
#ifdef IPV6
#define PRIipa PRIip6
#define ARGipa(x) ARGip6(x)
#else
#define PRIipa PRIip4
#define ARGipa(x) ARGip4(x)
#endif

#define BT_CONFIG_PARSE_ROUTER_ID       "router id 10.0.0.1; \n"
#define BT_CONFIG_PARSE_KERNEL_DEVICE   "protocol device {} \n"
#define BT_CONFIG_SIMPLE		BT_CONFIG_PARSE_ROUTER_ID BT_CONFIG_PARSE_KERNEL_DEVICE

void bt_bird_init(void);
void bt_bird_init_with_simple_configuration(void);
struct config *bt_config_parse(const char *str_cfg);

uint naive_pow(uint base, uint power);

#endif /* _BIRDTEST_UTILS_H_ */

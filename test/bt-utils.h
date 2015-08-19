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

#define BT_CONFIG_PARSE_ROUTER_ID       "router id 10.0.0.1; \n"
#define BT_CONFIG_PARSE_KERNEL_DEVICE   "protocol device {} \n"
#define BT_CONFIG_SIMPLE		BT_CONFIG_PARSE_ROUTER_ID BT_CONFIG_PARSE_KERNEL_DEVICE

void bt_bird_init(void);
void bt_bird_init_with_simple_configuration(void);
struct config *bt_config_parse(const char *str_cfg);

uint naive_pow(uint base, uint power);

#endif /* _BIRDTEST_UTILS_H_ */

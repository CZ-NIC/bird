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
#define ARGip4(x) (_I(x) >> 24) & 0xff, (_I(x) >> 16) & 0xff, (_I(x) >> 8) & 0xff, _I(x) & 0xff

#define PRIip6 "%04X:%04X:%04X:%04X:%04X:%04X:%04X:%04X"
#define ARGip6_HIGH(x,i) (((x).addr[(i)] >> 16) & 0xffff)
#define ARGip6_LOW(x,i)  ((x).addr[(i)] & 0xffff)
#define ARGip6_BOTH(x,i) ARGip6_HIGH(x,i), ARGip6_LOW(x,i)
#define ARGip6(x) ARGip6_BOTH((x), 0), ARGip6_BOTH((x), 1), ARGip6_BOTH((x), 2), ARGip6_BOTH((x), 3)

#define BT_CONFIG_PARSE_ROUTER_ID	"router id 1.1.1.1; \n"
#define BT_CONFIG_PARSE_STATIC_PROTO	"protocol static { ipv4; } \n"
#define BT_CONFIG_SIMPLE		BT_CONFIG_PARSE_ROUTER_ID BT_CONFIG_PARSE_STATIC_PROTO

uint bt_naive_pow(uint base, uint power);
void bt_bytes_to_hex(char *buf, const byte *in_data, size_t size);
void bt_random_net(net_addr *net, int type);
net_addr *bt_random_nets(int type, uint n);
net_addr *bt_random_net_subset(net_addr *src, uint sn, uint dn);
void bt_read_net(const char *str, net_addr *net, int type);
net_addr *bt_read_nets(FILE *f, int type, uint *n);
net_addr *bt_read_net_file(const char *filename, int type, uint *n);

void bt_bird_init(void);
void bt_bird_cleanup(void);
struct config *bt_config_parse(const char *cfg);
struct config *bt_config_file_parse(const char *filepath);

#endif /* _BIRDTEST_UTILS_H_ */

/*
 *	BIRD -- Export Protocol
 *
 *      (c) 2023 Georgy Kirichenko <g-e-o-r-g-y@yandex-team.ru>
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_EXPORT_H_
#define _BIRD_EXPORT_H_

#include "lib/socket.h"

struct export_buf {
	byte *tbuf;
	byte *tpos;
	uint64_t size;
};

struct export_config {
	struct proto_config c;
	const char *socket;
};

struct proto_export {
	struct proto p;
	struct export_config *cf;
	sock *s;
	uint32_t child_index;
	struct export_buf send_buf[2];
	uint32_t send_buf_index;
};

#endif

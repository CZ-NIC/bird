/*
 *	BIRD -- YANG-CBOR / CORECONF api -- CLI model
 *
 *	(c) 2026       Maria Matejka <mq@jmq.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _YANG_MODEL_CLI_H_
#define _YANG_MODEL_CLI_H_

#include "yang/yang.h"

/* TODO: This is not a good place for module boundary. */

bool yang_model_cli_rpc_call_show_memory(struct yang_session *se);

#endif /* _YANG_MODEL_CLI_H_ */

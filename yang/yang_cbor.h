/*
 *	BIRD -- YANG-CBOR encoding, decoding rules
 *
 *	(c) 2026       Vojtech Vilimek <vojtech.vilimek@nic.cz>
 *	(c) 2026       CZ.NIC, z.s.p.o.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_YANG_CBOR_H_
#define _BIRD_YANG_CBOR_H_

#include <stdint.h>

#include "lib/birdlib.h"
#include "nest/bird.h"
#include "yang/yang.h"
#include "yang/model.h"

typedef int64_t sid_t;

/* YANG instance-identifier */
struct yang_inst_id {
   sid_t sid;
   struct yang_inst_id *parent;
   void *keys;
   void *value;
   uint64_t index;
};

bool yc_validate_inst_id(struct yang_inst_id *iid);
void yc_compress_inst_id(struct yang_inst_id *iid, struct yang_inst_id **compressed);

void yang_cbor_init(struct yang_session *se);

void yang_cbor_open_datastore(void);
void yang_cbor_datastore_next_child(void);

void yang_cbor_open_container(void);
struct schema_node *yang_cbor_next_child(void);
void yang_cbor_close_container(void);

void yang_cbor_open_list(void);
bool yang_cbor_has_next_element(void);
void yang_cbor_close_list(void);

void yang_cbor_open_leaf_list(void);
/* yang_cbor_has_next_element() */
void yang_cbor_close_list(void);

void yang_cbor_value(void);

#endif

#ifndef _BIRD_YANG_MODEL_H_
#define _BIRD_YANG_MODEL_H_

#include <stdint.h>

#include "lib/birdlib.h"
#include "yang/yang_cbor.h"

// TODO move me to yang/yang.h?
/* YANG handlers */
enum yang_proc_state { /* YANG processing state */
   YP_OK,
   YP_WAIT,
   YP_ERR,
};

struct leaf_handler {
   enum yang_proc_state (*start)(struct yang_inst_id *id, void *ctx);
   enum yang_proc_state (*finish)(struct yang_inst_id *id, void *result);
};

struct container_handler {
   enum yang_proc_state (*start)(struct yang_inst_id *id, void *ctx);
   enum yang_proc_state (*key)(struct yang_inst_id *id, void *ctx, struct yang_inst_id *child);
   enum yang_proc_state (*value)(struct yang_inst_id *id, void *ctx, struct yang_inst_id *child, void *value);
   enum yang_proc_state (*finish)(struct yang_inst_id *id, void *result);
};

struct list_handler {
   struct container_handler list_handler;
   struct container_handler element_handler;
};

struct leaf_list_handler {
   struct container_handler leaf_list_hadnler;
   struct leaf_handler element_handler;
};

/* YANG Built-In Types (RFC 7950 section 4.2.4) */
enum yang_types {
   YT_BINARY = 1,
   YT_BITS,
   YT_BOOLEAN,
   YT_DECIMAL64,
   YT_EMPTY,
   YT_ENUMERATION,
   YT_IDENTITYREF,
   YT_INST_ID, /* instance-identifier */
   YT_INT8,
   YT_INT16,
   YT_INT32,
   YT_IN64,
   YT_LEAFREF,
   YT_STRING,
   YT_UINT8,
   YT_UINT16,
   YT_UINT32,
   YT_UINT64,
   YT_UNION,
};

struct yang_binary {
   // TODO: pattern
   // TODO: full feature length
   uint64_t min_len;
   uint64_t max_len;
   bool has_max_len;
};

struct yang_bits_bit {
   uint32_t position;
   char *name;
};

struct yang_bits {
   struct yang_bits_bit bits[0];
};

struct yang_decimal64 {
   // TODO: values
   uint8_t digits;
};

struct yang_enumeration_enum {
   int32_t value;
   char *name;
};

struct yang_enumeration {
   struct yang_enumeration_enum enums[0];
};

struct yang_identityref {
   sid_t bases[0];
};

struct yang_int {
   // TODO: ranges
};

struct schema_node;
struct yang_leafref {
   struct schema_node *node;
};

struct yang_string {
   uint64_t min_len;
   uint64_t max_len;
   bool has_max_len;
};

union unioned_yang_types {
   struct { enum yang_types type; struct yang_binary b; } binary;
   struct { enum yang_types type; struct yang_bits b; } bits;
   struct { enum yang_types type; } boolean;
   struct { enum yang_types type; struct yang_decimal64 d; } decimal64;
   struct { enum yang_types type; } empty;
   struct { enum yang_types type; struct yang_enumeration e; } enumeration;
   struct { enum yang_types type; struct yang_identityref i; } identityref;
   struct { enum yang_types type; } instance_identfier;
   struct { enum yang_types type; struct yang_int i; } int8;
   struct { enum yang_types type; struct yang_int i; } int16;
   struct { enum yang_types type; struct yang_int i; } int32;
   struct { enum yang_types type; struct yang_int i; } int64;
   struct { enum yang_types type; struct yang_leafref l; } leafref;
   struct { enum yang_types type; struct yang_string s; } string;
   struct { enum yang_types type; struct yang_int i; } uint8;
   struct { enum yang_types type; struct yang_int i; } uint16;
   struct { enum yang_types type; struct yang_int i; } uint32;
   struct { enum yang_types type; struct yang_int i; } uint64;
};

struct yang_union {
   union unioned_yang_types types[0];
};

struct yang_value {
   enum yang_types type;
   union {
      unsigned char *binary;
      uint32_t bit;
      bool boolean;
      int64_t decimal64;
      struct {} empty;
      int32_t enum_value;
      sid_t identity;
      struct yang_inst_id iid;
      int64_t int8;
      int64_t int16;
      int64_t int32;
      int64_t int64;
      /* leafref */
      char *string;
      uint64_t uint8;
      uint64_t uint16;
      uint64_t uint32;
      uint64_t uint64;
   } variant;
};

/* YANG schema nodes */
enum schema_node_type {
   SNT_CONTAINER = 1,
   SNT_LIST,
   SNT_LEAF,
   SNT_LEAF_LIST,
   SNT_RPC,
   SNT_ACTION,
   SNT_INPUT,
   SNT_OUTPUT,
   SNT_CHOICE,
   SNT_CASE,
   SNT_SX_STRUCTURE,
};

struct schema_node_list;

#define SCHEMA_NODE_FIELDS \
   enum schema_node_type type; \
   struct schema_node *parent; \
   sid_t sid

struct schema_node {
   SCHEMA_NODE_FIELDS;
};

struct schema_node_list {
   uint64_t length;
   struct schema_node *nodes[0];
};

struct container_node {
   SCHEMA_NODE_FIELDS;
   struct schema_node_list children;
};

struct list_node {
   SCHEMA_NODE_FIELDS;
   struct schema_node *first_value;
   struct schema_node_list children;
};

struct leaf_node {
   SCHEMA_NODE_FIELDS;
};

struct leaf_list_node {
   SCHEMA_NODE_FIELDS;
};

union all_schema_nodes {
   struct schema_node node;
   struct container_node container;
   struct list_node list;
   struct leaf_node leaf;
   struct leaf_list_node leaf_list;
};

//struct container_node *get_schema_root(void);

// TODO
//struct container_node *get_schema_rpc_action(void);

#endif

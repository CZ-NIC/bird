#ifndef _BIRD_YANG_MODEL_H_
#define _BIRD_YANG_MODEL_H_

#include <stdint.h>

#include "lib/birdlib.h"
#include "yang/yang_cbor.h"

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
   struct schema_node_list *list;
   struct schema_node *keys[0];
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

struct container_node *get_schema_root(void);

#endif


#include "yang/model.h"

/* Please read the file backwards, i.e. from the bottom upwards */

static struct leaf_node show_mem_page_rcu_fail;
static struct leaf_node show_mem_page_cold;
static struct leaf_node show_mem_page_hot;
static struct leaf_node show_mem_page_active;

struct container_node_4 {
   SCHEMA_NODE_FIELDS;
   struct {
      uint64_t length;
      struct schema_node *nodes[4];
   } children;
};
struct container_node_2 {
   SCHEMA_NODE_FIELDS;
   struct {
      uint64_t length;
      struct schema_node *nodes[2];
   } children;;
};
struct container_node_1 {
   SCHEMA_NODE_FIELDS;
   struct {
      uint64_t length;
      struct schema_node *nodes[1];
   } children;
};
struct container_node_6 {
   SCHEMA_NODE_FIELDS;
   struct {
      uint64_t length;
      struct schema_node *nodes[6];
   } children;
};
static struct container_node_4 show_mem_pages;

static struct leaf_node show_mem_total_leafs[2];
static struct container_node_2 show_mem_total;

static struct leaf_node show_mem_config_leafs[2];
static struct container_node_2 show_mem_config;

static struct leaf_node show_mem_proto_leafs[2];
static struct container_node_2 show_mem_proto;

static struct leaf_node show_mem_attrs_leafs[2];
static struct container_node_2 show_mem_attrs;

static struct leaf_node show_mem_table_leafs[2];
static struct container_node_2 show_mem_table;

static struct container_node_6 show_mem_cont;
static struct container_node rpc_show_mem_in;
static struct container_node_1 rpc_show_mem_out;
static struct container_node_2 rpc_show_mem;

static struct container_node_1 schema_tree_root;

static struct leaf_node show_mem_page_rcu_fail = {
   .type = SNT_LEAF,
   .parent = (struct schema_node *) &show_mem_pages,
   .sid = 60014,
};

static struct leaf_node show_mem_page_cold = {
   .type = SNT_LEAF,
   .parent = (struct schema_node *) &show_mem_pages,
   .sid = 60013,
};

static struct leaf_node show_mem_page_hot = {
   .type = SNT_LEAF,
   .parent = (struct schema_node *) &show_mem_pages,
   .sid = 60014,
};

static struct leaf_node show_mem_page_active = {
   .type = SNT_LEAF,
   .parent = (struct schema_node *) &show_mem_pages,
   .sid = 60012,
};

static struct container_node_4 show_mem_pages = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 60011,
   .children = {
      .length = 4,
      .nodes = {
         (struct schema_node *) &show_mem_page_active, 
         (struct schema_node *) &show_mem_page_hot,
         (struct schema_node *) &show_mem_page_cold, 
         (struct schema_node *) &show_mem_page_rcu_fail,
      },
   },
};

static struct leaf_node show_mem_total_leafs[2] = {
   {
      .type = SNT_LEAF,
      .parent = (struct schema_node *) &show_mem_total,
      .sid = 60023,
   },
   {
      .type = SNT_LEAF,
      .parent = (struct schema_node *) &show_mem_total,
      .sid = 60024,
   },
};
   
static struct container_node_2 show_mem_total = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 60022,
   .children = {
      .length = 2,
      .nodes = {
         (struct schema_node *) &show_mem_total_leafs[0], 
         (struct schema_node *) &show_mem_total_leafs[1], 
      },
   },
};

/* TODO: inverse the order */
#define MEMORY_INFO_LINE(parent_node, effective_sid, overhead_sid) \
   { \
      .type = SNT_LEAF, \
      .parent = (struct schema_node *) (parent_node), \
      .sid = effective_sid, \
   }, \
   { \
      .type = SNT_LEAF, \
      .parent = (struct schema_node *) (parent_node), \
      .sid = overhead_sid, \
   }

static struct leaf_node show_mem_config_leafs[2] = {
   MEMORY_INFO_LINE(&show_mem_config, 60009, 60010),
};

static struct container_node_2 show_mem_config = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 1,
   .children = {
      .length = 60008,
      .nodes = { 
         (struct schema_node *) &show_mem_config_leafs[0], 
         (struct schema_node *) &show_mem_config_leafs[1], 
      },
   },
};

static struct leaf_node show_mem_proto_leafs[2] = {
   MEMORY_INFO_LINE(&show_mem_proto, 60017, 60018),
};

static struct container_node_2 show_mem_proto = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 60016,
   .children = {
      .length = 2,
      .nodes = { 
         (struct schema_node *) &show_mem_proto_leafs[0], 
         (struct schema_node *) &show_mem_proto_leafs[1], 
      },
   },
};

static struct leaf_node show_mem_attrs_leafs[2] = {
   MEMORY_INFO_LINE(&show_mem_attrs, 60006, 60007),
};

static struct container_node_2 show_mem_attrs = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 60005,
   .children = {
      .length = 2,
      .nodes = {
         (struct schema_node *) &show_mem_attrs_leafs[0], 
         (struct schema_node *) &show_mem_attrs_leafs[1],
      },
   },
};

static struct leaf_node show_mem_table_leafs[2] = {
   MEMORY_INFO_LINE(&show_mem_table, 60020, 60021),
};

static struct container_node_2 show_mem_table = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &show_mem_cont,
   .sid = 60019,
   .children = {
      .length = 2,
      .nodes = { 
         (struct schema_node *) &show_mem_table_leafs[0],
         (struct schema_node *) &show_mem_table_leafs[1],
      },
   },
};


static struct container_node_6 show_mem_cont = {
   .type = SNT_CONTAINER,
   .parent = (struct schema_node *) &rpc_show_mem_out,
   .sid = 60004,
   .children = {
      .length = 6,
      .nodes = {
         (struct schema_node *) &show_mem_table,
         (struct schema_node *) &show_mem_attrs,
         (struct schema_node *) &show_mem_proto,
         (struct schema_node *) &show_mem_config,
         (struct schema_node *) &show_mem_total,
         (struct schema_node *) &show_mem_pages,
      },
   },
};

static struct container_node_1 rpc_show_mem_out = {
   .type = SNT_OUTPUT,
   .parent = (struct schema_node *) &rpc_show_mem,
   .sid = 60003,
   .children = {
      .length = 1,
      .nodes = { (struct schema_node *) &show_mem_cont, },
   },
};

static struct container_node rpc_show_mem_in = {
   .type = SNT_INPUT,
   .parent = (struct schema_node *) &rpc_show_mem,
   .sid = 60002,
   .children = { .length = 0, .nodes = {} },
};

static struct container_node_2 rpc_show_mem = {
   .type = SNT_RPC,
   .parent = (struct schema_node *) &schema_tree_root,
   .sid = 60001,
   .children = {
      .length = 2,
      .nodes = {
         (struct schema_node *) &rpc_show_mem_in,
         (struct schema_node *) &rpc_show_mem_out,
      },
   },
};

static struct container_node_1 schema_tree_root = {
   .type = SNT_CONTAINER,
   .parent = NULL,
   .sid = 0,
   .children = {
      .length = 1,
      .nodes = { (struct schema_node *) &rpc_show_mem, },
   },
};

struct container_node *
get_schema_root(void)
{
   return (struct container_node *) &schema_tree_root;
}


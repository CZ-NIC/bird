#ifndef UYTC_CORECONF_MODEL_H
#define UYTC_CORECONF_MODEL_H

enum container_state {
  CONTAINER_BEGIN,
  CONTAINER_MAP_OPENED,
  CONTAINER_KEY,
  CONTAINER_DONE,
  CONTAINER_ERROR,
};

struct container_data_light_t {
  enum container_state state;
  u64 child_sid;
  void *child_ctx;
};

enum rpc_state {
  RPC_BEFORE,
  RPC_MAP_OPENED,
  RPC_KEY,
  //RPC_CLOSE,
  RPC_DONE2,
  RPC_ERROR,
};

struct rpc_data_light_t {
  enum rpc_state state;
  u64 rpc_sid;
};

#endif

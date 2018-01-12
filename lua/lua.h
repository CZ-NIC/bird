#include "nest/bird.h"

#include <lua.h>

typedef struct lua_bird_state {
  int exception;
} lua_bird_state;

lua_bird_state *luaB_init(lua_State *L, struct linpool *lp);
void luaB_push_route(lua_State *L, rte *e);


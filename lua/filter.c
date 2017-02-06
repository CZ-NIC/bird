#include "nest/bird.h"
#include "filter/filter.h"
#include "lua.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

int filter_lua_chunk(const char *chunk, struct rte **e, struct rta *a, struct ea_list **ea, struct linpool *lp) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  luaB_push_bird_table(L);
  int le = luaL_dostring(L, chunk);
  int out;
  if (le) {
    log(L_WARN "bad lua: %s", lua_tostring(L, -1));
    out = F_ERROR;
  } else if (lua_isnumber(L, -1)) {
    out = lua_tonumber(L, -1);
  } else {
    log(L_WARN "lua return value is not a number: %s", lua_tostring(L, -1));
    out = F_ERROR;
  }

  lua_close(L);
  return out;
}

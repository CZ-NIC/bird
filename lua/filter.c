#include "nest/bird.h"
#include "filter/filter.h"
#include "lua.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* Docs: http://pgl.yoyo.org/luai/i/luaL_dostring */

struct f_val filter_lua_chunk(const char *chunk, struct rte **e, struct rta *a, struct ea_list **ea, struct linpool *lp) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  lua_bird_state *lbs = luaB_init(L, lp);
  luaB_push_route(L, *e);
  int le = luaL_dostring(L, chunk);
  struct f_val out = F_VAL_VOID;
  if (le && lbs->exception) {
    out = F_VAL(T_RETURN, i, lbs->exception);
  } else if (le) {
    log(L_ERR "bad lua: %s", lua_tostring(L, -1));
    out = F_VAL(T_RETURN, i, F_ERROR);
  } else if (lua_isnumber(L, -1)) {
    out = F_VAL(T_INT, i, lua_tonumber(L, -1));
  } else {
    log(L_WARN "lua return value is not a number (unimplemented): %s", lua_tostring(L, -1));
    out = F_VAL(T_RETURN, i, F_ERROR);
  }

  lua_close(L);
  return out;
}

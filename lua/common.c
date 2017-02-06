#include "nest/bird.h"
#include "filter/filter.h"
#include "lua.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

static int luaB_err(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 1)
    log(L_WARN "bird.err() accepts exactly 1 argument");

  if (n < 1)
    return 0;

  log(L_ERR "%s", lua_tostring(L, 1));
  return 0;
}

static int luaB_warn(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 1)
    log(L_WARN "bird.warn() accepts exactly 1 argument");

  if (n < 1)
    return 0;

  log(L_WARN "%s", lua_tostring(L, 1));
  return 0;
}

static int luaB_info(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 1)
    log(L_WARN "bird.info() accepts exactly 1 argument");

  if (n < 1)
    return 0;

  log(L_INFO "%s", lua_tostring(L, 1));
  return 0;
}

static int luaB_trace(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 1)
    log(L_WARN "bird.trace() accepts exactly 1 argument");

  if (n < 1)
    return 0;

  log(L_TRACE "%s", lua_tostring(L, 1));
  return 0;
}

void luaB_push_bird_table(lua_State *L) {
  lua_newtable(L);

  lua_pushstring(L, "err");
  lua_pushcfunction(L, luaB_err);
  lua_settable(L, -3);

  lua_pushstring(L, "warn");
  lua_pushcfunction(L, luaB_warn);
  lua_settable(L, -3);

  lua_pushstring(L, "info");
  lua_pushcfunction(L, luaB_info);
  lua_settable(L, -3);

  lua_pushstring(L, "trace");
  lua_pushcfunction(L, luaB_trace);
  lua_settable(L, -3);

  lua_setglobal(L, "bird");
}

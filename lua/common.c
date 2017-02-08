#include "nest/bird.h"
#include "conf/conf.h"
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

#define lua_sett(L, idx, val, what) do { \
  lua_pushstring(L, idx); \
  lua_push##what(L, val); \
  lua_settable(L, -3); \
} while (0)

#define lua_settablecfunction(L, idx, val)  lua_sett(L, idx, val, cfunction)
#define lua_settableinteger(L, idx, val)    lua_sett(L, idx, val, integer)
#define lua_settableip4(L, idx, val)	    lua_sett(L, idx, val, ip4)

static int luaB_generic_concat(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 2) {
    log(L_WARN "__concat needs exactly 2 arguments");
    return 0;
  }

  const char *a, *b;
  size_t la, lb;

  a = luaL_tolstring(L, 1, &la);
  b = luaL_tolstring(L, 2, &lb);

  if (a == NULL) {
    a = "";
    la = 0;
  }

  if (b == NULL) {
    b = "";
    lb = 0;
  }

  char *c = alloca(la + lb + 1);
  memcpy(c, a, la);
  memcpy(c + la, b, lb);
  c[la + lb] = 0;

  lua_pushlstring(L, c, la + lb);

  return 1;
}

static int luaB_ip4_tostring(lua_State *L) {
  int n = lua_gettop(L);
  if (n != 1) {
    log(L_WARN "__tostring needs exactly 1 argument");
    return 0;
  }

  lua_pushliteral(L, "addr");
  lua_gettable(L, 1);
  lua_Integer a = lua_tointeger(L, -1);
  char c[IP4_MAX_TEXT_LENGTH];
  bsnprintf(c, IP4_MAX_TEXT_LENGTH, "%I4", a);

  lua_pushstring(L, c);
  return 1;
}

static void lua_puship4(lua_State *L, ip4_addr a) {
  lua_newtable(L);
  lua_settableinteger(L, "addr", a);

  lua_newtable(L);
  lua_settablecfunction(L, "__tostring", luaB_ip4_tostring);
  lua_settablecfunction(L, "__concat", luaB_generic_concat);
  lua_setmetatable(L, -2);
}

void luaB_push_bird(lua_State *L) {
  lua_newtable(L);

  lua_settablecfunction(L, "err", luaB_err);
  lua_settablecfunction(L, "warn", luaB_warn);
  lua_settablecfunction(L, "info", luaB_info);
  lua_settablecfunction(L, "trace", luaB_trace);

  lua_settableip4(L, "router_id", config->router_id);

  lua_setglobal(L, "bird");
}

void luaB_push_route(lua_State *L, struct rte *e) {
}

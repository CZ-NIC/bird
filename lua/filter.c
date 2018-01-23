#include "nest/bird.h"
#include "conf/conf.h"
#include "filter/filter.h"
#include "lua.h"

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

/* Docs: http://pgl.yoyo.org/luai/i/luaL_dostring */

struct lua_new_filter_writer_data {
  struct lua_filter_chunk *first, *last;
};

static int lua_new_filter_writer(lua_State *L UNUSED, const void *p, size_t sz, void *ud) {
  struct lua_new_filter_writer_data *d = ud;
  struct lua_filter_chunk *cur = cfg_allocz(sizeof(struct lua_filter_chunk));

  cur->size = sz;
  cur->chunk = cfg_alloc(sz);
  memcpy(cur->chunk, p, sz);

  if (d->last)
    d->last = d->last->next = cur;
  else
    d->last = d->first = cur;

  return 0;
}

struct filter * lua_new_filter(struct f_inst *inst) {
  struct filter *f = cfg_alloc(sizeof(struct filter));
  f->name = NULL;
  f->type = FILTER_LUA;

  struct f_val string = f_eval(inst, cfg_mem);
  if (string.type != T_STRING) {
    cf_error("Lua filter must be a string");
    return NULL;
  }

  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  int loadres = luaL_loadstring(L, string.val.s);
  switch (loadres) {
    case LUA_ERRMEM:
      lua_close(L);
      cf_error("Memory allocation error occured when loading lua chunk");
      return NULL;
    case LUA_ERRSYNTAX:
      {
	const char *e = lua_tostring(L, -1);
	char *ec = cfg_alloc(strlen(e) + 1);
	strcpy(ec, e);
	lua_close(L);
	cf_error("Lua syntax error: %s", ec);
	return NULL;
      }
    case 0: /* Everything OK */
      break;
  }

  struct lua_new_filter_writer_data lnfwd = {};
  lua_dump(L, lua_new_filter_writer, &lnfwd, 0); /* No error to handle */
  lua_close(L);

  f->lua_chunk = lnfwd.first;
  return f;
}

static const char *lua_interpret_reader(lua_State *L UNUSED, void *ud, size_t *sz) {
  struct lua_filter_chunk **cptr = ud;
  if ((*cptr) == NULL)
    return NULL;

  *sz = (*cptr)->size;
  void *out = (*cptr)->chunk;
  *cptr = (*cptr)->next;
  return out;
}

struct f_val lua_interpret(struct lua_filter_chunk *chunk, struct rte **e, struct rta **a, struct ea_list **ea, struct linpool *lp, int flags) {
  lua_State *L = luaL_newstate();
  luaL_openlibs(L);
  lua_bird_state *lbs = luaB_init(L, lp);
  luaB_push_route(L, *e);
  struct lua_filter_chunk **rptr = &chunk;
  lua_load(L, lua_interpret_reader, rptr, "", "b");
  int le = lua_pcall(L, 0, LUA_MULTRET, 0);
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

int lua_filter_same(struct lua_filter_chunk *new, struct lua_filter_chunk *old) {
  size_t npos = 0, opos = 0;
  while (new && old) {
    size_t nrem = new->size - npos;
    size_t orem = old->size - opos;
    size_t rem = MIN(nrem, orem);
    if (memcmp(new->chunk + npos, old->chunk + opos, rem))
      return 0;

    npos += rem;
    opos += rem;

    if (npos == new->size) {
      new = new->next;
      npos = 0;
    }

    if (opos == old->size) {
      old = old->next;
      opos = 0;
    }
  }

  if (!new && !old)
    return 1;
  else
    return 0;
}

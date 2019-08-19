#ifndef _XDP_LUA_H
#define _XDP_LUA_H
#define XDPLUA_SKBENTRY "xdplua_skb"

#include <luadata.h>
#include <lua.h>
#include <lauxlib.h>

#include <linux/skbuff.h>
#include <net/udp.h>
#include <net/ip.h>

#define luaU_setregval(L, t, v) { \
	if (v) lua_pushlightuserdata(L, v); \
	else lua_pushnil(L); \
	lua_setfield(L, LUA_REGISTRYINDEX, t); }

#define luaU_getregval(L, t, v) { \
	lua_getfield(L, LUA_REGISTRYINDEX, t); \
	*v = lua_touserdata(L, -1); \
	lua_pop(L, 1); }

int luaopen_xdplua(lua_State *L);
#endif

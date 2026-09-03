---
name: project-lua-fork-vs-vendored-lib
description: The fork's Lua differs from vendored LuaPlus 1081 in tag numbering and in having two lua_call entry points; anything left undefined resolves to the wrong copy.
metadata:
  type: project
---

`main.exe` links our recovered Lua core *and* the prebuilt
`LuaPlusLibD_1081.lib` together (see [[project-lua-hybrid-abi-blocker]]). Every
Lua function we declare but do not define silently resolves to the vendored
copy, which was compiled against stock Lua 5.0 layouts and constants. Three of
those bit at once and were fixed in `7c2e17c` / `44dccc9`.

**Tag numbering.** The fork splits the function tag in two:

    LUA_TTABLE 5   LUA_CFUNCTION 6   LUA_TFUNCTION 7   LUA_TUSERDATA 8

Stock has `LUA_TFUNCTION 6`, `LUA_TUSERDATA 7`. That is why the code base uses
the `(tt | 1) != LUA_TFUNCTION` idiom for "callable". It is also why the
vendored `ltablib`'s `table.sort` rejected every Lua comparator with
`bad argument #2 to 'sort' (cfunction expected, got function)` - it checks
`luaL_checktype(L, 2, LUA_TFUNCTION)` with stock's 6, which names the *C*
function tag here. The fork's own `luaB_sort` (`FUN_00928360`) has no comparator
type check at all. The whole table library is now recovered in `LuaObject.cpp`
as `LuaTable*` / `LuaOpenTable`, from `tab_funcs` at 0x00D47418.

Any library whose registration array lives in the image should be recovered
rather than left to the vendored lib for the same reason - `luaopen_string`
went the same way earlier ([[project-lua-strlib-landed]]).

**Two `lua_call`s.** The fork has both:

- `FUN_0090D400`, exported as `?lua_call@@YAXPAUlua_State@@HH@Z`, `void`, a bare
  `luaD_call` - **unprotected**.
- `FUN_0090D430`, `int`, the same call wrapped in a C++ `try` with handlers at
  0x0090D48D and 0x0090D4B0 - the fork's only protected-call entry point, since
  the setjmp machinery was removed.

`LuaPrimitives.h` macros `lua_call` onto the protected one, which is right for
most call sites but wrong for `doscript`: `SCR_LuaDoFileConcat` (`FUN_004CECD0`)
reaches the exported unprotected one. Routing it through the protected form
turned every script error into a status nobody read, so a failing module left
its environment holding only what `import()` had seeded it with and the caller
carried on. Recovered as `LuaCallUnprotected`; use it wherever the binary calls
`__imp_?lua_call@@...`.

**`lua_getstack` off by one.** The binary steps `ci` down *before* testing the
level counter, so level 1 lands on the caller of the running function. Ours
tested first and reported every level one frame too shallow, so
`debug.getinfo(1)` described the C function it was called from. `Blueprints.lua`
compares that against each frame's source to work out which file a blueprint
came from, so every blueprint ended up with `Blueprints.lua` as its own id and
source.

**Symptom to recognise.** Modules that "import fine" but whose table holds only
`__moduleinfo`, `lazyimport` and `import` - that is a chunk that errored with
the error swallowed. Dump the module table with `lua_next` from the C++ side;
it is the fastest way to tell a failed import from a missing global.

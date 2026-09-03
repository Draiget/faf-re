---
name: project_empty_luaopen_tables_vein
description: luaopen_* in lua/LuaObject.cpp register EMPTY luaL_reg tables ("contents not yet recovered") - the real table is readable from the PE and de-orphans the Lua C functions.
metadata:
  type: project
---

`luaopen_serialize` (0x00923690) in `src/sdk/lua/LuaObject.cpp` was opening an
**empty** `luaL_reg` table with the comment "data table contents not yet
recovered". Effect: every runtime `serialize.tostring` / `serialize.fromstring`
call returned nil, *and* the already-recovered `LuaSerializeFromString` body was
an orphan nothing named. Fixed 2026-08-20, commit `8d9da1bb`.

**Why:** these tables are plain `.rdata`, so "not yet recovered" was never true —
the contents were always one PE read away. Any other `luaopen_*` with the same
comment is the same free win, and each one un-orphans every C function it names.

**How to apply — the recipe:**

1. Find the table symbol from the callgraph index, not by guessing:
   `select owner_token, from_ea, to_ea, to_name from data_refs where to_ea between <lo> and <hi>`
   For serialize this returned `FUN_00923690 / 0xd47068 / serializelib`.
2. Dump the table out of `bin/2025.7.1/ForgedAlliance.exe` (image base 0x00400000,
   walk the section headers to map VA -> file offset). Entries are
   `{const char* name; lua_CFunction fn;}` pairs terminated by `{0,0}`.
   Watch for the string literals being laid out *between* table entries — the
   serialize table's "fromstring" bytes sit at 0x00D4705C, before the array head
   at 0x00D47068, so reading backwards from the head looks like garbage.
3. Declare the C functions in a header **both** TUs already include
   (`lua/LuaObject.h` worked here — avoids a new include edge between
   `gpg/core/containers/ArchiveSerialization.cpp` and `lua/LuaObject.cpp`).
4. Name them in the table. That is the source-level invocation that keeps the
   bodies in the link.

Related traps found on the way:
- `FUN_008D4A80` is `std::stringstream::str()` forwarding to the stringbuf at
  `+0x0C` (it tail-calls `FUN_0047B610`, which reads a stringbuf's get/put areas
  and builds a string). A comment in `gpg/core/reflection/Reflection.cpp`
  attributes it to `std::runtime_error(const std::string&)` — that is wrong; do
  not propagate it. See [[project_fake_recovered_status_contamination]].
- `lua_setgcthreshold` is *defined* at `lua/LuaObject.cpp:1681` but declared in
  no header, so callers each re-declare it locally. Same class of problem as
  [[project_anon_namespace_statics_are_the_wall]].

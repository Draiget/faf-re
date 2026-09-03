---
name: project-scr-copy-vs-pushstack
description: Moving a LuaObject between the engine's separate Lua universes requires SCR_Copy; PushStack refuses it and aborts the loader.
metadata:
  type: project
---

The engine runs several independent Lua universes at once: the rules keep
`RRuleGameRulesImpl::mLuaState`, the scenario gets its own state in
`WorldSessionUserLoad`, the front end and preferences have theirs.
`LuaPlus::LuaObject::PushStack` (`FUN_00907D10`) compares
`state->l_G != m_state->m_state->l_G` and throws `LuaAssertion` — the binary
has no other check in that function, so any null-`m_state` guard we add there
is our own invention and will masquerade as the same error.

Any recovered helper that "copies" an object to another state by pushing it
onto that state's stack is therefore wrong across universes. The binary's
answer is `Moho::SCR_Copy` (`FUN_004D26D0`,
`src/sdk/moho/lua/CScrLuaObjectFactory.cpp`), a deep clone that rebuilds
tables entry by entry and re-wraps userdata through the reflected
`movRefFunc_`.

Fixed in `ff26bda` for `RRuleGameRulesImpl::ExportToLuaState` /
`UpdateLuaState`. **`src/sdk/moho/ui/UiRuntimeTypes.cpp` still has its own
`CopyLuaObjectToState` with the identical defect** (used by the front-end
data bridge, `SetFrontEndData` / `GetFrontEndData`) — verify against the
binary and convert it the same way when that path is next exercised.

Also learned there: `categories` is not copied at all. Both
`SetupCategories` (0x00529C30) and `ExportToLuaState` (0x00529F70) build the
table fresh on their own target state and publish one newly constructed
`EntityCategory` userdata per map entry.

Symptom to recognise: `warning: Error in background task: state->l_G ==
m_state->m_state->l_G` followed by the map loader aborting.

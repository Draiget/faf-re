---
name: project-luafunction-bool-result
description: FIXED (177e879) - LuaFunction<Ret>::operator() discarded every result that was not void or LuaObject, so LuaFunction<bool> always answered false; that is why every options-dialog dropdown stood open.
metadata:
  type: project
---

# FIXED: LuaFunction<bool> always returned false

`LuaFunction<Ret>::operator()` in `src/sdk/lua/LuaObject.h` handled two cases
and fell through on the rest:

```cpp
} else if constexpr (std::is_same_v<Ret, LuaObject>) { ... }
else { lua_settop(L, savedTop); return Ret{}; }   // <- every other Ret
```

So `LuaFunction<bool>` answered `false` and `LuaFunction<int>` answered `0`
whatever the script returned. The hand-written `Call_*_Bool` siblings in the
same class do it correctly (`Call_ObjectBool_Bool`, FUN_0078AF70, converts with
`lua_toboolean`) - the templated form is our generalisation of that family and
had to convert too.

Callers that were reading a constant: `CMauiControl::OnHide`,
`CMauiControl::GetIsScrollable`, `CScriptObject`'s TaskTick, two
`IUIManager` callbacks, one in `Projectile`.

## Why it showed up as "all dropdowns are open"

`CMauiControl::SetHidden` calls `OnHide(hidden)` and **returns early when it
answers true** - that is the control's chance to refuse. `combo.lua` builds its
dropdown, hides it, then installs

```lua
dropdown.OnHide = function(_, hidden)
    if not hidden and self._listhidden then return true end
```

so that a `Show()` on any ancestor does not drag the dropdown open with it -
`SetHidden` propagates to children unconditionally otherwise. With the result
discarded the refusal never landed and every combo in the options dialog
rendered its list expanded.

Confirmed by probe: 0 occurrences of `ret=1` before, 23 after.

**Watch for the same shape elsewhere**: `if constexpr` chains that end in a
default-constructed return are silent. Grep for `return Ret{}` / `return T{}`
in template call wrappers.

Related: [[project-lua-strlen-pseudo-index]].

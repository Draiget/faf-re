---
name: project-lua-strlen-pseudo-index
description: FIXED (a51b34f) - lua_strlen ignored pseudo-indices, so string.gfind measured a zero-length subject and every wrapped string in the UI (dialog bodies, tooltips) rendered blank.
metadata:
  type: project
---

# FIXED: every wrapped string in the UI was blank

Dialog bodies drew as an empty box with only their buttons. Tooltips were
empty. The cause was two layers down from the UI.

`lua_strlen` (FUN_0090CB10) resolved a non-positive index inline as
`state->top + idx`. The binary calls **`negindex`** there (`0x0090CB31`), which
is the only resolver that understands pseudo-indices - `LUA_REGISTRYINDEX`,
`LUA_GLOBALSINDEX` and `lua_upvalueindex(n)`. Those are large negative numbers,
so `top + idx` lands far below the stack base and the guard returns 0.

`gfind_aux` measures its subject with `lua_strlen(L, lua_upvalueindex(1))`.
Length 0 puts `src_end` at `src_init`, `singlematch` never fires, and the
iterator returns nil on its first call. `WrapText`'s
`for packedWord in string.gfind(text, "[^ \t]+")` then ran zero times and
returned an empty table, so `QuickDialog` set no text and computed a height of
just its padding.

## How it was found

Bracketing, in this order, each step ruling out the layer above:

  1. `CMauiText::SetText` / `GetStringAdvance` probes showed `advanceFunction(" ")`
     being called (so `WrapText` was entered) with no per-word measurement after
     it, and no `SetText` for the body line.
  2. A probe at the top of `gfind` showed it *was* called, with the right
     subject - so `LOC()` was fine and the failure was inside the iterator.
  3. A probe in `gfind_aux` printed `len=0` next to a valid `src` pointer and
     `t1=4` (LUA_TSTRING). That named the culprit exactly.

**Generalisable**: any recovered `lua_*` API that takes a stack index must go
through the binary's index resolver for non-positive indices. Inlining
`top + idx` silently works for ordinary negative indices and silently fails for
every pseudo-index. Audit any other API recovered the same way.

Related: [[project-luafunction-bool-result]], [[project-maui-control-size]].

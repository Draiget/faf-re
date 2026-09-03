---
name: project-lua-gc-upvalue-corruption
description: SOLVED - the traverseproto AV was CD3DPrimBatcher's ctor writing 0x120 bytes past a 4-byte allocation, smashing ~70 neighbouring Lua upvalue blocks. Fixed 60ec20f; includes the allocator-instrumentation recipe that found it.
metadata:
  type: project
---

**SOLVED 2026-08-04 in `60ec20f`.** Access violation at `traverseproto`
(`f->upvalues[i]->marked |= 1`) reading `0x3F800005`, reached from the per-frame
`CUIManager::UpdateFrameRate` -> `lua_pushstring` -> `luaC_checkGC`.

**Root cause: `CD3DPrimBatcher` declared no data members.** Every field it owns
is declared by `CD3DPrimBatcherRuntimeView` and written through a
`reinterpret_cast`, so `sizeof(CD3DPrimBatcher)` was just the vptr - 4 bytes -
while its constructor wrote out to `mAlphaMultiplier` at +0x120. `new
CD3DPrimBatcher` smashed 0x120 bytes past its allocation. The binary sizes it
explicitly: **`push 124h` at 0x007F6BCB**, immediately before the `operator new`
feeding the ctor.

Why it surfaced as a *Lua* crash: a 4-byte request comes from the allocator's
smallest size class, and those pages hold nothing but 4-byte blocks, so the
overrun wrote three identity 4x4 matrices across ~70 neighbours. Lua's per-Proto
upvalue-name array is exactly one 4-byte block, so the next GC walked
`Proto::upvalues` into a float.

## The instrumentation that found it (reusable)

Both probes live in the engine allocator (`gpg/core/utils/Global.cpp`) and write
to a file with raw Win32 calls (`CreateFileA`/`WriteFile`) - no CRT, no
allocation, safe to call from inside `malloc_0`/`free`.

1. **Live-block bitmap** - one bit per 4 bytes, set on hand-out, cleared on
   release, hooked into `malloc_0`, `free`, `AllocateInSmallBlock` and
   `PushHeapBlock`. Reports any hand-out covering an already-set bit.
   **Result: 5.2M allocations, zero overlaps** - which *exonerated the
   allocator* and proved the damage was a stray write. Always confirm the probe
   armed (it prints its base and a mark count); "no report" is meaningless
   otherwise.
2. **Value watch** - register `(address, expected)` for suspect blocks, rescan
   on *every* alloc and free, and on mismatch dump
   `RtlCaptureStackBackTrace`. Scanning on every mark is only affordable with a
   small dense list, so filter registrations (here: page offset 0x900-0xA80,
   the band every victim sat in). At 1024-call granularity the trace was
   useless; at per-mark granularity it landed inside the culprit ctor.

Symbolise with `symat.exe <exe> <IMAGE BASE FROM THIS RUN> <addr>...`; dbgrun
prints the base and it changes every run.

## Generalise: thin class + runtime view = latent heap smash

Audited every `*RuntimeView` pair by compiling a TU of
`Show<sizeof(T)>` instantiations (the undefined-template trick prints the value
in the error). **Every UI class is 4 bytes with an 88-408 byte view**:
`CMauiControl` 4 vs 212/284/236, `CMauiFrame` 4 vs 308, `CMauiBitmap` 4 vs 400,
`CMauiEdit` 4 vs 408, `CMauiText` 4 vs 404, `CMauiBorder` 4 vs 372,
`CMauiItemList` 4 vs 344, `CMauiMesh` 4 vs 320, `CMauiHistogram` 4 vs 308,
`CUIMapPreview` 4 vs 292, `CMauiCursor` 4 vs 8/88.

They are safe **only** because every UI allocation site uses an explicit
`operator new(0x134)`-style size copied from the binary. `CD3DPrimBatcher` was
the one that used a plain `new`, which is why it was the one that smashed.
**Writing `new CMauiFrame(...)` anywhere would reintroduce this instantly.**
When adding an allocation site for any thin class, take the size from the
binary's `push <size>` before its `operator new`.

Related: [[project-render-frame-blockers-2026-08]],
[[project-rendertarget-lane-inversion]],
[[project-thin-class-alloc-and-view-drift]]

## Two more defects this cadence uncovered downstream

`655d94f` **`gpg::STR_GetToken` returned one character per call.** Its
end-of-token loop advanced *while* the character was a delimiter instead of
while it was not; the binary (FUN_00938CB0) breaks out on `strchr` succeeding.
`CUserPrefs` splits dotted option paths with it, so `Game.prefs` was written as
`o = { t = { o = { s = { ... ` with stray `['n.']`/`['s.']` keys wherever the
scan straddled a separator. Startup then rejected its own output as "corrupt or
out-of-date", renamed it `.bad`, and ran on empty preferences. Fourteen other
call sites were equally broken: breakpoints on ':', stat paths on '_', network
addresses on '.', UI key names on '-', and the Lua `STR_GetTokens` binding.

`c9b0858` **`LuaObject::PushStack(LuaState*)` asserted something the binary
never did.** That overload does not exist in the binary at all - the only
exported symbol is the `lua_State*` form at 0x00907D10 - and ours added
`Ensure(state->m_rootState == m_state)`. The binary's guard is only that the two
objects share a `global_State`. **The engine runs two roots (sim and UI) over
one `global_State`**, so cross-root pushes are legal; ours threw on every
`cfunc_GetPreference`. This is the "defensive code the binary never had"
failure mode - when a recovered guard fires, check the binary for the guard
before believing the data is wrong.

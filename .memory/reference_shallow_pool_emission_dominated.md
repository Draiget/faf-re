---
name: reference-shallow-pool-emission-dominated
description: The closure-1 candidate pool is ~243 tokens but almost entirely compiler/container emissions. Screened list as of 2026-08-17 with per-token verdicts, so the sweep is not repeated.
metadata:
  type: reference
---

Screening recipe that works (do not re-derive):

  1. closure-1: every callee already in the have-set or >= 0x00A00000
  2. drop listing names containing `std::` `boost::` `fastvector` `_Node`
     `wx` `lua` `Lua` `__imp` `Wm3::`
  3. drop bodies matching
     `_Myfirst|_Mylast|_Myend|_Isnil|_Parent|_Right|_Left|_Myhead|_Mysize|`
     `_Myres|operator delete|operator new|_InterlockedExchangeAdd|qmemcpy`
  4. require a caller whose address resolves to a **real body** - find the
     `0x00XXXXXX` in a `.cpp`, look ahead 40 lines for a
     `Type::Method(...) {` definition with >8 code lines. This is what
     rejects the comment-only-stub callers.

**Do NOT filter by requiring the listing name to start with `Moho::` /
`gpg::` / `func_`.** That drops every `sub_*` function, which is most of
the pool - it made the pool look like 3 candidates when it is 243. That
error cost a batch on 2026-08-17.

## Screened verdicts (2026-08-17)

| Token | Instrs | Verdict |
|---|---|---|
| `FUN_007600A0` | 168 | STL sort partition (`_Med3`/`_Unguarded_partition`) |
| `FUN_005B4BB0` | 141 | `fastvector<CPathPoint>::insert` |
| `FUN_00702A70` | 74 | `std::map::erase(first,last)` range erase |
| `FUN_0087FCF0` | 66 | inlined 16-byte `memcmp` |
| `FUN_0046D500` | 65 | `weak_count` construction |
| `FUN_0073F940` | 43 | `boost::ptr_vector::push_back` + null-check throw |
| `FUN_008BEB90` | 47 | list/tree walk emission |
| `FUN_004C5190` | 47 | vtable-call loop over a range |
| `FUN_008D98E0` | 34 | `std::map<type_info>` tree find |
| `FUN_004B7D40` | 36 | `std::list::clear()` with element delete |
| `FUN_00453230` | 33 | `msvc8::vector<DebugLine>` element copy |
| `FUN_0085E0A0` | 211 | real, but caller `RenderStrategicIcons` is a comment-only stub |

All are container/compiler emissions the repo's rules say to express
through the container process, not as standalone bodies.

## The one genuine candidate left in that pool

`FUN_0099F410` (67 instrs) = `wxFrame::DoSendMenuOpenCloseEvent`,
dispatched from `WM_ENTERMENULOOP` / `WM_EXITMENULOOP` in
`wxFrame::MSWWindowProc` (0x0099F4B0), which **is** genuinely recovered
as `wxTopLevelWindowRuntime::MSWWindowProc`. Its declaration in
`WxRuntimeTypes.h:5399-5402` already documents the gap: "Only WM_CLOSE is
translated so far. The binary's switch also covers WM_MENUSELECT,
WM_ENTERMENULOOP/WM_EXITMENULOOP, WM_COMMAND, WM_SIZE, WM_PAINT and
WM_QUERYDRAGICON."

Blocked on type modelling, not layout: the body constructs a
`wxMenuEvent` (sets that vftable on a `wxEvent`), and `wxMenuEvent` is
not modelled in this tree - only `wxConstructorForwxMenuEvent`
(`WxRuntimeTypes.cpp:14098`) exists, itself a `[[maybe_unused]]` orphan.
Model `wxMenuEvent` first, then this and the orphan land together.

Low priority: the game window has no menus, so this is fidelity rather
than function.

## Where the real work is

Not in this pool. See [[project-render-frame-driver-elisions]] (six
`WRenViewport::Render` callees behind one keystone) and
[[project-range-rings-draw-cluster]] (two of three bodies written and
patch-saved).

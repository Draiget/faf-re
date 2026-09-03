---
name: project-ui-vector-of-vectors-closure
description: "8-function wx/UI closure at 0x0084E8A0 identified as msvc8::vector<msvc8::vector<T*>> emissions; not landable until the parent chain is recovered"
metadata:
  node_type: project
  type: project
---

Analysed 2026-08-21 (batch 43) from the closure ranking in
[[reference-landable-now-query]]. `UiRuntimeTypes.cpp` is free; this is a
research result, not a blocker on lease.

## What the bodies are

`FUN_0084FF80` (136 instr) reads `[obj+4]` as start and `[obj+8]` as end and
divides the span with `sar 2`, on an object the callers stride by **0x10**.
That is `msvc8::vector`'s `{proxy, first, last, end}` with a 4-byte element --
so the function is `msvc8::vector<T*>::operator=(const vector&)`, and the two
loops above it iterate over *vectors*:

| token | instr | is |
|---|---|---|
| `FUN_0084FF80` | 136 | `msvc8::vector<T*>::operator=` |
| `FUN_0084F820` | 20 | `std::copy` over a range whose element is that vector (0x10 stride) |
| `FUN_0084F8A0` | 12 | `std::fill` over the same |

i.e. the outer container is a `msvc8::vector<msvc8::vector<T*>>`.

Remaining closure members, unidentified: `FUN_0084E8A0` (74),
`FUN_0084EDB0` (29), `FUN_0084EE20` (261), `FUN_0084F200` (197),
`FUN_00850190` (99).

## Why it is not landable

**No `msvc8::vector<msvc8::vector<...>>` exists anywhere in `src/sdk/moho/ui`
or `moho/app` yet**, and the chain's own root `FUN_0084E8A0` is uncited --
`FUN_0084EE20`'s only owner. So there is no source construct that would make
MSVC emit these, and an `Address:` citation on `Vector.h` would be paperwork:
the linker keeps nothing.

The ranking attributed this closure to root `0x0084DA80`
(`SuspendInputWindowEventHandlersAndFlushQueue`), but that function works on
`gpg::fastvector_n<wxWindowBase*, 2>` -- 4-byte elements, not 0x10 -- so the
walk-up reached it by a different path and it is **not** the parent that
instantiates these.

## What would unblock it

Recover `FUN_0084E8A0` (74 instr) first and find which UI object owns the
vector-of-vectors; then the three identified bodies cite onto `Vector.h`'s
`operator=`, `copy_or_move_assign` and the fill member in one pass. Do not
cite them before that member exists in source.

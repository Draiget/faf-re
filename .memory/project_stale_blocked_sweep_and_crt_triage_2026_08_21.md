---
name: project-stale-blocked-sweep-and-crt-triage-2026-08-21
description: Whole-tree stale-blocked-flag sweep technique (found 11 real wins in minutes) + a recurring CRT/STL misclassification pattern + the sentinel-node allocator family that traces back to RbTree.h/Vector.cpp.
metadata:
  type: project
---

Same 2026-08-21 session as [[project_gpg_dtor_vein_closed_2026_08_21]]. Three distinct findings
worth keeping.

## 1. Stale-blocked-flag sweep (cheap, high-signal, whole-tree)

Some tokens carry `status: blocked` in `recovered_progress.json` despite already having a real,
committed, canonical `Address: 0xXXXXXXXX (FUN_XXXXXXXX...)` citation somewhere in `src/sdk/**`.
This is the mirror image of the well-known "fake-recovered" trap ([[project_fake_recovered_status_contamination]]) —
here the DB is wrong in the SAFE direction (too pessimistic), but it still wastes recovery-queue
attention and undercounts real progress.

Recipe (a few minutes, found 11 genuine hits out of 1770 blocked tokens):
```python
# 1. Extract every canonically-cited token tree-wide in one grep pass:
grep -rhoE "Address: 0x[0-9A-Fa-f]{8} \(FUN_[0-9A-Fa-f]{8}" src/sdk/ | grep -oE "FUN_[0-9A-Fa-f]{8}" | sort -u
# 2. Intersect with the blocked set from recovered_progress.json.
# 3. For each hit, confirm the citation is in the COMMITTED HEAD (not another agent's
#    uncommitted WIP) with `git show HEAD:<file> | grep -c 0xADDR` before trusting it.
# 4. Mark recovered with a note explaining it was a stale-flag correction, not a fresh recovery.
```
Caveats found applying this: a naive full-file regex for `0xADDRESS` (not the canonical
`Address: 0x... (FUN_...` pattern) gives false positives — addresses get mentioned in prose
comments describing OTHER functions' behavior ("0x0085E3A0 stacks under this one") without being
a real citation. Require the exact `Address: 0xXXXXXXXX (FUN_XXXXXXXX` prefix.

## 2. Recurring CRT/STL misclassification pattern

Several `blocked` tokens turned out to be genuine `external_dependency` material that had never
been triaged, all found by reading the actual `.c` decompiler body rather than trusting the name:
- `type_info::_m_data` frame-list cleanup (`_TYPEINFO_LOCK`, `frame_root`/`frame_root_nextFrame`) —
  MSVC CRT RTTI internals.
- SSE2/x87 dispatch shims for libm transcendental functions (`global_mode_sse2` + `_mm_getcsr()`
  check, distinct from the already-landed SSE2 *compat-probe* cluster which only detects support —
  this is a DIFFERENT, deeper CRT math-library dispatch layer).
- `std::_Tree::_Max`/`_Min` descend helpers reached only from `external_dependency`-classified
  `std::_Tree::erase` — genuine `std::` (not `msvc8::`) STL internals, ICF-folded (6 twins each).
- **The implicit-local-destructor trap**: a `blocked` token turned out to be the compiler-emitted
  implicit destructor for a LOCAL `std::set<float>` variable inside an already-fully-recovered
  function (`Moho::CDecalManager::RebuildLodHistogram`). Per RULE ONE, "some emissions map to NO
  source line: member destructors... implicit copy ctors — do not invent a call for them." This
  is `external_dependency`, not a function to write. General signal: if a small blocked function's
  only caller is a fully-recovered function whose body already uses the real STL/msvc8 container
  type, and the candidate's shape matches container-internals (RB-tree erase, `_Tidy`, etc.), check
  for this before writing anything.

**How to apply**: when a small (5-50 instruction) blocked candidate's body looks like raw
pointer/offset manipulation with no obvious engine semantics, check its caller chain first — if it
bottoms out in CRT/STL machinery (`_TYPEINFO_LOCK`, `global_mode_sse2`, `std::_Tree`, `_CxxThrowException`
scaffolding), don't try to force an engine-side C++ recovery; verify and reclassify.

## 3. The sentinel-node allocator family — traces back to RbTree.h, not a standalone target

A recurring 10-15-instruction shape appears dozens of times across totally unrelated subsystems
(`SNamedFootprintTypeInfo.cpp`'s footprint list, `IdleUnitSelector`'s `SSelectionSetUserEntity`,
`CD3DFileBatchTexture`'s BVSet, `InfluenceGrid`'s entry set, and more):
```c
result = AllocateCheckedElements(1, N);      // N = sizeof(node), varies per site
if (result) *result = 0;                      // zero first field, -4 sentinel guard
if (result != -4) result[1] = 0;               // zero second field
if (result != -8) result[2] = 0;               // zero third field
*(byte*)(result + K) = 1;                      // two trailing byte flags
*(byte*)(result + K + 1) = 0;
```
This is the MSVC8 `detail::rb_tree<Traits>` (or a hand-rolled sibling list) DEFAULT-CONSTRUCTOR's
sentinel/header-node allocation — i.e. `msvc8::set<T>::set()` / `msvc8::map<K,V>::map()` calling
into `RbTree.h`'s canonical tree-header init, NOT a standalone per-owner function. Confirmed by
tracing `Moho::InfluenceGrid::InfluenceGrid()`'s `entries()` member-initializer (a
`msvc8::set<InfluenceMapEntry,...>`) straight to this exact shape.

**Do not write a standalone C++ function for one of these** — that's the RULE ONE container-lane
trap in a new costume (a tree/list-node shape instead of the more commonly-seen vector shape). The
citation belongs on `detail::rb_tree<Traits>`'s default constructor in `RbTree.h`, following the
exact multi-address-per-sizeof(T) grouping convention already established for
`allocate_slots_checked`/`throw_too_long` in `Vector.h` (see [[project_gpg_dtor_vein_closed_2026_08_21]]).

## 4. Another false-recovered-caller pair found (CrtRuntimeHelpers.cpp, old `codex-main` entries)

`FUN_00A86084` ("Recovered CRT file-position helper...") and `FUN_00933640` ("Recovered VC8
proxy-vector dword insert-count lane...", with a 6-item `depends_on` list including
`FUN_00932F90`) are both DB-marked `recovered` since **2026-04-17/04-20**, `last_worker:
codex-main-*` (a different, older tool/session, predating this Claude session entirely). Neither
address actually appears anywhere in `src/sdk/moho/misc/CrtRuntimeHelpers.cpp` (verified: `grep -c
"0x00A86084\|0x00933640" CrtRuntimeHelpers.cpp` → 0). Classic false-recovered-caller
([[project_fake_recovered_status_contamination]]) — not yet fixed, just documented; this blocks
`FUN_00932F90` and `FUN_00A9C894` (both of which cite these as their sole "recovered" caller) from
being safely recoverable until either the real bodies are written or the DB entries are corrected.
If picking this up: `FUN_00933640`'s `depends_on` list (`FUN_00931BF0, FUN_00932490, FUN_00932610,
FUN_00932940, FUN_00932F90, FUN_00933220`) is a ready-made bottom-up recovery order for the whole
VC8 proxy-vector insert-count cluster — worth a dedicated pass, not a quick pick.

**As of this session, `RbTree.h`/`Vector.cpp` were under sustained concurrent-agent work for the
entire session** (dirty in `git status` continuously across many hours) — evidently a separate
agent was systematically working exactly this vein. Check `git status --short -- src/sdk/legacy/containers/RbTree.h
src/sdk/legacy/containers/Vector.cpp` before picking up any sentinel-node-shaped candidate; if
dirty, this whole family is claimed territory, defer to whoever's mid-flight there.

Known unresolved members of this family as of this session (still `blocked`, still needing
`RbTree.h`'s tree-header ctor citation once that file is free): `FUN_007B08D0` (0x1C=28-byte node,
`SSelectionSetUserEntity`/`WeakSet<UserEntity>` family — also blocks `IdleUnitSelector`'s
process-global ctor and `Moho::SelectionDragger3D::Func2`'s dependency chain), `FUN_0056FE00`
(~68-byte node, `CFormationInstance` family), `FUN_0071C2C0` (~64-byte node, `InfluenceGrid`
family), plus their respective `AllocateChecked*`-style callees (`FUN_007B1420`, `FUN_0071D740`,
etc.) which also belong in `Vector.h`'s `allocate_slots_checked` per-sizeof(T) group.

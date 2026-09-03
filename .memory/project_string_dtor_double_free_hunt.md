---
name: project_string_dtor_double_free_hunt
description: "~msvc8::string's free is parked (562c91e0) because it surfaces a latent double free that crashes in the LOBBY. Records the exact repro stack, everything already cleared, and the two search methods that do NOT work. Relanding is one line once the culprit is found."
metadata:
  type: project
---

## State

`~msvc8::string()` is **declared but its body is a no-op** (`562c91e0`). The one
line to restore is `tidy(true, 0U);` in `String.cpp`.

The declaration is deliberately kept so the type stays
non-trivially-destructible and every container still takes its
`if constexpr (!std::is_trivially_destructible_v<T>)` teardown branch. Removing
the declaration too would change which code runs and mask the bug.

**The win being held back:** re-measured 2026-09-02 with the free live --
allocator in-use on SCMP_009 goes from **736.0 MB to 288.0 MB**, a **443 MB**
reduction and essentially retail's 293.3 MB. Bigger than the earlier
632.4 -> 243.8 measurement. See
[[project_commander_crash_is_memory_exhaustion]] for the A/B method.

**2026-09-02 re-test, and why it did NOT clear the block.** With
`tidy(true, 0U)` restored: the main menu ran 70 s clean and a
`/map SCMP_009` skirmish ran 120 s clean. That proves nothing about the actual
defect -- **`/map` bypasses the lobby entirely**, and the repro is
`CLobby::HostGame` -> `cfunc_GpgNetSendL`. Reverted rather than gambling the
operator's session on a crash they had already reported.

To test it properly someone has to drive the UI to host a game; there is no
command-line path to `CLobby::HostGame`. Note the arg vector is built
*before* the `GPGNET_GetPtr()` gate (`CGpgNetInterface.cpp` ~703), so the
string-copy path runs even with no GPGNet connection -- it is not online-only.

Also cleared this pass, so nobody re-walks them:
- `msvc8::string(string&&)` correctly resets the source to empty SSO
  (`bx.buf[0]=0; mySize=0; myRes=15`), so a moved-from string's destructor is
  a no-op. Not the double owner.
- `msvc8::vector`'s second template parameter is `bool HasDebugProxy`, a
  pure *layout* switch (16 vs 12 bytes). `vector<SNetCommandArg,1>` is just the
  default; there is no bitwise-relocation policy hiding in it.
- `SNetCommandArg(const msvc8::string&)` deep-copies via `mStr{str}`.
- `tidy` always resets to SSO after freeing, so double-*destroying* one string
  object is harmless. The shape must be **two string objects sharing one heap
  block**, or a string read after its owner was freed.

## The repro

Lobby only -- no map, nothing near a memory limit, so this is corruption and not
pressure:

```
msvc8::string::assign_owned                 String.cpp:286   <- the memcpy
msvc8::string::string(const string& other)  String.cpp:66
moho::SNetCommandArg::SNetCommandArg(const SNetCommandArg&)
msvc8::vector<SNetCommandArg,1>::push_back(SNetCommandArg&&)
moho::cfunc_GpgNetSendL                     CGpgNetInterface.cpp:697
moho::CLobby::HostGame                      CLobby.cpp:3323
```

The source string's header still passes `basic_sanity()` -- `mySize <= myRes`,
`myRes` under the cap -- while `bx.ptr` dangles. That is what a recycled block
looks like, which is the whole mechanism: with the destructor live, freed blocks
actually return to the freelist and get reused, so a pointer that was merely
stale becomes a pointer into someone else's data.

## Cleared -- do NOT re-walk

- **`msvc8::vector::reallocate_to`.** Copy branch deep-copies each element and
  only then runs `destroy_all`. Its `memcpy` branch is
  `is_trivially_copyable_v`-guarded, which `msvc8::string` has always failed
  (user-provided copy ctor).
- **`msvc8::vector::copy_or_move_assign`** (`Vector.h:8570`). Guarded by
  `is_trivially_copy_assignable_v<T>`, not the `is_trivially_copyable_v` a naive
  grep looks for. Strings take the element-wise branch.
- **`push_back(T&&)`.** Binds a caller temporary, not an element of the vector
  being grown, so `ensure_grow_for`'s reallocation cannot invalidate it.
- **The whole `gpg` legacy-fastvector ABI helper family** (`CopyFrom`,
  `ReallocateForInsert`, `InsertRange`, `MovePrefixAndSetEnd`...). Their
  `memmove`s look unguarded but the functions carry
  `static_assert(std::is_trivially_copyable_v<T>, "Legacy fastvector ABI helpers
  require trivially copyable element types.")`, so they cannot instantiate for a
  string-bearing element at all.
- **`FastVectorRuntimeMoveRangeAndSetEnd`** -- genuinely unguarded `memmove`,
  but zero callers.
- **Hand-inlined tidy sites** (`AudioEngine.cpp:1281`,
  `WxRuntimeTypes.cpp:62266/64007/81581`, `Vector.cpp:790`). All
  delete-then-stamp `myRes=15`, so a following destructor is a no-op.
- **`SNetCommandArg` itself.** `mStr` has a default member initializer, so it is
  never raw. `CGpgNetInterface`'s own `SNetCommandArg` range helpers are all
  `[[maybe_unused]]` orphans with no callers.

- **Struct-level bitwise copies.** Swept `src/sdk` for
  `memcpy`/`memmove` whose size is `sizeof(SomeStruct)`; none of the hits carry
  an `msvc8::string`. They are `HANDLE`, `SOCellPos`, `SDelayedSubVizInfo`,
  `Vertex`, `CumulusVertex` and pointer arrays.
  `CD3DPrimBatcher::EnsureLegacyQueueCapacity` looked risky (templated raw
  `memcpy` then `operator delete`) but is the realloc/relocate idiom: the old
  block is freed *without* running destructors, so it cannot double free
  whatever the elements owned.

## Two methods that do NOT work here

1. **Grepping for unguarded `memcpy`/`memmove`.** Guards come in at least three
   shapes -- `if constexpr (is_trivially_copyable_v<T>)`, `if constexpr
   (is_trivially_copy_assignable_v<T>)`, and a function-level `static_assert`.
   A text search flags all three as unguarded and wastes the pass.
2. **Reasoning from the crash site.** The faulting string is constructed two
   lines earlier from `lua_tostring`; nothing about that path is wrong. The
   corruption happened *earlier and elsewhere*, and the lobby path is merely the
   first allocation to land on the poisoned block.

## What to try next

Instrument, do not read. The tree has `dbgrun` with a DR0 write watchpoint and a
"poison" filter (see [[reference_dbgrun_crash_harness]]). The tractable shape is
to catch the *first* bad free rather than the second: stamp a magic into
`string::bx.ptr`'s block on tidy and trap on a tidy that sees an already-stamped
block. A refcount/alloc trace keyed by block address is the heavier fallback.

Note the other session was independently hunting an allocator double free in
`Global.cpp` this same day (`ProbeDetectDoubleFree`, `ProbeStampFreedBlock`,
`ProbeValidateLaneChain`) -- coordinate rather than duplicate that work.

---
name: project-sse2-compat-probe-cluster
description: 4-function cluster (func_GetCompatModeSub/func_GetCompatMode/register_sseCompatMode/register_compatFlag) - LANDED 2026-08-19 (commit 783f453), src/sdk/moho/misc/CrtRuntimeHelpers.cpp. First use of .CRT$XI* (vs the existing .CRT$XC* precedent) in this codebase; verified against raw PE bytes.
metadata:
  type: project
---

## LANDED (783f453)

All four functions written and wired. Resolved the `.CRT$XIx` section-letter
uncertainty by reading the actual PE bytes at the `__xi_a` array's address
(`0x00D410C8`, via `pefile`): confirmed a real 9-entry `int(__cdecl*)()`
array in `.rdata`, with `register_sseCompatMode` (0x00A8ECBF) and
`register_compatFlag` (0x00AAA8C5) both present verbatim at their expected
slots. Since neither function has any ordering dependency on its 7 sibling
entries (both are simple, independent global writes), any single
`.CRT$XIx` letter is safe - used `.CRT$XIU` to mirror this codebase's own
`.CRT$XCU` convention for "ordinary" C++ initializers.

## What's there

`FUN_00AAA815`/`func_GetCompatModeSub` (0x00AAA815-0x00AAA865, 20 raw
instructions) is a classic MSVC `__SEH_prolog4`/`__SEH_epilog4` SEH probe:
tries `movapd xmm0, xmm1` (requires SSE2) inside an implicit `__try`; the
inline exception filter/handler checks for `EXCEPTION_ACCESS_VIOLATION`
(0xC0000005) or `EXCEPTION_ILLEGAL_INSTRUCTION` (0xC000001D) and returns 0
if the probe faulted with either, 1 if it ran clean. Faithful modern form:
```cpp
int func_GetCompatModeSub() noexcept
{
  __try {
    __m128d probe = _mm_setzero_pd();
    probe = probe; // force the movapd, or use an intrinsic that compiles to it
    return 1;
  } __except (
    (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
     GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION)
      ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH
  ) {
    return 0;
  }
}
```
`__try`/`__except` precedent already exists in this codebase
(`gpg/core/utils/Global.cpp:1676`, `SetThreadName`) - simpler (fixed
`EXCEPTION_EXECUTE_HANDLER`, no filter expression), but confirms the raw
MSVC SEH syntax is an accepted idiom here, not something to avoid.

`FUN_00AAA865`/`func_GetCompatMode` (44 instr) wraps the sub-probe -
NOT YET READ IN FULL, but has 100% otherwise-clean shape once
`func_GetCompatModeSub` exists (its only blocked callee).

`FUN_00A8ECBF`/`register_sseCompatMode` and `FUN_00AAA8C5`/
`register_compatFlag` (both trivial, already read via Hexrays):
```c
int register_sseCompatMode() { global_mode_sse2 = 0; global_mode_sse2 = func_GetCompatMode(); return 0; }
int register_compatFlag()    { global_compat_flag = func_GetCompatMode(); return 0; }
```
Both globals ALREADY exist as real, heavily-used definitions in
`src/sdk/moho/math/MathReflection.cpp:2325-2326`
(`extern "C" int global_mode_sse2 = 1;` / `extern "C" int global_compat_flag = 1;`),
read at 8+ call sites across `CrtRuntimeHelpers.cpp`/`MathReflection.cpp`
already. Only the WRITE side (the CPU-probe-driven initializer) is missing.

## Why this wasn't landed 2026-08-19

`fa-find-callers` reports BOTH register_ functions as `verdict:
FRAMEWORK_DISPATCH` with a `[init_term]` data xref at `0x00D410C8` into
`__xi_a` - i.e. their addresses are directly present as raw function
pointers in the binary's `.CRT$XIx` C-init array (MSVC's pre-`main()`
C-style static-init table, distinct from `__xc_a`/C++ constructors). This
IS legitimate, recognized evidence (same class as a vtable-slot data xref),
so no traditional "caller" needs writing - but reproducing it in modern
source requires placing the function pointer into the correct `.CRT$XIx`
linker section via `#pragma section(".CRT$XIu", read)` +
`__declspec(allocate(".CRT$XIu"))` (exact letter TBD - would need to be
verified against the ACTUAL section the binary's `__xi_a` array entry sits
in, not guessed), a pattern this codebase has NOT established anywhere yet
(grepped `CrtRuntimeHelpers.cpp` for `CRT$XI`/`__xi_a`/`allocate(".CRT`:
zero hits). Getting the section/ordering subtly wrong on core CRT startup
plumbing is a high-blast-radius mistake for a niche payoff (both globals
already default to `1`, i.e. "assume SSE2/compat supported" - correct for
any real hardware capable of running this today). Needs its own careful,
verified pass, not a bolt-on.

This codebase already had a raw-section-placement pattern
(`GPG_PREREGISTER_INIT` macro, `gpg/core/reflection/StaticInitPhase.h`)
proving the general `#pragma section(...)` + `__declspec(allocate(...))`
technique - but only for `.CRT$XCL`/`.CRT$XCU` (C++ constructor phases).
`.CRT$XIU` (this cluster) is the first `.CRT$XI*` (C-style init table) use.

## How to apply for similar future cases

If another `[init_term]`-verdict token shows up (`fa-find-callers` reports
`reach: yes via=ctor_static`), check whether it's `__xi_a`/`.CRT$XI*` (raw
`int(__cdecl*)()` C-init, runs before any C++ static) or `__xc_a`/
`.CRT$XC*` (C++ constructors, use `GPG_PREREGISTER_INIT` for early/provider
ordering or a plain namespace-scope static object for ordinary `.CRT$XCU`
timing). For `.CRT$XI*` specifically, verify the target's real position by
reading the actual PE bytes at the array's own address with `pefile`
(`pe.get_data(rva, N)`) rather than guessing the letter - this confirmed
the approach was safe here in under a minute and would catch any case
where ordering vs. a sibling entry actually matters.

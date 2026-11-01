# spec.py output: what each function's entry holds

`spec.py <inventory> <spec.bin> <report.txt>` reads the IDA exports (`FUN_<addr>.asm`, `ida_c/FUN_<addr>.c`, `FUN_<addr>.meta.json`) for every retail address in an inventory and writes one entry per function it can describe. The recorder DLL's spec mode reads the same file. A tool that calls retail functions directly (difffuzz-style golden checksums for many functions at once) can read it too.

## spec.bin

Little-endian. Header: `"RRS1"`, then `u32 count`. Then `count` entries:

| Bytes | Field |
|---|---|
| 4 | `va`: function entry in the retail image |
| 2 | `pop`: bytes the function pops on return (its `ret N`; 0 for caller-cleans) |
| 1 | `prologue`: bytes of whole instructions at the entry, at least 5, with no relative branch, call or ret (the recorder copies them) |
| 1 | `ret`: 0 none, 1 eax, 2 st0 as float, 3 st0 as double, 4 edx:eax |
| 1 | `nargs`, then `nargs` argument records of 4 bytes: |

Argument record: `location` (0..6 = eax, ecx, edx, ebx, esi, edi, ebp; `0x80 | n` = stack dword n above the return address), `words` (1 or 2), `hashed` (1 = a scalar by both the Hex-Rays prototype and the asm check), `isFloat` (1 = float or double).

Functions on `report.txt`'s review list (prototype and asm disagree, a struct passed by value, an argument in xmm0/cl/al/st0, no prototype) have no argument records and `ret` only when it is a plain eax/st0 result.

## Caution: Hex-Rays argument kinds

`hashed = 1` means the Hex-Rays prototype says scalar. Hex-Rays often types a pointer as `int`: cross-checked against our own demangled signatures (`tmp/claude/T-20261031-09/recorder/priority_plain_value.tsv`), only a handful of the 411 "all-scalar" entries really take plain values (`luaO_log2`, `luaO_int2fb`, `MaxInt`, `GetPlayerColor`); the rest take `this`, a `lua_State*` or another pointer. Check our signature before treating an argument as a value.

## Where results go

Golden checksums use difffuzz's `--dump` format (`dump_format.h`: one line per target and block of 65,536 iterations, `name block input-hash output-hash`) and `--values` lines (`name iteration inputs -> outputs`, hex words, NaN outputs canonical). faf_math_dump checks a row named the same once it has an adapter that calls our function for that address (`targets_sim.cpp`, `ENGINE_ONLY(...)`).

## Calling the functions directly: `difffuzz --spec`

`difffuzz --spec <spec.bin> [--spec-iters N] [--filter a,b] [--dump FILE] [--values FILE] [--row-timeout S]` reads the spec, picks the entries safe to call without a hand-written thunk, and calls each in the mapped retail image with generated inputs, writing the same two formats as `--dump`/`--values` (`tools/difffuzz/src/spec_run.cpp`; the machine-code stub builder is `spec_stub.cpp`, the row selector and input generator `spec_rows.cpp`).

- **What a row is:** every argument a `hashed` scalar on the **stack** (a plain cdecl function), and a non-void result. Entries with an unhashed argument (a pointer or struct: calling with a raw word faults, and the pointer it really wants is what `spec.py` could not type), a register argument (Hex-Rays' register placements miss unmarked `this` pointers, e.g. 0x00415560 reads `[esi]` before anything else), a callee-pop with a register result, or no result, are counted and skipped with a reason. Of the 3,916 entries in the 3-replay inventory spec, 346 qualify; most of the rest fail the Hex-Rays pointer-as-int check described above.
- **Isolation:** each row runs in its own child process (`--spec-row N` selects one). A function whose error path reaches the OS kills its process (an assert calling `GetModuleFileNameA` through retail's SEH handler, which the in-process guard cannot catch), and a hung call (a walk that never finishes) is killed at `--row-timeout` seconds. The parent appends each child's output and reports the row as `[RETAIL]` or `[FAIL]`, so one bad row never ends the run.
- **Inputs:** one shared generator draws each argument word as an integer edge case (0, 1, powers of two ±1, the int limits) or a float from `GenFloat` (`spec_rows.cpp`), so every platform replays the same stream; a row's stream is seeded from its index in the spec file, as difffuzz seeds a target's from its table index.
- **What the output is for:** the spec rows are retail's side only. To turn a spec row into a checked test, add a normal difffuzz/faf_math_dump row for the function (a generator and an `ENGINE_ONLY` ours adapter); then `faf_math_dump --check golden.txt --values retail_values.txt` compares ours against retail on every build, and the spec run can regenerate retail's numbers for it at any time.

# spec.py output: what each function's entry holds

`spec.py <inventory> <spec.bin> <report.txt>` reads the IDA exports (`FUN_<addr>.asm`, `ida_c/FUN_<addr>.c`, `FUN_<addr>.meta.json`) for every retail address in an inventory and writes one entry per function it can describe. The recorder DLL's spec mode reads the same file. A tool that calls retail functions directly (difffuzz-style golden checksums for many functions at once) can read it too.

## spec.bin

Little-endian. Header: `"RRS2"` (or `"RRS1"`, without the `writes` byte), then `u32 count`. Then `count` entries:

| Bytes | Field |
|---|---|
| 4 | `va`: function entry in the retail image |
| 2 | `pop`: bytes the function pops on return (its `ret N`; 0 for caller-cleans) |
| 1 | `prologue`: bytes of whole instructions at the entry, at least 5, with no relative branch, call or ret (the recorder copies them) |
| 1 | `ret`: 0 none, 1 eax, 2 st0 as float, 3 st0 as double, 4 edx:eax, 5 al, 6 ax, 7 xmm0 as float, 8 eax holding a pointer (recorded, never hashed: an address differs per run) |
| 1 | `nargs`, then `nargs` argument records of 4 bytes: |
| 1 | `writes`: 1 = the function, or anything it can reach through calls and jumps, may store outside its own stack frame, so its extra probe calls could change the game; 0 = probe-safe. A result written through a pointer counts: a re-call would overwrite what the real caller is about to read. So does anything the asm cannot prove: a virtual call or indirect jump, an import, an export with no return at its end, an indexed store into the frame. RRS2 only, right after the entry header and before the argument records. |

The `pop` parser reads both export spellings (`ret 0x58` from capstone, `retn 58h` from IDA, comments stripped). Functions whose asm contains disagreeing `ret N` sizes (an MSVC8 SEH exception-dispatch path ends in a plain `ret` while normal exits use `ret N`) are not written at all: the recorder's unwind matching needs the one pop the taken path will use, and a wrong one mis-attributes returns (observed as `eip=1` — the pushed hook index consumed as a return address — when `Moho::Projectile::Projectile`'s `retn 58h` was misread as `ret`).

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

## Probe mode: real calls re-run with edge values

With `RETAIL_RECORDER_PROBE=1` (and `RETAIL_RECORDER_JOURNAL=<path>`) the recorder, after recording a real call's result, calls the same function again on the same real objects: once with its own arguments, then once per edge value in place of each plain argument. Only entries with `writes == 0` and at least one `hashed` argument are probe candidates (re-calling anything else would change the game). Each function gets 4 rounds, each waiting for 4 times the calls of the last, so the rounds spread over the game.

- **Output** goes to the `RETAIL_RECORDER_OUT` file, appended after the per-function table:
  - `R <va> <call> <arg words> -> <result words>` — the real call of this round.
  - `P <va> <call> <variant> <arg words> -> <result words or F<code>>` — one re-call. Variant -1 has the real call's own arguments, and its result must equal the `R` line's (if it does not, the re-call is not reproducing the call, or the function depends on more than the snapshot). The other variants replace one argument: a float word takes the float list (±0, denormals, FLT_MIN/MAX, ±1, 0.5, 2, pi, 1e±10, 2^24-1, 2^31, 2^63, ±inf, NaN), an int word the int list (0, 1, 2, -1, -2, the 8- and 16-bit limits, INT_MAX, INT_MIN, INT_MIN+1), a two-word argument the double or int64 list.
  - `S <va> <call> <argIndex> <pointer> pre <16 words> post <16 words>` — an unhashed (pointer) argument's first 16 dwords before and after the round (SEH-guarded; `FFFFFFFF` words are unreadable). Pre == post says those 16 words did not change, nothing more.
- **Machine state of a re-call:** the registers, 16 stack words, x87 control word and MXCSR the real call entered with (copied at entry, because the stub's frame is overwritten by the time the call returns), with an empty x87 stack.
- **Gating:** probes run only past a 60s load grace period, and only on the elected leader thread — every thread counts its hooked calls in TLS and the first thread past 100,000 calls claims the leadership (the sim dominates; a fixed "first thread past 60s" claim lost the race to worker threads, and any-thread probing froze the loader). Hooked callees reached from inside a probe stay out of the call table and start no probes.
- **Journal** (`<va> <probesDone> <state> <writes>`): state 1 means skip. It is written as 1 before a round and rewritten after, so a probe that kills the process past the SEH handler stays marked and the next run skips it. A function whose variant -1 faults also stays at 1. Seed a new run's journal from the last one's to keep the skip list, but only from a run of the same recorder build: a journal from a broken build skips functions that were never at fault.
- **Faults:** `F<c0000005>` in a P line means that re-call faulted and was caught. An edge value in a word Hex-Rays typed as an int but that is really a pointer (see the caution above) faults this way, and the variant -1 line of the same round shows the function itself runs.

## RRS3: the two specs of a comparison

`spec_compare.py` writes `"RRS3"`, `u32 count`, `u32 flags` (bit 0: addresses are relative to the exe, for our ASLR build), then entries as in RRS2 with a `u32 id` after `writes`. The id is the retail address on both sides, and the hash starts from it. A word is hashed only when our PDB type says it is a plain int, float, double or int64. Plain arguments pair up in order among the plain ones, because Hex-Rays lists a register function's parameters in register order (`Entity::SetVizToEnemies` is `(mode@eax, this@ecx)`); the words are sorted before hashing for the same reason. A result is compared only when the original returns a value too, at the narrower width.

`RSET`: `"RSET"`, then per function with calls: `u32 id, level, count`, `i64 calls, recorded`, and `count` u64 hashes. A hash is kept when its top `level` bits are zero.

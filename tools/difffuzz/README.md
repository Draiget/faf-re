# difffuzz: differential fuzzing of pure leaf functions

Calls a function in the **retail** `bin\2025.7.1\ForgedAlliance.exe` and the **recovered** C++ for it with the same random inputs, then compares every output word bit for bit. No replay, no engine startup. A full run of 40 targets × 1,000,000 iterations takes about a minute.

```
tools\difffuzz\build.bat                 # builds build\difffuzz_release.exe + build\difffuzz_debug.exe
                                         # (a worktree without dependencies\: set FAF_DEPENDENCIES_DIR first)
tools\difffuzz\build\difffuzz_release.exe                       # every target, 1e6 iterations
tools\difffuzz\build\difffuzz_release.exe --filter SLERP,VecSet --iters 5000000
tools\difffuzz\build\difffuzz_release.exe --list                # targets, retail VA, our source
```

| Option | Meaning |
|---|---|
| `--iters N` | iterations per target (default 1,000,000) |
| `--seed S` | RNG seed (default `0x5EED2007`; each target derives its own stream) |
| `--filter a,b` | run only targets whose name contains one of the substrings |
| `--max-mismatch N` | stop a target after N printed mismatches (default 5) |
| `--strict-nan` | count NaN-payload-only differences as failures (see below) |
| `--skip-extreme` | drop inputs that are denormal/inf/NaN or outside 2^-63..2^63 |
| `--snan` | allow signalling NaNs in generated inputs (off: engine maths never makes one, and x87 `fld` quiets them) |
| `--cw 0xNNNN` | x87 control word for the comparison (default `0x007F`) |
| `--mxcsr 0xNNNN` | MXCSR for the comparison (default `0x1FBF`) |
| `--sse2 N` | value poked into retail `global_mode_sse2` (default 0; 1 tests the CRT's SSE2 math bodies) |
| `--image PATH` | retail exe (default: found by walking up from the tool to `bin\2025.7.1\`) |
| `--spec FILE` | call every auto-callable function of the retail-recorder spec file (see "Spec rows") |
| `--spec-iters N` | iterations per spec row (default 100,000) |
| `--spec-row N` | run exactly spec row N in this process (used internally by `--spec`) |
| `--row-timeout S` | per-row child timeout in seconds (default 300; a hung retail call is killed) |

Exit code: 0 when every selected target passes, 1 otherwise, 3 on a setup failure.

## How it works

- **Build** (`build.bat`): a standalone 32-bit console exe, built with `cl` from `vcvarsamd64_x86.bat`; it never touches `src\main.vcxproj`. The engine TUs under test are compiled **from `src`** (`moho\math\QuaternionMath.cpp`, `moho\math\Vector3f.cpp`, `legacy\math\X87Math.cpp`) with main.vcxproj's float-relevant Win32 switches: v143 defaults `/arch:SSE2 /fp:precise`, plus `/O2 /Oi` and the forced include `platform\X87SqrtCall.h` in Release, or `/Od /Ob1` in Debug. Both flavours are built and should agree. `src\sdk_mirror.cpp` holds verbatim copies of the two definitions that live in TUs too entangled to compile alone; each copy names its source lines, so keep it in sync.
- **Base address**: the exe links at `/BASE:0x10000000 /DYNAMICBASE:NO`. The retail image has no relocations, so it must sit at `0x00400000`. Process initialisation fills that range with NLS views and heaps, so `main` relaunches itself suspended, commits `0x00400000..+SizeOfImage` in the child with `VirtualAllocEx` before it initialises, and resumes it. The child adopts that allocation.
- **Loader** (`src\pe_image.cpp`): copies the headers and sections and applies section protections (`.text` is `PAGE_EXECUTE_READ`). It never runs the entry point, TLS callbacks or CRT init, and never resolves imports. Every IAT slot points at a stub that prints `unresolved import DLL!name (called from retail 0x...)` and raises an SEH exception; the harness then reports `[CRASH]` for that target and moves on.
- **Retail state the CRT would have set**: `global_mode_sse2` (0x01107030) is poked to the `--sse2` value (default 0: the game calls `_set_SSE2_enable(0)`, so the `_CI*` math entries take their x87 bodies). `__sse2_available` (0x01107034, read by `_ftol2`) is poked to 1, as the CRT init sets it on any SSE2 machine.
- **Lua math library**: `--filter lua_` runs one row per `math.*` entry. Each feeds a float the way the retail `math_X` does (operand on the x87 stack or widened to a double argument, result stored with `fstp dword`) to the CRT entry or a standalone retail leaf with the same inline sequence. `math.deg`/`rad`, `random` and `randomseed` have no standalone leaf, so their thunks replay the instruction sequence with the image's constants and its `floor`. `min`/`max` are only an `fcomip` compare of stored floats and have no row.
- **Static inits**: `kRetailStaticInits` in `main.cpp` lists pure C-init entries that run once under the default CW 0x027F. Today these are 0x00BEDC30, which writes the float π at 0x00FB78FC that QuatToAxisAndAngle reads, and 0x00BEDC60, which writes the float π/2 at 0x00FB7914 that COORDS_Pitch subtracts. When a target reads a BSS global, find its writer and add it there.
- **FP environment**: before each call, `fninit`, CW `0x007F`, MXCSR `0x1FBF`. CW `0x007F` is `_PC_24` plus round-to-nearest with all exceptions masked, exactly what the sim thread's `_controlfp(_PC_24, _MCW_PC)` leaves. MXCSR `0x1FBF` has the sticky exception flags set, as they usually are in game, because SSE2 libm bodies can branch on them. Each comparison also checks the x87 stack depth and the control word after the call; that check caught the `fstp st(0)` underflow in `ScaleVectorByMaxLengthX87`.
- **Comparison**: output buffers are pre-filled with `0xCDCDCDCD`, so a lane one side forgets to write is a mismatch too. Results are tallied as:
  - **value mismatch**: printed with input, retail and ours in hex, and tagged `inputs: ordinary` or `EXTREME`. The target fails.
  - **NaN-payload-only**: both sides produced a NaN in every differing word and only the propagated payload differs. x87 keeps the operand with the larger significand, while SSE keeps the first source operand, which depends on MSVC's register allocation. No source change can pin that down, so it is tallied and shown once. `--strict-nan` turns it into a failure.

## Cross-platform dump (faf_math_dump, dedicated-server plan WPR.21)

`faf_math_dump` runs the same targets without the retail image: each target's generator, with difffuzz's seed and per-target stream, and its `ours` function, linked against the engine's own objects (`faf_engine` on Windows, `faf_sim` on Linux) and built with their options. It hashes the inputs and outputs per block of 65,536 iterations (`src\dump_format.h`). `difffuzz --dump FILE` writes retail's outputs in the same format, and that file is the golden one, `tests\math_dump\golden.txt`: every platform must reproduce retail.

- **After every build** (Windows x64, x86 and Linux), `faf_math_dump --check tests/math_dump/golden.txt --iters 131072` runs: the first two blocks per target, about a second. A difference fails the build and names the target, the block, and whether the inputs or the outputs differ.
- **The `math_dump` test** (ctest) checks all 1,000,000 inputs per target, about 10 s.
- **Regenerate the golden file only from retail:** `difffuzz_release.exe --dump <file>`, after difffuzz passes, keeping the file's header. A change to a generator changes the inputs, so it needs a new golden file.
- **The values file** (plan WPL.26), `tests\math_dump\retail_values.txt`: retail's actual outputs for up to 64 inputs per target, one line each, `target iteration input-words -> output-words` in hex. Per target the first 16 inputs of its stream, then up to 24 whose inputs and up to 24 whose outputs hold a NaN, an infinity, a denormal, -0, 0x80000000 or 0x7FFFFFFF. `faf_math_dump --values <file>` runs our function on each line's inputs, alone or with `--check`, after every build and in the `math_dump` test. A difference prints the input, retail's value and ours, so it needs neither the retail image nor Windows. A selected target with no line fails as `MISSING`. Write it with `difffuzz_release.exe --values <file>` and keep its header. A new target or a generator change needs a new values file, as it needs a new golden file.

```
faf_math_dump --check tests\math_dump\golden.txt          # exit 1 on a difference
faf_math_dump --values tests\math_dump\retail_values.txt  # retail's values, case by case
difffuzz_release.exe --values retail_values.txt           # retail's values file (needs the retail image)
faf_math_dump --out windows-x64.txt                       # the file itself, for diffing two platforms
difffuzz_release.exe --dump retail.txt                    # retail's file (Windows x86, needs the retail image)
```

| Option | Meaning |
|---|---|
| `--check GOLDEN` | write the hash lines and compare them with GOLDEN (lines starting with `#` are comments) |
| `--out FILE` | write the hash lines to FILE; lines `target block input-hash output-hash` |
| `--iters N`, `--seed S`, `--filter a,b` | as for difffuzz |
| `--lines [--from N]` | write every iteration as `target iteration inputs -> outputs` (from iteration N on) instead of hashes |
| `--strict-nan` | keep NaN payloads in the outputs (default: every NaN output word becomes `7FC00000`) |

To find a difference, compare the files: the input hash says whether the generator or the function differs, and the block number gives the range. Then run both sides with `--filter <target> --lines --from <block × 65536> --iters <(block + 1) × 65536>` and diff those.

- **Floating-point environment:** our function runs as `faf_sim_math_tests` runs the sim's code: x87 precision 24 bits on x86 and the CRT's SSE2 lane off. The generator runs at the x87 default (53 bits), because the x86 build converts its 64-bit integers to double with `fild`.
- **Generator rules:** one random draw per expression. A call's arguments are evaluated right to left by the Microsoft ABI and left to right by System V, and cl and clang order a binary operator's operands differently. A float the generator computes from other lanes goes through `DerivedFloat`, which turns a NaN into `7FC00000`, because the sign and payload arithmetic leaves on a NaN are the compiler's choice.
- **NaN payloads in outputs:** which operand's payload an operation keeps follows the x87/SSE split and the compiler's operand order, so by default they are canonicalised, as difffuzz tallies them instead of failing. A target with integer outputs (`lua_randomseed`) sets `rawOutputs`, and its words are never treated as NaNs.
- **Retail stubs:** `src\retail_absent.cpp` defines every `retail::` thunk as an abort, so the targets table links unchanged. Add a stub there with each new thunk.

Results on 2026-10-29 (Windows clang-cl, Linux clang 18 and glibc 2.39, retail through difffuzz built with cl): retail, Windows x64, Windows x86 and Linux x64 write the same file at 1,000,000 inputs per target. With `--strict-nan`, the first run (before the generators were made portable) showed NaN-payload-only differences: `QuatToMatrix` 1,225 and `BuildRotationMatrixFromEulerHPR` 23 of 1e6 between Windows x64 and Linux, `BuildTiltShortestArcDelta` 621 of 1e6 between x86 and x64.

The first comparison with retail found one engine difference: `math.randomseed` converted its argument with a plain `int64` cast, which clang saturates, so +inf and values from 2^63 up seeded with `0xFFFFFFFF` where retail's `fistp qword` (0x0091A0F5) stores the integer indefinite and seeds with 0. It now uses `msvc8::TruncateToInt64`.

The fourth wave (12 rows: the retail callers of the inline X87Math helpers and the remaining sim-called leaves of QuaternionMath, Vector3f, GridPos, VMatrix4 and the Wild Magic extras; plan WPR.21) found four more. The cl-built difffuzz passed the first; only `faf_math_dump` against retail's golden file showed it:
- `HaStar::Cluster::QuantizeEdgeCost` (0x0092D8B0): `static_cast<int>(std::ceil(scaled))` is undefined for an infinite quotient (a zero distance), and clang's x64 code saturated it into bucket 31 where retail's `fistp` stores the integer indefinite and the clamp gives bucket 0. It now runs retail's `frndint`/`cmova`/`fistp` sequence. `tests/sim_math/golden.txt` had recorded bucket 31 for its three infinite cases.
- `FloorSecondsToTicks` (0x0066D1D0) and `GridPos::GridPos` (0x00506E20): retail's floor (`frndint`, `fcompi`, `cmovb -1`) also borrows for a NaN, which `fcompi` reports as below, so NaN floors to 0x7FFFFFFF; ours gave 0x80000000.
- `VAxes3::VAxes3(quat)` (0x004EC590): retail doubles the later lane of each mixed product (`(2y)x`, `(2z)x`, `(2z)y`, as `VMatrix4::Set` does); ours doubled the earlier one, which overflows to infinity once a lane passes FLT_MAX / 2.

The fifth wave (10 rows: the eight `CColPrimitive<Box3f/Sphere3f>` collision virtuals, `DistVector3Segment3<float>::GetSquared` for projectiles and `IntrBox2Box2<float>::Test` for unit steering) moved the Wild Magic queries into the engine. Retail linked a Wild Magic compiled for x87: each expression stays on the stack with a 24-bit significand and the register's wide exponent, and every named float, `Vector3` temporary and `Dot`/`FAbs`/`Sqrt` result is stored to float once (`IntrSegment3Sphere3<float>::Find` stores `kDiff.Dot(kDiff)` at 0x00A47214 and compares `fQM*fQP` on the stack). Built from source for SSE the library parted from retail on 176 of the 1,000,000 inputs of the five rows that run its queries, all but one with a lane outside 2^-63..2^63 or non-finite; the ordinary one: a zero-length segment on a sphere's centre, where `fQM*fQP` (about 4e-63) flushed to 0. `src/moho/math/Wm3Queries.cpp` ports the nine queries the engine calls with `msvc8::X87Float` (`src/legacy/math/X87Float.h`, the x87 value held in a double and rounded to 24 bits per operation), and the compiled `Wm3Foundation`, `Wm3Dx9Renderer` and `Wm3Dx9Application` libraries are gone (`cmake/deps/wildmagic` is headers only). Two findings:
- `IntrBox3Sphere3<float>::Find` (0x00A43420) reports a hit on its "moving away" result (Wild Magic 3.8 tests `iRetVal != 0` as the miss) with intersection coordinates it never set; retail reads them from slots shared with other locals and from the caller's stack. `CColPrimitive<Sphere3f>::CollideBox` only gets there with an infinite, NaN or overflowing lane, so `ColSphere::CollideBox` draws finite lanes and the query has no row of its own.
- The box-box SAT (`ComputeBoxBoxContactManifold`, 0x00474830) picks each axis's overlap bounds with `comiss` selects (0x00474E15..0x00474E2E), not `fmin`/`fmax`: an unordered compare keeps the other box's bound, which `fmin`/`fmax` drop when it is NaN. 2,213 of 200,000 `ColBox::CollideBox` inputs differed.

The sixth wave (13 rows, 105 in all; plan WPR.21) covers what the sim still ran untested: `CHeightField::GetElevation`, `CRandomStream::FRand(lower, upper)`, `VTransform::Inverse`, the Vector2f leaves, `RayBoxSlabClip` and `CAniPoseBone::Rotate` called in the retail image (the bone's pose holds one record whose dirty byte is set, so `CAniPose::MarkBoneDirty` returns at once), and five inlined X87Math sites whose thunk runs the site's own instructions: the fall axis in `MotorFallDown::Update` (0x006952A9..0x006953B1), `Atan2Difference` (0x006BDAF2..0x006BDB31, through retail's float atan2 leaf), the dive curve speed (0x006C336C..0x006C3380), the projectile speed (0x006A2846..0x006A2861) and the Lua number key's `cvttss2si`. `inv_sqrt` (0x0050D150) has no row: its only caller, `BuildTiltShortestArcDelta`, has one. Three findings:
- `CHeightField::GetElevation` (0x0044FB90) floors with `frndint`/`fcompi`/`cmovb -1`/`fistp`, and `x - static_cast<float>(static_cast<int>(std::floor(x)))` is undefined outside the int range: clang folds it to `x - floor(x)`, 0 where retail subtracts the integer indefinite. The cl-built difffuzz passed; Windows x64 and x86 (clang-cl) differed in both checked blocks of the golden file. GridPos's floor is now `msvc8::FloorToIntX87`, which both use.
- `CRandomStream::FRand(lower, upper)` (0x0051B5C0) keeps the range, `range * word` and the 2^-32 scale on the x87 stack with its wide exponent; through `MulTwisterWord`'s float product a range near FLT_MAX overflowed to infinity. Now `msvc8::TwisterWordInRange`.
- The dive curve speed forms `phase * pi` on the x87 stack before `fsin`; a denormal phase rounded onto the float grid first gave a sine one or two ulps away. `msvc8::SinTimes` is now `msvc8::SinOfProductTimes(phase, pi, base)`.

The seventh wave (1 row, 106 in all; plan WPL.25) covers the integer floor and ceil sites. All 38 `static_cast<int>(std::floor/ceil(x))` sites in the sim folders were undefined for NaN and outside the int range. Retail does each one with the inline `frndint`/`fcompi`/`cmov`/`fistp` sequence (a few also with `cvttss2si`). They now call `msvc8::FloorToIntX87`, the new `msvc8::CeilToIntX87` (`cmova +1`, so a NaN ceils to 0x80000000) or `msvc8::TruncateToInt`. The row `CeilToIntX87` calls retail's standalone copy of the ceil sequence at 0x00425110.

`build.bat` compiles `src/moho/collision/CColPrimitiveBase.cpp` and the two Wild Magic files for these rows; `src/engine_absent.cpp` stands in for the three engine definitions they reference but no row reaches (`VAxes3(quat)`, `gpg::HandleAssertFailure`, `gpg::STR_Printf`).

Rows whose engine function is in a TU this build cannot compile use a mirror in `sdk_mirror.cpp`; `faf_math_dump` calls the engine's own definition instead (`ENGINE_OR_MIRROR` in `targets_math.cpp`), except for `RATE_GameRateToSpeed` and `ProjectBoxOntoAxis`, which the engine keeps in anonymous namespaces. New rows go at the end of `kTargets`: a row's random stream comes from its index.

## Spec rows: calling every spec function without a thunk each

`difffuzz --spec <spec.bin>` (the file `tools/retail-recorder/spec.py` writes; `tools/retail-recorder/SPEC_FORMAT.md`) calls every **auto-callable** entry in the mapped image directly: a machine-code stub built per function at run time (`src/spec_stub.cpp`) places the generated argument words in the stack slots the spec names, calls the retail entry and stores the result (`src/spec_rows.cpp` selects the rows and generates the inputs, `src/spec_run.cpp` runs them). No hand-written thunk per function.

```
difffuzz_release.exe --spec ..\retail-recorder\build\spec_all.bin --spec-iters 2000 --values spec_values.txt
```

- **Auto-callable** means: every argument a scalar the Hex-Rays prototype and the asm agree on, placed on the stack (a plain cdecl function), and a non-void result. Unhashed (pointer/struct) arguments, register arguments (often an unmarked `this`), callee-pops-with-register-result and void functions are skipped with a reason. Of the 3,916-entry inventory spec, 346 rows qualify — the Hex-Rays pointer-as-int caveat (`SPEC_FORMAT.md`) explains the rest.
- **One child process per row** (`--spec-row N` for a single one): a retail error path that reaches the OS kills only that child, and `--row-timeout S` (default 300) kills a hung call. Good rows print `[RETAIL]`, bad ones `[FAIL]` and the run continues.
- The output formats are faf_math_dump's (`--dump`, `--values`), so a spec row's numbers drop into the same files once an ours-side adapter exists for the function (a row in `kTargets`/`AllTargets`); until then they are retail's reference numbers. `--filter` takes the row names (`spec_<VA>`).

## Sim targets on engine objects

`src\targets_sim.cpp` holds rows for sim functions that work on an engine object rather than on a few floats. Retail builds the object with its own constructor, runs the function and frees the object; ours does the same with the engine's class. Rows come after the math rows (`AllTargets`), so a math row's random stream does not move.

- **Retail allocator**: the image's heap is set up by CRT init, which never runs here, so `main` patches the allocator's three primitives (`malloc_0` 0x00958B20, `free` 0x00958C40, `msize` 0x00957EA0, all cdecl) with a `jmp` to the harness's heap (`_aligned_malloc` at 16 bytes, zero-filled so a read of an unwritten buffer gives the same value every run). `operator new`/`delete`, `calloc` and `realloc` reach these three, so retail constructors and container growth work. Imports still trap.
- **Object contents from a few words**: a row carries a size, a seed and a shape code, and one integer-only expander both sides share (`FillFieldSamples`) fills the object, so a row stays within `kMaxWords` and every platform builds the same object.
- **Heap guard**: each redirected block has 16 guard bytes after it, checked on free. A retail write past a block prints `[HEAP]` and fails the row; without it the write corrupted the harness heap and the process died later with no output.
- **Hang watchdog**: difffuzz and `faf_math_dump` each run a thread that ends the process (exit 4) once one iteration has run for 60 s, printing `[HANG]` / `HANG` with the target, iteration and input. A call that never returns used to hold the run, or the post-build check, until it was killed.
- **Retail only in difffuzz**: the standalone build cannot compile the engine TUs these classes live in, so a row's `ours` is null there. difffuzz runs retail (crash, x87 depth and control-word checks included), prints `[RETAIL]` and writes retail's outputs with `--dump` and `--values`; `faf_math_dump`, linked against the engine, checks them after every build. A row whose output is too large for the format hashes it (FNV-1a over the values, `rawOutputs`).

| Row | Retail | What both sides do |
|---|---|---|
| `CHeightField::UpdateBounds` | 0x00476BB0 | build a field of 2..64 x 2..64 cells (powers of two, as every map: for an odd side the constructor's tier 0 is `cells >> 1` wide but a whole-field `UpdateBounds` writes one column past it, in retail and in ours; a 1-cell field has no tier grid at all and the tier readers fault on it), bound it whole, refill the samples from a second seed, `UpdateBounds` over a rect (inside, past the edges, `0x7FFFFFFF`, negative); out: tier count and a hash of every tier's size and min/max words |
| `CHeightField::Intersection` | 0x00476F30 | build and bound a field, intersect a line (aimed at the surface, along a cell diagonal, along an axis or straight down, level, from outside the map, or any floats; finite, `FLT_MAX` and infinite ranges); out: the point and the hit record. Line starts stay within 2^20 and direction lanes are 0 or at least 2^-100: a NaN, infinite or far-off start, or a lane so small that a clip limit overflows to infinity or turns into a NaN (`(-1/d) * 0`), gives the cell walk no end, in retail as in ours |
| `CHeightField::ClipSegmentToWorld` | 0x004776E0 | the Intersection row's lines with any lane, the range included, swapped 1 time in 5 for any float (NaN, infinite, denormal): the clip walks no cells, so those are safe here; out: the result, then min and max |
| `CHeightField::GetTierBounds` | 0x00475DA0 | build and bound a field, read one tier cell's min and max (tier 0: the 2x2 samples; tier n: min/max grid n-1) at x, z inside, past the edges, near `0x7FFFFFFF` or any; the tier stays within the field's count, since retail indexes the tier vector unchecked (0x00475C0E); out: min and max in world units |
| `InfluenceGrid::GetThreat` | 0x00715750 | a grid's own threat record, decay rates and 0..6 per-army records, 14 floats each, from a seed (small exact values, any bits, or a mix); a threat type in -2..16 and an army that is negative (the sum over all armies) or inside the vector, since retail indexes it without a bound (0x00715788); out: the threat |
| `InfluenceGrid::DecayInfluence` | 0x00715130 | the same records; out: the 14 threat lanes after one decay step |
| `VEC_LookAt` | 0x004ECBD0 | an up and a forward vector: a random heading, forward parallel to up (the collapsed cross product), zero or tiny, or any floats; out: the 9-float VAxes3, untouched when forward has no length (MathReflection.cpp is engine-only, so this row runs here) |
| `VEC_Mul4x3` | 0x004EE710 | two 4x4 matrices of values in -4..4 with any float one lane in ten; out: the 16 lanes, the w lanes left as they were |
| `CHeightField::GetNormal` | 0x0069A620 | build a field, sample the normal at a coordinate on, near or past the sample lines |

Field shapes: flat, random words, rolling, terraced, a 0/0xFFFF checkerboard, and ridges along the cell diagonals.

## Adding a target

1. Read `decomp\recovery\disasm\fa_full_2026_03_26\FUN_<VA>.asm` and note which registers or stack slots it reads before writing; where the result goes (`eax`, `al`, `st0`, or `xmm0`, which MSVC8 used for some internal float returns); and who pops the arguments (`ret` vs `ret N`). Also check that it calls nothing but other leaves (`faidx card FUN_<VA>`).
2. **Thunk** (`src\retail_thunks.h/.cpp`): write a `__declspec(naked)` `__cdecl` wrapper that saves `ebx/esi/edi/ebp`. After those four pushes, argument *k* is at `[esp + 20 + 4k]`. Load the retail inputs, `mov reg, VA` / `call reg` through a register the function does not take as input, then fix up the result and restore:
   ```cpp
   // 0x0044F7E0: reads [edi], writes [esi], mov eax, esi.
   __declspec(naked) void* __cdecl NormalizeVectorInto(void*, const void*)
   {
     __asm {
       push ebx
       push esi
       push edi
       push ebp
       mov esi, [esp + 20]      ; dest
       mov edi, [esp + 24]      ; source
       mov eax, 0x0044F7E0
       call eax
       pop ebp
       pop edi
       pop esi
       pop ebx
       ret
     }
   }
   ```
   Fix-ups: `movzx eax, al` for a bool. For an `xmm0` float, use `sub esp,4 / movss [esp],xmm0 / fld [esp] / add esp,4`. For by-value structs, push their dwords last-to-first. For a callee-pops function, leave out the `add esp`.
3. **Target** (`src\targets_math.cpp`): write three small functions, then add one row to `kTargets`: `{name, VA, "our file + symbol", inWords, outWords, inLayout, outLayout, gen, retail, ours}`.
   - `gen(Rng&, u32* in)`: fill the input words. Use `GenFloat`, `GenVec3`, `GenVecPair` (near-parallel and antiparallel), `GenQuat`/`GenQuatPair`, `GenAngle` (includes ±π ± k ulp), `GenT` and `GenEdge` from `gen.cpp`.
   - `retail(in, out)` and `ours(in, out)`: unpack with `Load`, `Canary` the outputs, call the thunk or the recovered function, then pack *every* output into `out`: the return value, any in-place operands and any flags.
4. If the recovered function is in another TU, add that `.cpp` to `SDK_SRCS` in `build.bat` when it compiles standalone. Otherwise mirror it in `sdk_mirror.cpp` with a comment naming the file and line range.

## Mismatch classes found so far (all fixed in src)

All of them come from the x87-vs-SSE split. The 2007 build ran these chains on the x87 stack. Under `_PC_24` every step rounds its *mantissa* the way float does, but keeps the x87 *exponent* range until the final `fstp`, so values that leave the float range in between, or go denormal, differ from per-step SSE float maths. The fix in each case is an `msvc8::*X87` helper in `legacy\math\X87Math.cpp` that mirrors the asm range, with an x64 twin in `X87Math64.asm`. The MSVC8 CRT's `fmod` has its own zero-sign quirk, handled by `msvc8::fmod`.

Inlined copies of `NormalizeAngleSignedRadians` (0x0062FB50) take their argument straight off the x87 stack, so `_CIfmod` sees a value that was never rounded to float. In `SetFiringArc`/`SetAimingArc` a centre of `-2^-150` stays non-zero through the fmod and only rounds to `-0` afterwards. Those sites use `moho::NormalizeAngleSignedRadiansX87(msvc8::HalfSumX87(a, b))`.

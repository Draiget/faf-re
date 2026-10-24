# difffuzz: differential fuzzing of pure leaf functions

Calls a function in the **retail** `bin\2025.7.1\ForgedAlliance.exe` and the **recovered** C++ for it with the same random inputs, then compares every output word bit for bit. No replay, no engine startup. A full run of 40 targets × 1,000,000 iterations takes about a minute.

```
tools\difffuzz\build.bat                 # builds build\difffuzz_release.exe + build\difffuzz_debug.exe
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

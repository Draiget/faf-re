# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries.

## What This Repo Does

- Reconstructs C++ SDK/game code from FAF binaries, RTTI/vtables, and decompiler output.
- Restores class layouts, methods, and behavior in `src/sdk/**`.
- Keeps binary-backed address annotations in source (`Address: 0xXXXXXXXX`) for traceability.

## Build Environment

### Original FAF binary facts

- Binary format: `PE32` (`x86`), Windows GUI subsystem.
- Original toolchain: `MSVC 8.0` (`Visual Studio 2005`, linker `8.00`).
- Base address: `0x400000` (relocations stripped, no ASLR).
- CRT usage: no `MSVCR*` import, likely static CRT (`/MT`).

### Building this repository

Use a Visual Studio developer shell before `msbuild`:

```bat
%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
```

Build example:

```bat
msbuild src\sdk\sdk.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32
```

### Boost bootstrap (external dependency)

Use the in-repo patch + bootstrap flow for your external Boost `1.34.1` path:

```bat
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_boost_1_34_1_required.ps1 -BoostRoot "<your external boost path>"
```

Details:
- `dependencies/patches/boost_1_34_1_faf_required.patch`
- `dependencies/patches/boost_1_34_1_faf_required.md`

## Known Dependencies in FAF

- Boost `1.34.1` (verified via `scripts/detect_boost_patch_version.py` against `1.34.0`/`1.34.1` runtime signatures)
- LuaPlus `5.0` build `1081` (with local thread-related modifications)
- wxWidgets `2.4.2` (MSW)
- Wild Magic `3.8` (now Geometric Tools)
- [zlib `1.2.3`](https://github.com/OSDVF/zlib-win-x64)
- BugSplat
- CRI Middleware (Sofdec + ADX)
- DirectX 9/10 (with XACT audio; DX10 path is partial/non-functional in FA)

## Function Coverage (Script-Based, Fast)

Coverage is computed from:

1. `decomp/recovery/fa_function_names_*.json` (IDA function universe)
2. `Address: 0x...` annotations found under `src/sdk/**`

Run:

```bat
python scripts/recovery_coverage.py
python scripts/recovery_coverage.py --dump-excluded-external-csv decomp/recovery/reports/boost_function_inventory_2026-03-26.csv
python scripts/detect_boost_patch_version.py --mode binary --binary-file bin/external/ForgedAlliance.exe
```

Snapshot (2026-03-26):

- Reconstructed FAF functions: `3,766/67,153 (5.61%)`
- Scoped (`moho + gpg + external`, with Boost + zlib excluded): `2,961/13,217 (22.40%)`
- External dependencies excluded from scoped denominator: `Boost 6/217 (2.76%), zlib 0/15 (0.00%)`
- zlib exclusion rationale: in-binary calls to `inflate/deflate` resolve to internal FAF.exe addresses (no zlib imports).
- External entries excluded (no body evidence): `356`
- Boost address inventory: `decomp/recovery/reports/boost_function_inventory_2026-03-26.csv`
- Boost exclusion summary: `decomp/recovery/reports/boost_function_inventory_2026-03-26.md`
- zlib linkage audit: `decomp/recovery/reports/zlib_linkage_audit_2026-03-26.md`

Namespace split:

- `moho`: `2,425/8,717 (27.82%)`
- `gpg`: `473/2,172 (21.78%)`
- `external`: `63/2,340 (2.69%)`

External dependency split:

- `wxWidgets`: `20/1,359 (1.47%)`
- `MSVC STL/CRT`: `4/398 (1.01%)`
- `WildMagic`: `28/387 (7.24%)`
- `LuaPlus/Lua`: `11/184 (5.98%)`

## Projects

- `inspect-injector`: injector/launcher for runtime inspection.
- `inspect`: injected DLL.
- `main`: FAF wrapper app.
- `sdk`: reconstructed SDK/game code.

## Notes

- `USE_X87_COMPATIBILITY`: keeps x87-compatible floating-point behavior where needed.

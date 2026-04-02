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

Current coverage snapshot (2026-04-02):

- Total FAF functions: `67,153`
- Recovered FAF functions in source annotations: `11,433/67,153 (17.03%)`
- Scoped coverage (`moho+gpg+external`): `4,910/13,217 (37.15%)`
- Annotated addresses under `src/sdk/**`: `11,719` (`FA: 11,433`, `non-FA: 286`)

Namespace split:

- `moho`: `4,030/8,717 (46.23%)`
- `gpg`: `702/2,172 (32.32%)`
- `external`: `178/2,328 (7.65%)`

External dependency split:

- `wxWidgets`: `88/1,359 (6.48%)`
- `MSVC STL/CRT`: `28/398 (7.04%)`
- `WildMagic`: `36/387 (9.30%)`
- `LuaPlus/Lua`: `26/184 (14.13%)`

Recovery DB snapshot (2026-04-02, `fa_full_2026_03_26`):

- Exported done: `67,162`
- Recovered: `19,316`
- Pending: `46,849`
- Blocked: `1,024`
- In progress: `22`
- Coverage: `28.76%`

## Projects

- `inspect-injector`: injector/launcher for runtime inspection.
- `inspect`: injected DLL.
- `main`: FAF wrapper app.
- `sdk`: reconstructed SDK/game code.

## Notes

- `USE_X87_COMPATIBILITY`: keeps x87-compatible floating-point behavior where needed.

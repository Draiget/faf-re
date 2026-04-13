# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries.

## Recovery Coverage (2026-04-13, `fa_full_2026_03_26`)

Progress snapshot:

- Total FAF functions (IDA index): `67,153`
- Recovered so far (source annotations, in-scope families): `7,326`
- **Coverage (moho + gpg + external): `55.41%`**

Namespace families:

- `moho`: `5,520/8,717 (63.32%)`
- `gpg`: `1,417/2,172 (65.24%)`
- `external`: `375/2,328 (16.11%)`

External dependency status (progress):

- `wxWidgets`: `125/1,359 (9.20%)`
- `MSVC STL/CRT`: `51/398 (12.81%)`
- `WildMagic`: `42/387 (10.85%)` — consolidated as upstream `external_dependency` (see [`dependencies/patches/wildmagic3p8_faf_required.md`](dependencies/patches/wildmagic3p8_faf_required.md))
- `LuaPlus/Lua`: `157/184 (85.33%)`

Progress DB status breakdown (`decomp/recovery/recovered_progress.json`, `fa_full_2026_03_26`):

- `recovered`: `24,780` (70.14%)
- `skip`: `4,738` (13.41%) — CRT-internal / compiler-generated
- `external_dependency`: `2,855` (8.08%) — third-party libs (libpng,
  zlib, wxWidgets, LuaPlus/Lua, boost, MSVC STL, CRI Sofdec/ADX, undname,
  bugsplat) and CRT helpers
- `needs_evidence`: `2,048` (5.80%)
- **`blocked`: `908` (2.57%)** — functions previously attempted that
  depend on an unrecovered subsystem, a not-yet-typed owner class, or
  a non-trivial call-tree not yet walked bottom-up. The remaining
  blocked bucket is dominated by large single-function engine work
  (UI dialogs, Sim bootstrap, large Unit/command state machines,
  shader/material caches) plus a few Moho typed-owner bundles
  (CFormationInstance layout, CUnitAssistMoveTask Execute path) that
  each need a dedicated recovery pass.
- **Total tracked in progress DB: `35,328`**

## Patch + Build Quickstart

Use a Visual Studio developer shell before `msbuild`:

```bat
%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
```

Patch/bootstrap required external dependencies:

```bat
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_boost_1_34_1_required.ps1 -BoostRoot "<your external boost path>"
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_wxwindows_2_4_2_required.ps1 -WxRoot "<your external wxWindows-2.4.2 path>"
```

Build:

```bat
msbuild src\sdk\sdk.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32
```

This command is validated in a VS developer shell; expected result is `0 Error(s)` (warnings remain).

Recommended hang-safe build wrapper:

```bat
powershell -ExecutionPolicy Bypass -File scripts\build_sdk_with_timeout.ps1 -TimeoutMinutes 120 -NoOutputTimeoutMinutes 10
```

Patch/build details:

- `dependencies/patches/boost_1_34_1_faf_required.md`
- `dependencies/patches/wxwindows_2_4_2_faf_required.md`
- `scripts/build_sdk_with_timeout.md`

## Known Dependencies in FAF

- Boost `1.34.1`
- LuaPlus `5.0` build `1081`
- wxWidgets `2.4.2` (MSW)
- Wild Magic `3.8` (now Geometric Tools)
- [zlib `1.2.3`](https://github.com/OSDVF/zlib-win-x64)
- BugSplat
- CRI Middleware (Sofdec + ADX)
- DirectX 9/10 (with XACT audio; DX10 path is partial/non-functional in FA)

## Projects

- `inspect-injector`: injector/launcher for runtime inspection.
- `inspect`: injected DLL.
- `main`: FAF wrapper app.
- `sdk`: reconstructed SDK/game code.

## Notes

- `USE_X87_COMPATIBILITY`: keeps x87-compatible floating-point behavior where needed.

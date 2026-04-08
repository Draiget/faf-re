# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries.

## Recovery Coverage (2026-04-08, `fa_full_2026_03_26`)

Coverage is computed from:

1. `decomp/recovery/fa_function_names_*.json` (IDA function universe)
2. `Address: 0x...` annotations found under `src/sdk/**`

Run:

```bat
python scripts/recovery_coverage.py
python scripts/recovery_coverage.py --dump-excluded-external-csv decomp/recovery/reports/boost_function_inventory_2026-03-26.csv
python scripts/detect_boost_patch_version.py --mode binary --binary-file bin/external/ForgedAlliance.exe
```

Progress snapshot:

- Total exported functions: `67,164 of 67,164 (100.00% completed)`
- Recovered so far: `27,190`
- Pending: `37,912`
- Blocked: `2,111`
- Coverage (recovered): `40.48%`

By namespace:

- `moho`: `5,023/8,717 (57.62%)`
- `gpg`: `1,350/2,172 (62.15%)`
- `other`: `11,733/53,936 (21.75%)`
- `dependencies` (external entries with body evidence): `360/2,328 (15.46%)`
- `dependencies` not link-proven in built libs (recovery-required): `402/1,063 (37.82%)`

By external dependency:

- `wxWidgets`: `1,265/1,359` will be linked (`93.08%`); recovery-required `1/94 (1.06%)`
- `MSVC STL/CRT`: `0/398` will be linked (`0.00%`); recovery-required `192/398 (48.24%)`
- `WildMagic`: `0/387` will be linked (`0.00%`); recovery-required `50/387 (12.92%)`
- `LuaPlus/Lua`: `0/184` will be linked (`0.00%`); recovery-required `159/184 (86.41%)`

`recovery-required` means non-`external_dependency` completed statuses over functions not link-proven in built libs.

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

Optional hang-safe build wrapper:

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

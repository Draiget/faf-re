# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries.

## Recovery Coverage (2026-04-10, `fa_full_2026_03_26`)

Coverage is computed from:

1. `decomp/recovery/fa_function_names_*.json` (IDA function universe)
2. `Address: 0x...` annotations found under `src/sdk/**`

Run:

```bat
python scripts/recovery_coverage.py
python scripts/recovery_coverage.py --dump-excluded-external-csv decomp/recovery/reports/boost_function_inventory_2026-03-26.csv
python scripts/detect_boost_patch_version.py --mode binary --binary-file bin/external/ForgedAlliance.exe
```

Pending-reconstruction guard (prevents "forgotten partial lifts"):

```bat
python scripts/recovery_pending_audit.py --namespace fa_full_2026_03_26 --include-untracked
python scripts/recovery_pending_audit.py --namespace fa_full_2026_03_26 --include-untracked --queue-out decomp/recovery/queues/pending_reconstruction_mismatches.txt
python skills/fa-recovery-iteration/scripts/recovered_progress.py bulk-mark --namespace fa_full_2026_03_26 --functions-file decomp/recovery/queues/pending_reconstruction_mismatches.txt --status needs_evidence --note "Source contains pending reconstruction marker; keep tracked as unfinished."
```

Progress snapshot:

- Total FAF functions (IDA index): `67,171`
- Recovered so far (`completed`): `31,096`
- Pending: `32,243`
- Blocked: `3,776`
- In progress: `115`
- **Coverage (of recovered functions): `46.30%`**

Namespace families:

- `moho`: `5,105/8,717 (58.56%)`
- `gpg`: `1,392/2,172 (64.09%)`
- `external`: `378/2,328 (16.24%)`

External dependency split:

- `wxWidgets`: `124/1,359 (9.12%)`
- `MSVC STL/CRT`: `49/398 (12.31%)`
- `WildMagic`: `52/387 (13.44%)`
- `LuaPlus/Lua`: `153/184 (83.15%)`

External dependency status (progress):

- `wxWidgets`: `1,260/1,359 (92.72%)`
- `MSVC STL/CRT`: `0/398 (0.00%)`
- `WildMagic`: `0/387 (0.00%)`
- `LuaPlus/Lua`: `0/184 (0.00%)`

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

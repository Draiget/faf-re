# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries. Inspired by [Forged Alliance Forever](https://faforever.com) team-work.

## Recovery Coverage (`25/07/2026`, `fa_full_2026_03_26`)

Progress snapshot:

- Total FAF functions: `67,167`
  - *IDA index, exported*
- Progress coverage:  **`97.26%`**
  - *Consists of `recovered` + `skip` + `external_dependency` ÷ exported*
  - *Total amount of completed tokens: `65,327`*

Progress DB status breakdown:

- `recovered`: `53,474` (81.86%)
- `skip`: `6,170` (9.44%) — CRT-internal / compiler-generated / orphan template instantiations / static-init glue
- `external_dependency`: `5,683` (8.70%) — third-party libs
  - *libpng, zlib, wxWidgets, LuaPlus/Lua, boost, MSVC STL, WildMagic/Wm3, CRI Sofdec/ADX, undname, bugsplat, CRT helpers*
- `needs_evidence`: `3` (0.00%)
- `in_progress`: `29` (0.04%)
- **`blocked`: `1,874` (2.79%)**
  - *strict circular/dep-blocked (in-DB literal `status == "blocked"`)*  
  - *combined with `needs_evidence`, the "not-yet-recovered non-engine-external" bucket is `1,877`*
  - *the `stats` tool's `blocked_count` aggregates the same two buckets and reports `1,877`*
    — functions previously attempted that depend on an unrecovered subsystem, a not-yet-typed owner class, or a non-trivial call-tree not yet walked bottom-up.

## Caller-Wiring Health

Verdicts computed by [`fa-find-callers`](skills/fa-find-callers/SKILL.md) across the namespace's SQLite callgraph index. A function's verdict reflects whether its binary callsite evidence is satisfied by recovered source — i.e. whether some recovered file in `src/sdk/**` actually invokes it (directly, via vtable slot, or via a framework dispatch table).

### Recovered (53,474 functions) — wiring health

| Bucket | Count | % of recovered |
|---|---:|---:|
| **Confirmed caller** (recovered binary caller wired by name) | `15,651` | 29.27% |
| Vtable-anchored (virtual override of a recovered class) | `5,843` | 10.93% |
| Framework dispatch (wx event, EH handler, Lua binding, reflection table, …) | `5,499` | 10.28% |
| Caller still blocked (orphan-helper risk — caller awaits recovery) | `2,549` | 4.77% |
| No callsite evidence (no recorded code/data caller in the index) | `23,713` | 44.34% |
| Unclassified data xref (manual review) | `215` | 0.40% |
| RTTI-only | `4` | 0.01% |

### Not-yet-recovered (1,877 blocked + needs_evidence) — backlog readiness

| Bucket | Count | % of backlog |
|---|---:|---:|
| **Recoverable now** (`OK_RECOVERED_CALLER` — recovered caller exists; recover next) | `283` | 15.08% |
| Vtable-anchored (recover with the owning class) | `178` | 9.48% |
| Framework dispatch (wx/EH/Lua/reflection) | `34` | 1.81% |
| **Caller functions unrecovered** (`NEEDS_RECOVERED_CALLER` — recover the parent first) | `946` | 50.40% |
| No callsite evidence (likely external/dead — candidates for `external_dependency`) | `434` | 23.12% |
| Unclassified data xref (manual review) | `1` | 0.05% |
| RTTI-only | `1` | 0.05% |

*Set `FAF_README_SKIP_VERDICTS=1` to skip this block during tight worker loops.*

## Build Quickstart + Patches

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
msbuild src\sdk\main.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32
```

Recommended hang-safe build wrapper:

```bat
powershell -ExecutionPolicy Bypass -File scripts\build_sdk_with_timeout.ps1 -TimeoutMinutes 120 -NoOutputTimeoutMinutes 10
```

Patch/build details:

- [boost_1_34_1_faf_required.md](dependencies/patches/boost_1_34_1_faf_required.md)
- [luaplus_build1081_faf_required.md](dependencies/patches/luaplus_build1081_faf_required.md)
- [wildmagic3p8_faf_required.md](dependencies/patches/wildmagic3p8_faf_required.md)
- [wxwindows_2_4_2_faf_required.md](dependencies/patches/wxwindows_2_4_2_faf_required.md)

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
- `main`: reconstructed SDK/game code (primary recovered project).

## Notes

- `USE_X87_COMPATIBILITY`: keeps x87-compatible floating-point behavior where needed.

## Credits

Big thanks to all active maintainers and contributors of the FAF project. This work builds on many years of engine inspection and disassembly effort by the FAF community, with special recognition to:

- [Hdt80bro](https://github.com/Hdt80bro)
- [4z0t](https://github.com/4z0t)

### Deprecations & Fixes

- `GetVersionExW` - deprecated, ignored via disable warning 4996.

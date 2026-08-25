# FAF-RE

Reconstruction/disassembly project for the old **Supreme Commander: Forged Alliance** engine and game binaries. Inspired by [Forged Alliance Forever](https://faforever.com) team-work.

## Recovery Coverage (`25/08/2026`, `fa_full_2026_03_26`)

Progress snapshot:

- Total FAF functions: `67,167`
  - *IDA index, exported*
- Progress coverage:  **`98.45%`**
  - *Consists of `recovered` + `skip` + `external_dependency` ÷ exported*
  - *Total amount of completed tokens: `66,129`*

Progress DB status breakdown:

- `recovered`: `53,095` (80.29%)
- `skip`: `7,381` (11.16%) — proven ICF aliases / thunks / EH or static-init glue with no distinct source body
- `external_dependency`: `5,653` (8.55%) — proven third-party/import-boundary code
  - *libpng, zlib, wxWidgets, LuaPlus/Lua, external Boost internals, WildMagic/Wm3, CRI Sofdec/ADX, undname, bugsplat, CRT imports*
- `needs_evidence`: `33` (0.05%)
- `in_progress`: `9` (0.01%)
- **`blocked`: `1,069` (1.59%)**
  - *strict circular/dep-blocked (in-DB literal `status == "blocked"`)*  
  - *combined with `needs_evidence`, the "not-yet-recovered non-engine-external" bucket is `1,102`*
  - *the `stats` tool's `blocked_count` aggregates the same two buckets and reports `1,102`*
    — functions previously attempted that depend on an unrecovered subsystem, a not-yet-typed owner class, or a non-trivial call-tree not yet walked bottom-up.

## Binary Callsite Readiness

Verdicts computed by [`fa-find-callers`](skills/fa-find-callers/SKILL.md) across the namespace's SQLite callgraph index and progress statuses. These counts show whether binary callers/dispatch evidence exists and whether caller tokens are marked recovered. They do **not** parse caller bodies or prove that a matching named call, registration, or virtual source edge exists. Verify real source wiring with `scripts/recovery_callgraph_match_audit.py` plus manual caller-body inspection.

### Recovered (53,095 functions) — binary caller context

| Bucket | Count | % of recovered |
|---|---:|---:|
| **Recovered caller token exists** (source edge still requires verification) | `16,778` | 31.60% |
| Vtable-anchored (virtual override of a recovered class) | `5,885` | 11.08% |
| Framework dispatch (wx event, EH handler, Lua binding, reflection table, …) | `5,565` | 10.48% |
| No recovered caller token yet (orphan risk) | `1,772` | 3.34% |
| No callsite evidence (no recorded code/data caller in the index) | `22,875` | 43.08% |
| Unclassified data xref (manual review) | `216` | 0.41% |
| RTTI-only | `4` | 0.01% |

### Not-yet-recovered (1,102 blocked + needs_evidence) — backlog readiness

| Bucket | Count | % of backlog |
|---|---:|---:|
| **Candidate** (`OK_RECOVERED_CALLER` — caller token recovered; inspect its body) | `50` | 4.54% |
| Vtable-anchored (recover with the owning class) | `124` | 11.25% |
| Framework dispatch (wx/EH/Lua/reflection) | `8` | 0.73% |
| **Caller functions unrecovered** (`NEEDS_RECOVERED_CALLER` — recover the parent first) | `553` | 50.18% |
| No indexed callsite evidence (needs investigation/evidence) | `366` | 33.21% |
| Unclassified data xref (manual review) | `1` | 0.09% |
| RTTI-only | `0` | 0.00% |

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

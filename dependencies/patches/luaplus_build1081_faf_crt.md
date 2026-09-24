# FAF LuaPlus Build 1081 — modern-CRT fixes

Baseline: **vendored** `LuaPlus_Build1081.7z`, SHA256
`1f1bc467e7c430a52610ed8331f2d966728c9658ad909e971c4eaf9f61e08890`.
Pinned in [`docker/deps.lock.json`](../../docker/deps.lock.json).

Role: **baked-in** — the archive is a post-patch snapshot, so these fixes are
already in it. The patch is the record of what FAF changed relative to the
LuaPlus 1081 release, verified by reverse-check on every build.

Companion to
[`luaplus_build1081_faf_required.md`](luaplus_build1081_faf_required.md),
which covers the eighteen Lua VM layout files.

## Why it is needed

LuaPlus Build 1081 predates the C99 `swprintf(buffer, count, format, …)`
signature. Modern MSVC rejects the legacy three-argument call sites with
**C2440** in both files. Every call becomes `_snwprintf` with an explicit
buffer length and a `(wchar_t*)` cast.

## Scope — two files, eight call sites

| File | Sites | What they format |
|---|---|---|
| `Src/LuaPlus/LuaPlusAddons.c` | 1 | `lua_number2wstr`, buffer length 32 |
| `Src/LuaPlus/lwstrlib.c` | 3 | quoted-escape buffers: `\%03d` (5), `\x%04x` and `\x%02x` (10) |
| `Src/LuaPlus/lwstrlib.c` | 4 | `%`-format helper writes, `MAX_ITEM` |

## Recovered 2026-09-23 — this patch had never been applicable

These fixes were originally part of `luaplus_build1081_faf_required.patch`
(commit `050ff711`), which was **malformed**: its first hunk declared
`@@ -20,7 +20,7 @@` but carried only six lines of body, so `git apply`
rejected the entire file with `corrupt patch at line 12` in both directions.
The fixes survived only because the `.7z` snapshot happened to contain them.

When that patch was regenerated against the vendored archive, these two files
dropped out of the record entirely — the archive already contains them, so they
no longer appear in a diff against it.

Recovering the original from git history showed its **scope was never wrong**:
it documented all eight call sites. The only defect was the single dropped
context line. Repairing that line and rebasing the paths from repo-root-relative
(`a/dependencies/LuaPlus_Build1081/Src/…`) to dependency-root-relative
(`a/Src/…`, matching every other patch here) produced this file.

So this is the original artifact repaired, not a reconstruction. It
reverse-checks cleanly against a fresh extraction of the archive, which
confirms all eight sites are present and unmodified since.

## Checking it

```powershell
.\docker\scripts\Apply-Patches.ps1 -CheckOnly -Only LuaPlus_Build1081
```

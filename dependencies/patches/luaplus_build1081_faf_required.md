# LuaPlus Build 1081 required patch notes

## Scope
- Dependency: `dependencies/LuaPlus_Build1081`
- Target built: static library (`LuaPlusLib_1081` / `LuaPlusLibD_1081`)
- Toolchain: VS2022 (`v143`) with Win32/x64 (`x64_x86` dev shell)

## Why this patch is needed
LuaPlus Build 1081 was authored for older MSVC CRT behavior. Modern MSVC uses
the C99-compatible `swprintf` signature (`buffer, count, format, ...`) and
rejects legacy call sites that pass `format` as the second argument.

Without this patch, these compile errors occur:
- `C2440` in `LuaPlusAddons.c` (`lua_number2wstr`)
- `C2440` in `lwstrlib.c` (wide-string format helper paths)

## Source changes
- `Src/LuaPlus/LuaPlusAddons.c`
  - `lua_number2wstr` now uses `_snwprintf` with explicit buffer length (`32`).
- `Src/LuaPlus/lwstrlib.c`
  - Replaced legacy `swprintf` usages with `_snwprintf` and explicit lengths for:
    - quoted binary escape formatting buffers
    - `%`-format helper buffer writes (`MAX_ITEM`)

See `dependencies/patches/luaplus_build1081_faf_required.patch` for exact hunks.

## Standalone build project used
- `dependencies/LuaPlus_Build1081/LuaPlusLib_1081.vcxproj`
- Compatibility settings used to match legacy behavior:
  - `LUAPLUS_HAS_WCHAR_T`
  - `UndefinePreprocessorDefinitions=UNICODE;_UNICODE`
  - Win32/x64, MBCS
- Consumer integration note:
  - `src/sdk` and `src/inspect` define `LUAPLUS_LIB` so LuaPlus headers do not
    auto-link `LuaPlusD_1081.lib`/`LuaPlus_1081.lib`; project linkage is explicit
    to `LuaPlusLibD_1081.lib`/`LuaPlusLib_1081.lib`.

## Build commands
Run from a VS developer shell initialized with:

```bat
%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
```

Then build:

```bat
msbuild dependencies\LuaPlus_Build1081\LuaPlusLib_1081.vcxproj /t:Build /p:Configuration=Debug /p:Platform=Win32 /m
msbuild dependencies\LuaPlus_Build1081\LuaPlusLib_1081.vcxproj /t:Build /p:Configuration=Release /p:Platform=Win32 /m
msbuild dependencies\LuaPlus_Build1081\LuaPlusLib_1081.vcxproj /t:Build /p:Configuration=Debug /p:Platform=x64 /m
msbuild dependencies\LuaPlus_Build1081\LuaPlusLib_1081.vcxproj /t:Build /p:Configuration=Release /p:Platform=x64 /m
```

## Outputs
- `output/LuaPlus_Build1081/Win32/Debug/LuaPlusLibD_1081.lib`
- `output/LuaPlus_Build1081/Win32/Release/LuaPlusLib_1081.lib`
- `output/LuaPlus_Build1081/x64/Debug/LuaPlusLibD_1081.lib`
- `output/LuaPlus_Build1081/x64/Release/LuaPlusLib_1081.lib`

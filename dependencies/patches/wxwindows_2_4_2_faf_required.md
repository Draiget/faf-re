# FAF wxWindows 2.4.2 Patch + Bootstrap

This repo uses an external `wxWindows-2.4.2` tree and links against the static MSW build.

The patch file `wxwindows_2_4_2_faf_required.patch` captures local fixes needed for modern VS2022 toolchains and modern Windows SDK headers.

## Current patch scope

Patched files in `wxwindows_2_4_2_faf_required.patch`:

- `src/common/datetime.cpp`
- `src/common/intl.cpp`
- `src/makevc.env`
- `src/msw/makefile.vc`
- `src/zlib/makefile.vc`

## One-shot bootstrap

Run from a Visual Studio developer shell:

```bat
%comspec% /k "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_wxwindows_2_4_2_required.ps1 -WxRoot "<your external wxWindows-2.4.2 path>"
```

Patch-only (no build):

```bat
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_wxwindows_2_4_2_required.ps1 -WxRoot "<your external wxWindows-2.4.2 path>" -PatchOnly
```

Or set an env var once:

```bat
set WX_ROOT=<your external wxWindows-2.4.2 path>
powershell -ExecutionPolicy Bypass -File scripts\bootstrap_wxwindows_2_4_2_required.ps1
```

## Manual steps

1. Apply patch:

```bat
git -C "<your external wxWindows-2.4.2 path>" apply "<path to this repo>\\dependencies\\patches\\wxwindows_2_4_2_faf_required.patch"
```

2. Build static wx libs:

```bat
cd /d "<your external wxWindows-2.4.2 path>"
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsamd64_x86.bat"
set "WXWIN=<your external wxWindows-2.4.2 path>"
cd /d src\msw
nmake /f makefile.vc FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD
```

3. Verify output libs exist:

- `<your external wxWindows-2.4.2 path>\lib\png.lib`
- `<your external wxWindows-2.4.2 path>\lib\zlib.lib`
- `<your external wxWindows-2.4.2 path>\lib\jpeg.lib`
- `<your external wxWindows-2.4.2 path>\lib\tiff.lib`
- `<your external wxWindows-2.4.2 path>\lib\regex.lib`
- `<your external wxWindows-2.4.2 path>\lib\wxmsw.lib`

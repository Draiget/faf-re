# FAF wxWindows 2.4.2 x64 Patch

Applies on top of `wxwindows_2_4_2_faf_required.patch`. wx 2.4.2 predates Win64
support (it has no `_WIN64` handling at all); these are the changes that let the
static Unicode library build and run as x64 for `main.vcxproj`'s x64
configurations. Every change is a no-op for Win32: the `...Ptr` window-long
functions and `GWLP_*` indices are macros for the 32-bit ones there, `UINT_PTR`
and `DWORD_PTR` are `UINT`/`DWORD`, and the two header changes are guarded by
`_WIN64`.

Stored with CRLF terminators, like the required patch. Apply with
`patch --binary -p1` from the wx root.

## Changes

- `include/wx/platform.h`: do not define `wxSIZE_T_IS_UINT` on Win64, so
  `wxString` keeps its `operator[](unsigned int)` overloads and `str[0u]` stays
  unambiguous.
- `include/wx/thread.h`: `wxCritSectBuffer` is 40 bytes on Win64
  (`sizeof(CRITICAL_SECTION)`); the union's pointer member aligns it.
- `src/makevc.env`: `CPU` follows the developer shell (`VSCMD_ARG_TGT_ARCH`),
  so the recursive png/jpeg/tiff/regex/zlib builds archive for x64 too.
- `src/msw/{combobox,dialup,fdrepdlg,radiobox,spinctrl,tooltip,window}.cpp`:
  every `Set/GetWindowLong` call on `GWL_WNDPROC` / `GWL_USERDATA` (which Win64
  headers do not define) is the `...Ptr` form on `GWLP_*`, and its `(LONG)`
  casts are `(LONG_PTR)`, so window procedures and `this` pointers are not cut
  to 32 bits.
- `src/msw/{colordlg,fdrepdlg}.cpp`: the common-dialog hook procedures return
  `UINT_PTR`, as `LPCCHOOKPROC` / `LPFRHOOKPROC` require.
- `src/msw/thread.cpp`: `GetProcessAffinityMask` takes `DWORD_PTR` masks.
- `src/msw/window.cpp`: owner-drawn menu measuring goes through `size_t`
  temporaries (`MEASUREITEMSTRUCT` holds `UINT`s).

wx 2.4.2 still keeps `HWND`s and tree/list item pointers in `unsigned long`
(`WXHWND`, `wxTreeItemId::m_pItem`, ...). User and GDI handles are 32-bit on
Win64, and `main.vcxproj` links its x64 image `/LARGEADDRESSAWARE:NO`, which
keeps every heap address below 2 GB, so those round-trip exactly.

## Build

From the wx root, in a copy of the tree (the build writes `lib\*.lib` and would
overwrite the Win32 libraries):

```bat
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
set "WXWIN=<copy root>"
cd /d "%WXWIN%\src\msw"
nmake /f makefile.vc FINAL=1 DLL=0 WXMAKINGDLL= CRTFLAG=/MD UNICODE=1 "OVERRIDEFLAGS=/DUNICODE /D_UNICODE /EHsc"
```

Check `lib\mswu\wx\setup.h` still says `wxUSE_UNICODE 1` afterwards, then copy
`wxmswu.lib png.lib jpeg.lib tiff.lib regex.lib zlib.lib` from the copy's `lib\`
into `dependencies\wxWindows-2.4.2\lib\x64\`, where the x64 link looks for them.

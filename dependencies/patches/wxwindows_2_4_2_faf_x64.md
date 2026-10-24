# FAF wxWindows 2.4.2 x64 Patch

Applies on top of `wxwindows_2_4_2_faf_required.patch`. wx 2.4.2 predates Win64 support (it has no `_WIN64` handling at all); these are the changes that let the static Unicode library build and run as x64. Every change is a no-op for Win32: the `...Ptr` window-long functions and `GWLP_*` indices are macros for the 32-bit ones there, `UINT_PTR` and `DWORD_PTR` are `UINT`/`DWORD`, and the two header changes are guarded by `_WIN64`.

Stored with CRLF terminators, like the required patch, and applied after it (see the apply rule in `wxwindows_2_4_2_faf_required.md`).

## Changes

- `include/wx/platform.h`: do not define `wxSIZE_T_IS_UINT` on Win64, so `wxString` keeps its `operator[](unsigned int)` overloads and `str[0u]` stays unambiguous.
- `include/wx/thread.h`: `wxCritSectBuffer` is 40 bytes on Win64 (`sizeof(CRITICAL_SECTION)`); the union's pointer member aligns it.
- `src/makevc.env`: `CPU` follows the developer shell (`VSCMD_ARG_TGT_ARCH`), so the recursive png/jpeg/tiff/regex/zlib builds archive for x64 too.
- `src/msw/{combobox,dialup,fdrepdlg,radiobox,spinctrl,tooltip,window}.cpp`: every `Set/GetWindowLong` call on `GWL_WNDPROC` / `GWL_USERDATA` (which Win64 headers do not define) is the `...Ptr` form on `GWLP_*`, and its `(LONG)` casts are `(LONG_PTR)`, so window procedures and `this` pointers are not cut to 32 bits.
- `src/msw/{colordlg,fdrepdlg}.cpp`: the common-dialog hook procedures return `UINT_PTR`, as `LPCCHOOKPROC` / `LPFRHOOKPROC` require.
- `src/msw/thread.cpp`: `GetProcessAffinityMask` takes `DWORD_PTR` masks.
- `src/msw/window.cpp`: owner-drawn menu measuring goes through `size_t` temporaries (`MEASUREITEMSTRUCT` holds `UINT`s).

## Pointer-width follow-up: `wxwindows_2_4_2_faf_x64_pointers.patch`

Applies on top of this patch. Without it, wx 2.4.2 still passes `WPARAM`/`LPARAM` and keeps tree/list item pointers in 32-bit `unsigned long`/`long`, which only works while every address is below 2 GB (`/LARGEADDRESSAWARE:NO`). With a large-address-aware image the first `WM_GETTEXT` through `wxWindow::MSWDefWindowProc` wrote through a truncated buffer address, and D3D9 `CreateDevice` failed with `D3DERR_INVALIDCALL`. Every change is guarded by `_WIN64` or is the same value on Win32:

- `include/wx/defs.h`: `WXWPARAM`/`WXLPARAM` are `unsigned __int64`/`__int64`; `WXHTREEITEM` and `WXHIMAGELIST` (pointers in Win32) are 64-bit.
- `include/wx/treebase.h`, `include/wx/treelistctrl.h`: `wxTreeItemIdValue` (`wxTreeItemId::m_pItem`) is `__int64`, with a matching constructor; `wxArrayTreeItemIds` stores it in a new `wxBaseArrayInt64` (`include/wx/dynarray.h`, `src/common/dynarray.cpp`).
- `include/wx/listbase.h`: `wxListItem` item data is `__int64`.
- `include/wx/msw/treectrl.h`, `src/msw/treectrl.cpp`, `src/generic/dirctrlg.cpp`: the child-enumeration cookie is a `wxTreeItemIdValue`; `DeleteChildren` keeps `HTREEITEM`s in a `wxArrayTreeItemIds`.
- `src/generic/treelistctrl.cpp`, `src/generic/treectlg.cpp`: item pointers reach `wxTreeItemId` through its `void *` constructor instead of `(long)`.
- `src/msw/{choice,listbox,mdi,tabctrl,tbar95}.cpp`: string, buffer and data pointers go out as `LPARAM`/`INT_PTR`; `listbox.cpp` reads item data back as `LRESULT`; `fontenum.cpp`'s callback takes an `LPARAM`; `window.cpp` keeps the window procedure's result as `WXLPARAM`; `mdi.cpp`'s `wxMDIChildFrame::MSWDefWindowProc` takes a `WXWPARAM`.
- `src/common/dynarray.cpp`: sorted arrays pass items to the compare callback through `size_t`, not `long`; `src/common/list.cpp` tests a string pointer for null directly; `include/wx/hashmap.h` hashes a pointer through `size_t`.

Left as they are: `HWND`/`HDC`/`HFONT`/... in `unsigned long` (user and GDI handles are 32-bit significant on Win64), `src/msw/treectrl.cpp`'s attribute hash key, and pointer casts in code the engine does not reach (`src/common/cmndata.cpp`, `src/common/cshelp.cpp`, `src/generic/treelay.cpp`, `src/msw/{helpchm,helpwin,dcprint,thread,utils,tooltip}.cpp`, `src/common/variant.cpp`'s pointer print).

The engine and the library must be compiled against the same patched headers, because `WXLPARAM`, `wxTreeItemId` and `wxListItem` change size; the CMake build compiles both from `dependencies/wxWindows-2.4.2`.

## Building it

The CMake build applies both x64 patches with the required one and compiles the same patched tree for either architecture; nothing else is needed.

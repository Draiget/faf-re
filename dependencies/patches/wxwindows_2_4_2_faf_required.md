# FAF wxWindows 2.4.2 Patch + Bootstrap

> **Baseline note (2026-09-23).** The container build takes wxWindows from the
> vendored archive `wxWindows-2.4.2.7z` (SHA256 `c76a4502…`), which is a
> *post-patch* snapshot — every change below is already present in it, so
> nothing is applied at build time. `docker/scripts/Apply-Patches.ps1` verifies
> it by content instead (430 added lines, all confirmed present).
>
> Do not try to `git apply` this patch outside a git work tree: it is stored
> with CRLF terminators, so git strips the CR as a line terminator and then
> fails to match the CRLF source files. Inside this repository
> `core.autocrlf=true` hides that.
>
> The archive ships an **ANSI** `wxmsw.lib`; `main.vcxproj` links `wxmswu.lib`,
> so the Unicode `nmake` build and the `setup.h` stamp that follows it are
> mandatory — `docker/scripts/Build-Deps.ps1` does both.


This repo uses an external `wxWindows-2.4.2` tree and links against the static MSW build.

The patch file `wxwindows_2_4_2_faf_required.patch` captures local fixes needed for modern VS2022 toolchains and modern Windows SDK headers.

## Current patch scope

Patched files in `wxwindows_2_4_2_faf_required.patch`:

- `include/wx/treelistctrl.h` (new, see below)
- `src/common/datetime.cpp`
- `src/common/intl.cpp`
- `src/generic/treelistctrl.cpp` (new, see below)
- `src/makevc.env`
- `src/msw/makefile.vc` (also adds `treelistctrl.obj` to `GENERICOBJS`)
- `src/zlib/makefile.vc`

## wxTreeListCtrl (added 2026-09-24)

Forged Alliance built the wxCode tree-list control into its wx library: its code
sits in the wx block at 0x009816E0-0x0098B1F0, and the engine derives from it
(the Lua debugger's watch panes) or embeds it (the reflection property editor).
wx 2.4.2 does not ship it, so the patch adds it to the library build.

The source is wxCode SVN r2003 (2004-10-03,
`svn.code.sf.net/p/wxcode/code`, `trunk/wxCode/components/treelistctrl`). It is
the only revision with both `wxTreeListCtrl::m_headerHeight` (FA's control is
0x140 bytes) and the column hit-test loops that never advance `x`, as FA's code
has. Its header window (0x154) and column info (0x20) match FA's too.

FA changed that revision; the parts the engine reaches are carried here and
marked `FAF`:

- `wxTreeListColumnInfo` has a second flag after `m_shown` (+0x09), set by a
  six-argument constructor (0x004A3A30).
- `wxTreeListCtrl::AddColumn(text, width, bool, alignment)`, the overload the
  engine calls (0x004A3BE0).
- `wxTreeListItem::HitTest` has an `ONITEMLABEL` branch that searches the
  columns with both flags set (0x009842B0).
- Any column can be edited in place: `wxTreeListCtrl::EditLabel(item, column)`
  (0x00987BD0) over the main window's `EditLabel` (0x00986EC0), which keeps the
  column in `m_editCol` (the dword FA added before the button metrics, +0x1C8)
  for `OnRenameAccept` (0x009893B0) to write the result back to. The rename
  timer carries the click point (0x00981270, `Notify` 0x00988360), so a slow
  click edits the column clicked (0x009872D0). The reflection property editor
  edits its Value column this way.
- `wxTreeListCtrl` has no `DoGetBestSize` override. r2003 declares one but
  never defines it (the body arrives in r2017), so any build of it fails to
  link; FA's control keeps `wxControl::DoGetBestSize` (vtable slot 103,
  0x0098D5D0), and the declaration is dropped.

We call the flag `m_labelHitTest`; FA's name is unknown, as are the names of
the edit additions. The rest of FA's changes are not recovered: a cursor at
+0x230, a selection flag at +0x244 and two strings at +0x248/+0x250 of its
0x258-byte `wxTreeListMainWindow`, and a column field it added to
`wxTreeEvent` (+0x8C, set by the edit events). Nothing in the engine reaches
them, so `wxTreeEvent` keeps wx 2.4.2's layout.

`wxWindows-2.4.2.7z` predates this addition, so the archive does not contain
the two new files or the makefile line until it is regenerated.

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

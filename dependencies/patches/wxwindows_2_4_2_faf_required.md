# FAF wxWindows 2.4.2 patch

> **Baseline (2026-10-24).** The official `wxMSW-2.4.2.zip` from the wxWidgets GitHub release `v2.4.2` (SHA256 `081cb30347ed9092a50c39311b46586f4264fb125942652db168851be96ebf33`), with these patches applied in order: `wxwindows_2_4_2_faf_required.patch`, `wxwindows_2_4_2_faf_x64.patch`, `wxwindows_2_4_2_faf_x64_pointers.patch`. The result is byte-identical to `dependencies/wxWindows-2.4.2` (4,912 files); everything else in that folder is build output plus the four files the wx makefile generates (`lib/msw*/wx/setup.h`, `src/common/lex_yy.c`, `src/common/y_tab.c`).
>
> Regenerated 2026-10-24: `_required` now also carries the `treelistctrl.obj` position in `src/msw/makefile.vc` and creates `treelistctrl.h/.cpp` with LF endings, as they are in the tree; `_x64_pointers` was re-cut against those LF files. The `v2.4.2` git tag is a different file set (other line endings, all ports) and is not a usable baseline.
>
> Apply from inside the dependency tree with `GIT_CEILING_DIRECTORIES` set to its parent and `git -c core.autocrlf=false apply --unsafe-paths --whitespace=nowarn <patch>`. The `-c core.autocrlf=false` matters: Git for Windows sets `core.autocrlf=true` system-wide, which rewrites the line endings of the files a patch creates, and later patches written against the real endings then fail.
>
> The release's `setup.h` is the ANSI one; the engine needs the Unicode build (`mswu`), whose `setup.h` configure writes.

The engine links wx statically (MSW port, Unicode).

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

Forged Alliance built the wxCode tree-list control into its wx library: its code sits in the wx block at 0x009816E0-0x0098B1F0, and the engine derives from it (the Lua debugger's watch panes) or embeds it (the reflection property editor). wx 2.4.2 does not ship it, so the patch adds it to the library build.

The source is wxCode SVN r2003 (2004-10-03, `svn.code.sf.net/p/wxcode/code`, `trunk/wxCode/components/treelistctrl`). It is the only revision with both `wxTreeListCtrl::m_headerHeight` (FA's control is 0x140 bytes) and the column hit-test loops that never advance `x`, as FA's code has. Its header window (0x154) and column info (0x20) match FA's too.

FA changed that revision; the parts the engine reaches are carried here and marked `FAF`:

- `wxTreeListColumnInfo` has a second flag after `m_shown` (+0x09), set by a six-argument constructor (0x004A3A30).
- `wxTreeListCtrl::AddColumn(text, width, bool, alignment)`, the overload the engine calls (0x004A3BE0).
- `wxTreeListItem::HitTest` has an `ONITEMLABEL` branch that searches the columns with both flags set (0x009842B0).
- Any column can be edited in place: `wxTreeListCtrl::EditLabel(item, column)` (0x00987BD0) over the main window's `EditLabel` (0x00986EC0), which keeps the column in `m_editCol` (the dword FA added before the button metrics, +0x1C8) for `OnRenameAccept` (0x009893B0) to write the result back to. The rename timer carries the click point (0x00981270, `Notify` 0x00988360), so a slow click edits the column clicked (0x009872D0). The reflection property editor edits its Value column this way.
- `wxTreeListCtrl` has no `DoGetBestSize` override. r2003 declares one but never defines it (the body arrives in r2017), so any build of it fails to link; FA's control keeps `wxControl::DoGetBestSize` (vtable slot 103, 0x0098D5D0), and the declaration is dropped.

We call the flag `m_labelHitTest`; FA's name is unknown, as are the names of the edit additions. The rest of FA's changes are not recovered: a cursor at +0x230, a selection flag at +0x244 and two strings at +0x248/+0x250 of its 0x258-byte `wxTreeListMainWindow`, and a column field it added to `wxTreeEvent` (+0x8C, set by the edit events). Nothing in the engine reaches them, so `wxTreeEvent` keeps wx 2.4.2's layout.

## Building it

The CMake build (clang-cl) compiles wx from the patched tree itself (`cmake/deps/wxwindows`): there is no `nmake` step and no prebuilt library. Configure also writes the files the wx makefile would generate (`lib/msw*/wx/setup.h` with `wxUSE_UNICODE 1` for `mswu`, `src/common/y_tab.c`, `src/common/lex_yy.c`).

wx's `WinMain` is left out (`NOMAIN`, wx's own switch in `src\makevc.env`): the engine has its own `WinMain` (0x008D44A0) and calls `wxEntry` itself, while `main.obj` is always linked for `wxhInstance`, so a wx `WinMain` would be a duplicate symbol.

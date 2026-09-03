

## Quantified 2026-09-02

The live cluster is in `src/sdk/moho/misc/ScrDebugWindow.cpp` (unlocked): a
block of ~15 wx bridge helpers **forward-declared in its anonymous namespace,
called, and never defined anywhere** - `ConstructWxMenu`,
`ConstructWxMenuItem`, `AppendWxMenuItem`, `AppendWxMenuBarMenu`,
`ConstructWxMenuBar`, `SetFrameMenuBar`, `CreateFrameToolBar`,
`AddToolBarTool`, `AddToolBarSeparator`, `RealizeToolBar`,
`ConstructWxNotebook`, `AddNotebookPage`, `ConstructWxListCtrl`,
`ConstructWxSplitterWindow`, `SplitWxSplitterWindowVertically`,
`ConstructWxGenericDirCtrl`, `ConstructWxBitmapFromFile`, `DestroyWxBitmap`,
`ConnectDynamicTreeItemActivatedHandler`.

They account for most of the tree's remaining LNK2019s. Implementing them is
real wx-integration work (constructing wxMenuItem/wxToolBar/wxNotebook and
wiring dynamic event handlers), not a decompilation task, and it only affects
the script debug window - so it is **off the commander/rendering goal path**.
Take it as a dedicated wx pass.

Note `ConnectDynamicTreeItemActivatedHandler` appears twice in the link log
under two different anonymous-namespace hashes (`?A0x5900937f` and
`?A0xf18afdc5`) with `void*` and `void* const` parameter spellings - two
separate TUs each carrying their own undefined copy. See
[[feedback_msvc_param_const_breaks_cross_tu_linkage]] for why the two
spellings are different symbols.

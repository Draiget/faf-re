# Forced-unresolved symbol allowlist

Symbols this recovery does not define yet. `main.vcxproj` links with `/FORCE`,
so each is a warning rather than an error - but the linker still needs an
address for the call site and uses RVA 0, which the loader relocates to the
module base. Calling one jumps to `imagebase + 0`.

`scripts/linkcheck.py` reads this list and fails a build that produces any
unresolved symbol not in it. Remove an entry when it is recovered; never add
one to silence a build.

## Sofdec frame converters

`CFT_Ycc420plnToArgb8888Prg` / `_Int` are the CRI Sofdec ARGB converters,
address-taken at `SofdecSfxRuntime.cpp:2394` and selected during movie playback
when the stream's chroma flags call for them. Their bodies are at `0x00AEEB40`
and `0x00AEE960`, with the `cft_c_` / `cft_sse_` leaf tier underneath.
`mwsffrm_CallbackAnalyzeSofdecHeader` is address-taken into the Sofdec platform
callback table at `SofdecAdxPlatformRuntime.cpp:2506`.

## wx widget bridges

The `anonymous namespace` entries are the declared-but-undefined widget bridges
in `ScrDebugWindow.cpp` and `ScrWatchCtrl.cpp`, reached only through
`SCR_CreateDebugWindow` - the `/debug` command-line flag, or the
`SC_LuaDebugger` console command. Each declaration cites the wx library call
target it stands for.

They cannot be defined where they are declared: the real wx headers redeclare
`wxPoint` / `wxSize` / `wxEventTable` at global scope and collide with this
project's reconstructions of those names. They need their own translation unit,
and being in an anonymous namespace they would first have to move to a named
one - which in turn needs the wx hybrid-link question settled, since these
objects are our reconstructions rather than real wx instances.

## The list

```
_CFT_Ycc420plnToArgb8888Int
_CFT_Ycc420plnToArgb8888Prg
_mwsffrm_CallbackAnalyzeSofdecHeader
bool __cdecl `anonymous namespace'::SplitWxSplitterWindowVertically(void *,void *,void *,int)
void * __cdecl `anonymous namespace'::ConstructWxBitmapFromFile(void *,struct wxStringRuntime const *,int)
void * __cdecl `anonymous namespace'::ConstructWxGenericDirCtrl(void *,void *,struct wxStringRuntime const *,struct wxStringRuntime const *,struct wxStringRuntime const *)
void * __cdecl `anonymous namespace'::ConstructWxListCtrl(void *,void *,int,struct wxPoint const *,struct wxSize const *,int,void const *,struct wxStringRuntime const *)
void * __cdecl `anonymous namespace'::ConstructWxMenu(void *)
void * __cdecl `anonymous namespace'::ConstructWxMenuItem(void *,void *,int,struct wxStringRuntime const *,struct wxStringRuntime const *,bool,void *)
void * __cdecl `anonymous namespace'::ConstructWxNotebook(void *,void *,int,struct wxPoint const *,struct wxSize const *,int,struct wxStringRuntime const *)
void * __cdecl `anonymous namespace'::ConstructWxSplitterWindow(void *,void *,int,struct wxStringRuntime const *)
void * __cdecl `anonymous namespace'::CreateFrameToolBar(void *,int,int,struct wxStringRuntime const *)
void __cdecl `anonymous namespace'::AddNotebookPage(void *,void *,struct wxStringRuntime const *,bool,int)
void __cdecl `anonymous namespace'::AddToolBarSeparator(void *)
void __cdecl `anonymous namespace'::AddToolBarTool(void *,int,struct wxStringRuntime const *,void *,struct wxStringRuntime const *)
void __cdecl `anonymous namespace'::AppendWxMenuBarMenu(void *,void *,struct wxStringRuntime const *)
void __cdecl `anonymous namespace'::AppendWxMenuItem(void *,void *)
void __cdecl `anonymous namespace'::AppendWxMenuSeparator(void *)
void __cdecl `anonymous namespace'::ConnectDynamicTreeItemActivatedHandler(void * const,int,int,void * const,void * const)
void __cdecl `anonymous namespace'::ConnectDynamicTreeItemActivatedHandler(void *,int,int,void *,void *)
void __cdecl `anonymous namespace'::DestroyWxBitmap(void *)
void __cdecl `anonymous namespace'::RealizeToolBar(void *)
```

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
void __cdecl `anonymous namespace'::ConnectDynamicTreeItemActivatedHandler(void * const,int,int,void * const,void * const)
void __cdecl `anonymous namespace'::ConnectDynamicTreeItemActivatedHandler(void *,int,int,void *,void *)
```

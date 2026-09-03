---
name: project-texture-loading-never-worked
description: No texture in the game had ever loaded (3 stacked defects on one path); this is why every dialog collapsed to a point. Fixed 6c150a5. Also records the /nomovie fast path and the splash skip keys.
metadata:
  type: project
---

# Texture loading never worked at all — FIXED (6c150a5)

Symptom the operator reported: the Profile Manager drew "Create", "Options"
and "Delete" **on top of each other** in the centre of a black screen, with
"OK"/"Cancel" likewise overlapping. No panel, no button chrome, just text.

Cause: **no texture in the game had ever loaded.** `Bitmap.Width` is
`ScaleNumber(self.BitmapWidth())` (lua/maui/bitmap.lua), so a failed texture
gives a 0x0 control. MAUI layout is expressed *relative to neighbours' sizes*
(`LayoutHelpers.LeftOf/RightOf`), so a row of zero-width buttons collapses
onto one point. **A collapsed-layout dialog means look at texture loading, not
at the layout code.** There were no LazyVar warnings and the failures were
logged at `info:` level ("Unable to load texture from file: ..."), so a
warning/error grep finds nothing.

Three stacked defects, all on the one path:

1. **`CD3DFileBatchTexture.cpp` — `GetD3DTextureData` bypassed the resource
   manager.** It called `factory->Load(...)` directly; the binary
   (`func_GetD3DTextureData`, 0x0044DF90) calls
   `RES_GetResource(&weak, path, 0, SBatchTextureData::sType)`. That skipped
   the manager's **VFS path resolution**. See the path-shape note below.
2. **`ResourceManager.cpp` — the loaded resource was destroyed immediately.**
   `ResolvePendingResourceRequest` published a *weak* handle to the caller and
   released the only strong reference without ever storing it: the cache slot
   `request.mResolved` was assigned **from** `outResource` instead of from
   `loadedResource`. Fix: `AssignSharedPairRetainRelease(&loadedResource,
   &request.mResolved)` first, then `BuildWeakPairFromLiveSharedVariant1(
   &request.mResolved, outResource)` — mirroring the cache-hit path at the top
   of the same function.
3. **`D3D9Interfaces.cpp` — `D3DXCreateTextureFromFileInMemoryEx` args shifted
   by one.** See the IDA trap below.

## ⚠ Path shapes: VFS vs archive-qualified

`FWaitHandleSet::MemoryMapFile` does **no** VFS translation (faithful — the
binary doesn't either). It canonicalises, looks in `mZipEntries`, else
`CreateFileW`. The zip map is keyed by the **archive-qualified physical**
path that `DISK_MountZipFile` builds:

    g:\...\gamedata\textures.scd\textures\ui\common\scx_menu\profile\panel_bmp.dds

Callers must therefore resolve first, via `DISK_GetVFS()->FindFile(...)` (or
`RES_GetResource`, which does it for you). A raw mount-point path like
`/textures/ui/...` canonicalises to `\textures\ui\...`, misses the map, and
`CreateFileW` on a leading-backslash path returns nothing. Every other loader
in the tree (audio, movies, fonts, effects, `CWldMap`) already calls
`FindFile`; the texture path was the odd one out. If a resource "isn't found"
but the archive demonstrably contains it, check which path shape reached
`DISK_MemoryMapFile`.

## ⚠ IDA applies the *volume* prototype to D3DXCreateTextureFromFileInMemoryEx

At 0x008ECD87 IDA names the callee `D3DXCreateTextureFromFileInMemoryEx`
(confirmed: the thunk jumps to `d3dx9_35.dll` ordinal 0x62, the **2D** entry,
15 params) but annotates the pushes with the **16-param volume** prototype,
inventing a `depth` argument. Every label from `format` onward is therefore
shifted one place left. The retry at 0x008ECDB7 pushes exactly **15** and
settles it. Read the pushes, not the labels.

True argument list for `GetTexture2D`:

| # | param | value |
|---|---|---|
| 4,5 | Width, Height | `-2` = **D3DX_DEFAULT_NONPOW2** (not -1!) |
| 6 | MipLevels | 1 |
| 7 | Usage | 0 |
| 8 | Format | 0 (`D3DFMT_UNKNOWN`, take from file) |
| 9 | Pool | 2 (`D3DPOOL_SYSTEMMEM`) |
| 10,11 | Filter, MipFilter | 1, 1 (`D3DX_FILTER_NONE`) |
| 13 | pSrcInfo | pointer to a stack `D3DXIMAGE_INFO` |

`Format=2` (the shifted value) is not a D3DFORMAT at all, so the call and its
identical retry both failed. `NONPOW2` matters independently: these images are
580x448, 200x72, 120x180 — plain `D3DX_DEFAULT` would rescale them to powers
of two and change the sizes the whole layout derives from.

## Fast iteration: /nomovie and the splash skip keys

`lua/ui/splash/splash.lua` (in `lua.nx2`):

- `if GetPreference("movie.nologo") or HasCommandLineArg("/nomovie") then
  EngineStartFrontEndUI() return end` — **`/nomovie` skips all four splash
  movies** and goes straight to the front end. Both bindings are recovered and
  it works. Use it for every UI-side iteration; it cuts ~145s per run
  (`fmv_scx_intro` alone is 128s).
- Skip keys during playback: **Esc / Enter / Space / mouse click** jump to the
  **last** movie; pressing again leaves the splash. Any other key is swallowed.

**Passing `/nomovie` through Git Bash does not work** — bash rewrites it to
`C:/Program Files/Git/nomovie`. Put the switch inside a `.bat` (see the
scratchpad `runnomovie.bat`), and use `ping -n N 127.0.0.1 >nul` for the
delay, since `timeout` refuses to run with stdin redirected.

Related: [[project-vfs-die-root-cause]], [[project-frame-driver-refresh-stub]].

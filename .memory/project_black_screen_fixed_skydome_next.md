---
name: project-black-screen-fixed-skydome-next
description: CONFIRMED FIXED 2026-08-18 (commit fdf0def) - the CRenderWorldView vtable black screen is gone. /map SCMP_009 now reaches WRenViewport::Render and starts drawing; new crash is a pre-existing, unrelated bug in ResourceManager::ManageWatchedResources via SkyDome::CreateTextures.
metadata:
  type: project
---

[[project-black-screen-is-renderworldview-vtable]]'s fix landed and is
**confirmed by runtime evidence**, not just compile-clean.

## What changed

Commit `fdf0def` ("Install CRenderWorldView's vtable and land the
command-graph draw pass"):
  - `CUIWorldView`'s ctor now placement-constructs `moho::CRenderWorldView`
    at `+0x11C` (`UiRuntimeTypes.cpp`), publishing a real
    `IRenderWorldView` vtable instead of four zero bytes.
  - `CRenderWorldView::RenderCommandGraph` (slot 2, 0x0086ECD0) written:
    lazily caches the session's command graph, draws it through
    `UICommandGraph::DrawCommandGraphMesh` (the six-pass per-frame
    command-graph render), draws unit skirts, always draws the build-drag
    overlay via the already-landed `DrawCommandGraph`.
  - `UICommandGraph::DrawCommandGraphMesh` (0x00829190) written: opaque +
    glow orderline passes (RB-tree walk bucketed by texture), waypoint
    marker pass, position-node mesh pass, path-preview pass, screen-space
    ETA-label pass.
  - `Moho::DrawPathPreview` (0x0082A380, 595 decompiled lines) written:
    draws the active move-command preview ribbon, either RDP-simplified
    from a queued path (`SimplifyPathSpan`) or a straight cursor-to-unit
    line (`PickPathPreviewSubject`), sharing `EmitHermiteRibbonSegments`
    with `DrawCommandOrderline`. Its IDA-declared first parameter (a
    literal `-1` at the sole call site) turned out to be a decompiler
    artifact for `UICommandGraph* this` - every real read inside the body
    hits `mSession`/`mNodes[]` at their known offsets. Fixed the signature
    to take `UICommandGraph&` explicitly and declared it a `friend` of
    `UICommandGraph` for the access, after an earlier pass in this same
    session had wired the caller with a signature missing that parameter
    entirely - caught before commit, not after.
  - Found and fixed a real bug in my own draft while re-deriving the width
    math from raw offsets: two textually-adjacent decompiled quantities
    (`v142` feeding the arrowhead cap-offset divisor, `v108` the actual
    ribbon width) looked identical on a first pass but use different scale
    constants (`*3.0`/`*0.2` vs `*2.0`) and only one folds in a
    footprint-size seed - conflating them would have scaled the arrowhead
    cap wrong. Caught by re-reading the raw `.c` a second time before
    tucheck, not by tucheck itself (both versions compile).

## Runtime proof (dbgrun, /map SCMP_009, 2026-08-18 ~17:53 local)

Old fault (gone):
```
[EXCEPTION] ACCESS_VIOLATION read from address 00000004
  main!moho::WRenViewport::RenderAllHeads+0xDE  [WxRuntimeTypes.cpp:64990]
```

New fault (much deeper - confirms the render pipeline now actually runs):
```
[EXCEPTION] ACCESS_VIOLATION (0xC0000005) read from address C5FFA4D6
  main!moho::ResourceManager::ManageWatchedResources+0x7D  [ResourceManager.cpp:4738]
  <- SkyDome::CreateTextures+0x95   [SkyDome.cpp:562]
  <- SkyDome::CreateRenderAbility+0x14   [SkyDome.cpp:338]
  <- WRenViewport::RenderSkyDome+0x108   [WxRuntimeTypes.cpp:65323]
  <- WRenViewport::Render+0x29E   [WxRuntimeTypes.cpp:65138]
  <- WRenViewport::RenderAllHeads+0x1C4   [WxRuntimeTypes.cpp:65010]
```

`fault=2` total this run (one more past this one, not yet inspected -
check `/tmp/brkmap_out.txt`-equivalent from the next run for the second).
`cpp=2321` C++ throws printed are Lua runtime errors during normal script
execution, not crashes - this project's established baseline noise, not a
regression.

## Next blocker: SkyDome::CreateTextures / ResourceManager::ManageWatchedResources

This is a **pre-existing, unrelated bug** - nothing to do with the
command-graph/vtable chain just landed. `ManageWatchedResources` reads
through a garbage pointer (`C5FFA4D6`, an uninitialized-memory-looking
address, `ebx`/`ecx` both `~C5FFA4xx`) 0x7D bytes into the function at
`ResourceManager.cpp:4738`, called from `SkyDome::CreateTextures` during
`SkyDome::CreateRenderAbility`, itself called from `WRenViewport::RenderSkyDome`
- the very first drawable thing `WRenViewport::Render` attempts once a
world view actually exists and dispatches. Read `ResourceManager.cpp`
around line 4738 and `SkyDome::CreateTextures` (`SkyDome.cpp:562`) next -
likely an uninitialized/dangling resource-watch-list entry, or a
mistyped/missing-null-check field read.

Not chased further this session - this note exists to hand the actual
next concrete blocker to whoever (or whatever pass) picks this up next,
per this repo's own "no orphaned blocker without a note" convention.

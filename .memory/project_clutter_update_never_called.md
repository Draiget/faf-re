---
name: project_clutter_update_never_called
description: READY TO APPLY, blocked only on the WxRuntimeTypes.cpp file lock. WRenViewport::Render omits the inlined Clutter::Update, so no clutter region is ever generated and no decorative scatter meshes render. Exact insertion point and evidence recorded.
metadata:
  type: project
---

## The gap

`Clutter::Update` (`0x007D6380`) is **never invoked anywhere in `src/sdk`**.
The clutter object is constructed (`WxRuntimeTypes.cpp:67171`), destructed
(`:67275`) and shut down (`:70215`) — but never updated. `UpdateCurrent` and
`GenerateNew` have no source caller either. So no clutter region is ever
created and the decorative scatter never renders.

This matches the operator's symptom 3, *"no map borders (some meshes around
map)"*.

## Where it belongs — exact evidence

`Clutter::Update` itself has **zero xrefs** in the binary
(`FUN_007D6380.xrefs.txt`: `xrefs_total: 0`). That is not dead code — MSVC
**inlined** it, since its whole body is two calls. The proof is in the
callees' xrefs:

```
FUN_007D6510.xrefs.txt  (Clutter::UpdateCurrent)
  code from=0x007D6384 owner=0x007D6380   <- the inlined-away Update
  code from=0x007F9322 owner=0x007F90D0   <- Moho::WRenViewport::Render
```

So `WRenViewport::Render` calls `UpdateCurrent` directly at `0x007F9322`,
followed by `GenerateNew` (`0x007D6640`). The source line that produced both
is a single `mClutter.Update(camera)`.

## Why it is not landed

`WRenViewport::Render` is recovered at `WxRuntimeTypes.cpp:70447` (it already
drives `meshRenderer->Batch(...)` at `:70685`), but that file carried another
session's uncommitted work on 2026-09-02, including probes marked "TEMPORARY
PROBE (do not commit)". Editing it would force a commit that sweeps in their
WIP, which the file-lease protocol forbids — see
[[feedback_multi_agent_file_lease_protocol]].

**To apply once the lock clears:** add the `mClutter.Update(camera)` call into
`WRenViewport::Render` at the point matching `0x007F9322`, i.e. in the
per-head render sequence, and confirm the clutter regions populate. Check
first whether `Clutter::Init`/`Shutdown` pairing is also wired — only
`Shutdown` currently has a caller.

## Related

Same file-contention blocker as the `wxFileName`/`wxScrollHelper` cluster
([[project_wx_cluster_blocked_on_wxruntimetypes_lock]]) and the terrain
normal-map defect, which lives in the peer-locked `CWldMap.cpp`
([[project_playablerectupdates_never_populated]]). Three separate real fixes
are now queued behind two locked files — worth telling the operator so they
can decide whether to land or park the other session's WIP.

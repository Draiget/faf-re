---
name: project-d3d9-zero-adapters-is-host-not-code
description: "invalid head count" at startup is a host condition — D3D9 reports GetAdapterCount()==0 — proven by a standalone probe; do not chase the GAL for it.
metadata:
  type: project
---

# "invalid head count" at startup is the HOST, not our GAL

Confirmed 2026-09-01. When `/map SCMP_009 //log` dies at:

    ThrowGalError("DeviceD3D9.cpp", 1229, "invalid head count")
      CheckAdapterSelectionForSetup   D3D9Interfaces.cpp:3513
      InitializeDeviceD3D9Backend     D3D9Interfaces.cpp:6293
      moho::CreateDeviceD3D           StartupHelpers.cpp:7256
      CScApp::CreateAppFrame / CreateDevice / Init

...it means `runtime.adapters` is empty, i.e. `IDirect3D9::GetAdapterCount()`
returned 0. The check itself (`headCount > adapterCount`) is faithful and
correct — with one head configured and zero adapters enumerated, throwing is
what the binary does.

## The decisive test — run this BEFORE touching any GAL code

`scratchpad/d3dprobe.cpp` (recreate it; ~40 lines, links `d3d9.lib`, build
x86 via `vcvarsamd64_x86`): call `Direct3DCreate9` and print
`GetAdapterCount()` plus each adapter's identifier. It uses the real D3D9
headers and none of our code.

Result on this host, 2026-09-01:

    Direct3DCreate9(D3D_SDK_VERSION=32) -> 00C42180
    Direct3DCreate9(0x20)               -> 00C4EFA0
    [SDK_VERSION] GetAdapterCount() = 0
    [0x20]        GetAdapterCount() = 0

The interface is created successfully and then reports **zero adapters**.
Nothing in `src/sdk` participates in that. Retail `ForgedAlliance.exe` fails
the same way when the host is in this state, which is the corroborating
observation.

## Incidental confirmations from the probe

- `D3D_SDK_VERSION == 32 == 0x20`, so the engine's hardcoded
  `InvokeDirect3DCreate9Interface(0x20U)` is exactly right — not a bug, and
  not worth "fixing".
- `Direct3DCreate9` succeeding tells you nothing about adapter availability.
  The null check at `D3D9Interfaces.cpp:6286` passes in this state.

## It is a WINDOW, not a permanent state — and launches are expensive

Superseding the earlier "degrades after ~35 launches" theory. Measured
2026-09-01:

| time | event | count |
|---|---|---|
| t0 | first probe of the session | **0** |
| t0+~40min | probe again, nothing launched in between | **1** (TITAN RTX) |
| +build, +1 `/map` launch (failed at device creation) | | |
| right after | probe | **0** |
| +30s / +60s / +90s | probe | **0**, **0**, **0** |

So the adapters come back on their own after tens of minutes, and the state
goes back to zero around a launch attempt. It does NOT recover in seconds.

Practical consequences:

- **Each launch attempt costs roughly the next 40 minutes** of
  runtime-verification availability. Make every one count.
- **Probe immediately before launching, and launch instantly if it reads
  non-zero.** Do not build in between: the window can close during the build,
  which is exactly how the one recovery window this session got wasted.
  Have `main.exe` already built and staged first.
- Wait for the window with a slow background check (a probe every ~2 min that
  exits on the first non-zero count gives one notification and no load).
  Do not hand-poll, and do not retry launches in a loop — see the global
  host-safety rule.

Whether the launch itself causes the drop or the window merely expired on its
own is not yet separated; both fit the data. Distinguishing them needs a probe
run at short intervals across a window with *no* launch in it.

Until a window is open, **runtime verification is unavailable** and the only
honest report is "blocked on the host", never "it should work now".

Related: [[project_startup_debugging_harness]],
[[project_render_goal_first_frame_confirmed]],
[[project_shared_checkout_runtime_artifacts]].

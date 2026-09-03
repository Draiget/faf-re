---
name: project-factory-queue-ui-stub
description: UI_FactoryCommandQueueHandlerBeat is an empty stub that is already called every beat, so the factory build-queue UI never updates. Body decoded; blocked on one 164-instruction vector-assign and its five helpers.
metadata:
  type: project
---

`moho::UI_FactoryCommandQueueHandlerBeat()` at
`UiRuntimeTypes.cpp:25832` is **`{}`** - an empty body - and it is **already
wired**: `CUIManager::DoBeat` calls it (`CUIManager.cpp:382`). So the engine
runs it every beat and it does nothing, which means the factory build-queue UI
is never told the queue changed - `OnQueueChanged` never fires.

This is a live gameplay-visible defect, not paperwork.

## Decoded body (FUN_00836180, 187 instrs)

    mState = UI_Manager->mState;
    LuaObject queue;                       // the payload passed to Lua
    bool notify = true;

    if (no factory selected) {             // sCurrentBuildFactory._M_start null or == 8
      if (sCurrentBuildQueue is non-empty) {
        queue.AssignNil(mState);
        sub_837070(&tmp, sCurrentBuildQueue.start, sCurrentBuildQueue.end);   // clear the cache
        goto notify;                       // notify with nil so the UI clears
      }
      // otherwise: nothing changed, no call
    } else {
      fastvector<BuildQueueItem> snapshot{};
      sub_835DF0(&snapshot, <resolved factory ref>);      // build this beat's queue
      if (sub_837750(&snapshot)) {
        notify = false;                    // identical to the cached queue -> no call
      } else {
        func_AddScriptUIBuildQueueItem(&snapshot, mState, &queue);  // build the Lua table
        sub_836C80(&snapshot);                                      // commit into sCurrentBuildQueue
      }
      <free snapshot>
      if (notify) goto notify;
    }

    notify:
      gamemain = SCR_Import(mState, "/lua/ui/game/gamemain.lua");
      LuaFunction fn{gamemain["OnQueueChanged"]};
      fn.Call_Object(queue);

Everything in that flow is already recovered - `SCR_Import`, `sub_835DF0`,
`sub_837750`, `func_AddScriptUIBuildQueueItem`, `sub_837070`,
`func_DeleteRangeBuildQueueItems`, and the LuaPlus imports - **except one**.

## The single blocker: sub_836C80 (0x00836C80, 164 instrs)

It is `sCurrentBuildQueue = snapshot`, a vector assign with three arms:

  - snapshot fits in the current **size**: `CopyBuildQueueItems` over the
    existing elements, `DeleteRangeBuildQueueItems` the tail, fix `end`. This
    arm is already expressed in `sub_837070`
    (`UiRuntimeTypes.cpp:25818-25826`) and can be reused.
  - snapshot fits in the current **capacity**: uninitialised-copy dance via
    `sub_836E60` / `sub_8378B0` / `sub_8378E0`.
  - otherwise: free and rebuild, via `sub_837120` + `operator delete` +
    `sub_836E60` + `sub_8370D0`.

Those five helpers (`sub_836E60`, `sub_8378B0`, `sub_8378E0`, `sub_8370D0`,
`sub_837120`) are the rest of the closure-20 measurement. They are container
machinery, so per the container-emission rule express the assign through the
existing `CurrentBuildQueueRuntimeView` + `CopyBuildQueueItems` /
`DeleteRangeBuildQueueItems` API rather than transcribing all five.

**Order of work:** write the assign as one named helper against the existing
queue API, then replace the empty stub with the flow above. The stub is already
called, so no caller wiring is needed - this is a pure stub replacement.

## How it was found

Not by the closure sweep - that ranked it as a 20-function cluster and I
skipped it twice. It surfaced from the **annotation-gap sweep**: its symbol
name already appears in `src/sdk` (3 times) while its address does not, which
is the signature of "implemented or stubbed, but unannotated". Of ~2490
candidates with a usable identifier, 551 look like annotation gaps rather than
real gaps. Running that check first would have saved two batches.

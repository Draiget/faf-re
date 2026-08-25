#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/Rect2.h"
#include "moho/misc/Listener.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/ECommandEvent.h"
#include "moho/unit/tasks/CBuildTaskHelper.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CCommandTask;
  class CUnitCommand;
  class Entity;
  struct RUnitBlueprint;
  class Unit;

  struct CUnitMobileBuildTaskListenerPad
  {
    std::uint32_t mListenerPad{};
  };

  static_assert(sizeof(CUnitMobileBuildTaskListenerPad) == 0x04, "CUnitMobileBuildTaskListenerPad size must be 0x04");

  /**
   * Runtime owner for mobile-build task command/listener lanes.
   */
  class CUnitMobileBuildTask : public CCommandTask, public CUnitMobileBuildTaskListenerPad, public Listener<ECommandEvent>
  {
  public:
    /**
     * Address: 0x005F6400 (FUN_005F6400, ??0CUnitMobileBuildTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes detached mobile-build-task storage for reflection lanes:
     * command/listener subobjects, build-helper defaults, and build target
     * placement/runtime weak-link state.
     */
    CUnitMobileBuildTask();

    /**
     * Address: 0x005F6520 (FUN_005F6520, ??0CUnitMobileBuildTask@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Initializes one dispatch-bound mobile-build task, binds command-listener
     * lanes, resolves build placement from footprint/cell coordinates, and
     * primes runtime build-area/skirt caches.
     */
    CUnitMobileBuildTask(
      CCommandTask* dispatchTask,
      const RUnitBlueprint* blueprint,
      const Wm3::Vector3f& buildPosition,
      const Wm3::Quatf& buildOrientation,
      const Wm3::Vector3f& buildDirection
    );

    /**
     * Address: 0x005F6AC0 (FUN_005F6AC0, ??1CUnitMobileBuildTask@Moho@@QAE@@Z)
     *
     * What it does:
     * Clears owner/build-unit state bits, commits dispatch result lane for
     * failed/interrupted completion, and tears down helper + weak-link lanes.
     */
    ~CUnitMobileBuildTask() override;

    /**
     * Address: 0x005F8370 (FUN_005F8370, ??2CUnitMobileBuildTask@Moho@@QAE@@Z_0)
     *
     * What it does:
     * Allocates one mobile-build task object and forwards arguments into
     * dispatch-bound in-place construction.
     */
    [[nodiscard]] static CUnitMobileBuildTask* Create(
      CCommandTask* dispatchTask,
      const RUnitBlueprint* blueprint,
      const Wm3::Vector3f& buildPosition,
      const Wm3::Quatf& buildOrientation,
      const Wm3::Vector3f& buildDirection
    );

    /**
     * Address: 0x00605CD0 (FUN_00605CD0)
     *
     * What it does:
     * Stores one blueprint pointer lane and returns this task.
     */
    CUnitMobileBuildTask* SetBlueprint(const RUnitBlueprint* blueprint) noexcept;

    // Address: cached RTTI lane read/written by
    // `CUnitMobileBuildTaskSerializer::Init` (0x005FBBA0); see
    // `moho/unit/tasks/CUnitMobileBuildTaskSerializer.cpp`.
    static gpg::RType* sType;

    /**
     * Address: 0x005FE710 (FUN_005FE710, Moho::CUnitMobileBuildTask::MemberDeserialize)
     *
     * IDA signature:
     * void __usercall MemberDeserialize(CUnitCommand** this@<ecx>, gpg::ReadArchive* archive@<eax>);
     *
     * What it does:
     * Loads mobile-build-task state from an archive in binary lane order: the
     * base `CCommandTask` sub-object and the embedded `CBuildTaskHelper` by
     * reflected type; the command / blueprint pointer lanes via the typed
     * `ReadPointer_*` slots; the build position / orientation / direction and
     * build rect/skirt payloads by reflected type; the placement-retry counter
     * via the virtual `ReadInt` slot; and the build-unit / pending-build-entity
     * weak links by reflected type.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005FE950 (FUN_005FE950, Moho::CUnitMobileBuildTask::MemberSerialize)
     *
     * IDA signature:
     * void __usercall MemberSerialize(CUnitMobileBuildTask* this@<eax>, gpg::WriteArchive* archive@<esi>);
     *
     * What it does:
     * Line-for-line write mirror of `MemberDeserialize` over the identical field
     * set and order: the base sub-object and the build helper via reflected
     * `Write`; the command / blueprint pointer lanes via `RRef_*` +
     * `WriteRawPointer(... Unowned ...)`; the transform + rect payloads via
     * reflected `Write`; the placement-retry counter via the virtual `WriteInt`
     * slot; and the two weak links via reflected `Write`.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x005F7440 (FUN_005F7440, Moho::CUnitMobileBuildTask::TaskTick)
     *
     * VFTable SLOT: 1
     *
     * What it does:
     * Mobile engineer build-task state machine (Preparing/Waiting/Starting/
     * Processing/Complete): clears obstructing props, moves the builder into
     * range, faces the target, spawns/adopts the seed unit, drives the build
     * helper to completion, then issues the rebuild-upgrade or factory-rally
     * follow-up. Returns the scheduler code (-1/0/1/10/50).
     */
    int Execute() override;

    /**
     * Address: 0x005F80C0 (FUN_005F80C0, Moho::CUnitMobileBuildTask::OnEvent)
     * Mangled: ?OnEvent@CUnitMobileBuildTask@Moho@@UAEXW4ECommandEvent@2@@Z
     *
     * VFTable SLOT: 0 of the `Listener<ECommandEvent>` sub-object at +0x34
     * (`??_7CUnitMobileBuildTask@Moho@@6B?$Listener@W4ECommandEvent@Moho@@@Moho@@@`).
     *
     * IDA signature:
     * void __thiscall sub_5F80C0(Listener<ECommandEvent>* this, ECommandEvent event);
     *
     * What it does:
     * Re-seats the build order after the owning command was edited. Abandons
     * any build already in flight (drops the target's no-reclaim protection,
     * zeroes the builder's work progress, stops the helper's build focus and
     * clears both weak links), then recomputes the placement from the
     * command's current target: cell-snaps the gun target position by the
     * blueprint footprint, converts it back to a world position through the
     * sim's map, and refreshes `mBuildPosition`, `mBuildRect` and
     * `mBuildSkirt`. Finally rewinds the task to `TASKSTATE_Preparing` and
     * unstages the owning task thread so it runs again next frame.
     *
     * The `event` argument is never read - every command event re-seats the
     * order identically.
     */
    void OnEvent(ECommandEvent event) override;

  private:
    /**
     * Address: 0x005F6C70 (FUN_005F6C70, sub_5F6C70)
     *
     * Sphere-queries units on the build site for a live, being-built unit of the
     * target blueprint coincident with the build position (the "seed").
     */
    [[nodiscard]] Unit* FindExistingSeedUnitOnSite() const;

    /**
     * Address: 0x005F6EA0 (FUN_005F6EA0, sub_5F6EA0)
     *
     * Box-queries ObstructsBuild props over the footprint; on a RebuildBonus id
     * match binds the pending-build entity (returns null), else returns the
     * nearest obstructing prop to reclaim.
     */
    [[nodiscard]] Entity* FindObstructingPropToReclaim();

  public:
    CBuildTaskHelper mBuildHelper;       // 0x40
    CUnitCommand* mCommand;              // 0x84
    const RUnitBlueprint* mBlueprint;    // 0x88
    Wm3::Vector3f mBuildPosition;        // 0x8C
    Wm3::Quatf mBuildOrientation;        // 0x98
    Wm3::Vector3f mBuildDirection;       // 0xA8
    std::int32_t mPlacementRetryCount;   // 0xB4
    WeakPtr<Unit> mBuildUnit;            // 0xB8
    WeakPtr<Entity> mPendingBuildEntity; // 0xC0
    gpg::Rect2i mBuildRect;              // 0xC8
    gpg::Rect2f mBuildSkirt;             // 0xD8
  };

  static_assert(sizeof(CUnitMobileBuildTask) == 0xE8, "CUnitMobileBuildTask size must be 0xE8");
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildHelper) == 0x40, "CUnitMobileBuildTask::mBuildHelper offset must be 0x40"
  );
  static_assert(offsetof(CUnitMobileBuildTask, mCommand) == 0x84, "CUnitMobileBuildTask::mCommand offset must be 0x84");
  static_assert(
    offsetof(CUnitMobileBuildTask, mBlueprint) == 0x88, "CUnitMobileBuildTask::mBlueprint offset must be 0x88"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildPosition) == 0x8C, "CUnitMobileBuildTask::mBuildPosition offset must be 0x8C"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildOrientation) == 0x98,
    "CUnitMobileBuildTask::mBuildOrientation offset must be 0x98"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildDirection) == 0xA8, "CUnitMobileBuildTask::mBuildDirection offset must be 0xA8"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mPlacementRetryCount) == 0xB4,
    "CUnitMobileBuildTask::mPlacementRetryCount offset must be 0xB4"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildUnit) == 0xB8, "CUnitMobileBuildTask::mBuildUnit offset must be 0xB8"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mPendingBuildEntity) == 0xC0,
    "CUnitMobileBuildTask::mPendingBuildEntity offset must be 0xC0"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildRect) == 0xC8, "CUnitMobileBuildTask::mBuildRect offset must be 0xC8"
  );
  static_assert(
    offsetof(CUnitMobileBuildTask, mBuildSkirt) == 0xD8, "CUnitMobileBuildTask::mBuildSkirt offset must be 0xD8"
  );
} // namespace moho

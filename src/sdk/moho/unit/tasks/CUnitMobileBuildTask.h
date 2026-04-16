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

    void OnEvent(ECommandEvent) override {}

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

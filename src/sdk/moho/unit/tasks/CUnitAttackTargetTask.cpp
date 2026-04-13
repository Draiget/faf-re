#include "moho/unit/tasks/CUnitAttackTargetTask.h"

#include <cmath>
#include <cstddef>
#include <cstdint>
#include <new>

#include "moho/ai/IAiNavigator.h"
#include "moho/path/SNavGoal.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UnitWeapon.h"
#include "moho/unit/tasks/CUnitMeleeAttackTargetTask.h"

namespace
{
  struct CUnitAttackTargetTaskRuntimeView
  {
    std::uint8_t mCommandTaskStorage[sizeof(moho::CCommandTask)]{}; // +0x00
    std::uint8_t mUnknown30To8F[0x60]{};                            // +0x30
  };

  static_assert(
    sizeof(CUnitAttackTargetTaskRuntimeView) == sizeof(moho::CUnitAttackTargetTask),
    "CUnitAttackTargetTaskRuntimeView size must match CUnitAttackTargetTask"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mCommandTaskStorage) == 0x00,
    "CUnitAttackTargetTaskRuntimeView::mCommandTaskStorage offset must be 0x00"
  );
  static_assert(
    offsetof(CUnitAttackTargetTaskRuntimeView, mUnknown30To8F) == 0x30,
    "CUnitAttackTargetTaskRuntimeView::mUnknown30To8F offset must be 0x30"
  );

  [[nodiscard]] CUnitAttackTargetTaskRuntimeView* AsRuntimeView(
    moho::CUnitAttackTargetTask* const task
  ) noexcept
  {
    return reinterpret_cast<CUnitAttackTargetTaskRuntimeView*>(task);
  }

  [[nodiscard]] moho::CCommandTask* AsCommandTask(CUnitAttackTargetTaskRuntimeView* const runtime) noexcept
  {
    return reinterpret_cast<moho::CCommandTask*>(runtime->mCommandTaskStorage);
  }

  [[nodiscard]] int RoundToCellCoord(const float value) noexcept
  {
    return static_cast<int>(std::lrintf(value));
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x005F27D0 (FUN_005F27D0, Moho::CAttackTargetTask::operator new)
   *
   * What it does:
   * Chooses melee-vs-ranged attack task allocation from dispatch unit state,
   * then forwards into the corresponding dispatch-bound constructor lane.
   */
  CAttackTargetTask* CAttackTargetTask::Create(
    CCommandTask* const dispatchTask,
    CAiTarget* const target,
    CAiFormationInstance* const formation
  )
  {
    if (dispatchTask != nullptr && dispatchTask->mUnit != nullptr && dispatchTask->mUnit->mIsMelee) {
      return CUnitMeleeAttackTargetTask::Create(dispatchTask, target, formation);
    }

    void* const storage = ::operator new(sizeof(CUnitAttackTargetTask), std::nothrow);
    if (!storage) {
      return nullptr;
    }

    try {
      return ::new (storage) CUnitAttackTargetTask(dispatchTask, target, formation, true, false);
    } catch (...) {
      ::operator delete(storage);
      throw;
    }
  }

  /**
   * Address: 0x005F2CE0 (FUN_005F2CE0, Moho::CUnitAttackTargetTask::SetWeaponGoal)
   *
   * What it does:
   * Builds one rectangular navigator goal centered on target position and
   * half-weapon-radius extents, then dispatches it through the owner
   * `IAiNavigator`.
   */
  void CUnitAttackTargetTask::SetWeaponGoal(const Wm3::Vector3f& targetPosition, UnitWeapon* const weapon)
  {
    IAiNavigator* const navigator = AsCommandTask(AsRuntimeView(this))->mUnit->AiNavigator;
    if (navigator == nullptr) {
      return;
    }

    const int maxRadius = static_cast<int>(weapon->mWeaponBlueprint->MaxRadius);
    const float halfRadius = static_cast<float>(maxRadius) * 0.5f;

    const int minX = static_cast<std::int16_t>(RoundToCellCoord(targetPosition.x - halfRadius));
    const int minZ = static_cast<std::int16_t>(RoundToCellCoord(targetPosition.z - halfRadius));

    SAiNavigatorGoal goal{};
    goal.mPos1.x0 = minX;
    goal.mPos1.z0 = minZ;
    goal.mPos1.x1 = minX + maxRadius;
    goal.mPos1.z1 = minZ + maxRadius;
    goal.mPos2 = gpg::Rect2i{};
    goal.mLayer = static_cast<ELayer>(0);
    navigator->SetGoal(goal);
  }
} // namespace moho

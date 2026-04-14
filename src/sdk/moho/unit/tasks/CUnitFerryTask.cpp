#include "moho/unit/tasks/CUnitFerryTask.h"

#include <memory>
#include <new>

#include "moho/ai/IAiNavigator.h"
#include "moho/unit/core/Unit.h"

namespace
{
  constexpr std::uint64_t kUnitStateMaskFerryTaskFlags = (1ull << 20) | (1ull << 32);
}

namespace moho
{
  /**
   * Address: 0x0060E2C0 (FUN_0060E2C0, Moho::CUnitFerryTask::~CUnitFerryTask)
   *
   * What it does:
   * Aborts active unit navigation, clears ferry task owner-state bits, and
   * unlinks all ferry-task weak-unit ownership lanes.
   */
  CUnitFerryTask::~CUnitFerryTask()
  {
    Unit* const ownerUnit = mUnit;
    if (ownerUnit != nullptr) {
      if (IAiNavigator* const navigator = ownerUnit->AiNavigator; navigator != nullptr) {
        navigator->AbortMove();
      }

      ownerUnit->UnitStateMask &= ~kUnitStateMaskFerryTaskFlags;
    }

    mBeacon.UnlinkFromOwnerChain();
    mFerryUnit.UnlinkFromOwnerChain();
    mCommandUnit.UnlinkFromOwnerChain();
  }

  /**
   * Address: 0x0060F7E0 (FUN_0060F7E0, Moho::CUnitFerryTask::operator new)
   *
   * What it does:
   * Allocates one ferry-task object and forwards constructor arguments into
   * in-place construction.
   */
  CUnitFerryTask* CUnitFerryTask::Create(
    CCommandTask* parentTask,
    CUnitCommand* command
  )
  {
    auto* raw = static_cast<CUnitFerryTask*>(::operator new(sizeof(CUnitFerryTask)));
    auto guard = std::unique_ptr<CUnitFerryTask, void (*)(CUnitFerryTask*)>(raw, [](CUnitFerryTask* p) {
      ::operator delete(p);
    });
    return std::construct_at(guard.release(), parentTask, command);
  }
} // namespace moho

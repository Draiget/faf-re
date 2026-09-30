#include "moho/unit/tasks/CUnitGetBuiltTask.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    constexpr const char* kAiUnitCommandsPath = "c:\\work\\rts\\main\\code\\src\\sim\\AiUnitCommands.cpp";
  }

  /**
   * Address: 0x0060A4D0 (FUN_0060A4D0, Moho::CUnitGetBuiltTask::TaskTick)
   *
   * What it does:
   * Tracks build completion for the owner unit and completes when the unit is
   * mobile and attached to a parent transporter/entity.
   */
  int CUnitGetBuiltTask::Execute()
  {
    if (mTaskState == TASKSTATE_Preparing) {
      if (mUnit->IsBeingBuilt()) {
        return 1;
      }

      if (!mUnit->IsMobile()) {
        return -1;
      }

      mTaskState = TASKSTATE_Waiting;
    } else if (mTaskState != TASKSTATE_Waiting) {
      gpg::HandleAssertFailure("Reached the supposably unreachable.", 557, kAiUnitCommandsPath);
    }

    return (mUnit->mAttachInfo.GetAttachTargetEntity() != nullptr) ? 1 : -1;
  }

  /**
   * Address: 0x0060A550 (FUN_0060A550, Moho::CUnitGetBuiltTask::CUnitGetBuiltTask)
   *
   * What it does:
   * Runs the detached `CCommandTask` base constructor and leaves the derived
   * task with its own vftable installed by the compiler.
   */
  CUnitGetBuiltTask::CUnitGetBuiltTask()
    : CCommandTask()
  {}

  /**
   * Address: 0x0060A810 (FUN_0060A810, Moho::CUnitGetBuildTask::CUnitGetBuildTask)
   *
   * What it does:
   * Constructs one built-task child lane from parent command-dispatch context.
   */
  CUnitGetBuiltTask::CUnitGetBuiltTask(CCommandTask* const parent)
    : CCommandTask(parent)
  {}

  /**
   * Address: 0x0060A570 (FUN_0060A570, scalar deleting destructor thunk)
   *
   * What it does:
   * Runs `CCommandTask` teardown for the built-task lane; there is no extra
   * derived state to release.
   */
  CUnitGetBuiltTask::~CUnitGetBuiltTask() = default;
} // namespace moho

namespace
{
  [[nodiscard]] gpg::RType* CachedCUnitGetBuiltTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CUnitGetBuiltTask));
    }
    return cached;
  }

  // CUnitGetBuiltTask adds no fields beyond CCommandTask (see the trivial
  // forwarding constructors above), so the binary serializes it purely as
  // its CCommandTask base -- both facades below read/write through the
  // cached CCommandTask reflection type rather than a per-class member
  // Deserialize/Serialize.
  [[nodiscard]] gpg::RType* CachedCCommandTaskTypeForGetBuiltTask()
  {
    gpg::RType* type = moho::CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CCommandTask));
      moho::CCommandTask::sType = type;
    }
    return type;
  }

} // namespace

namespace moho
{
  /**
   * What it does:
   * Loads the `CCommandTask` base; the derived class adds no archived
   * fields. Inlined into `gpg::SerSaveLoadHelper<CUnitGetBuiltTask>::Deserialize`
   * 0x0060A700.
   */
  void CUnitGetBuiltTask::MemberDeserialize(gpg::ReadArchive* const archive, const int, const gpg::RRef& ownerRef)
  {
    archive->Read(CachedCCommandTaskTypeForGetBuiltTask(), static_cast<CCommandTask*>(this), ownerRef);
  }

  /**
   * What it does:
   * Saves the `CCommandTask` base. Inlined into
   * `gpg::SerSaveLoadHelper<CUnitGetBuiltTask>::Serialize` 0x0060A740.
   */
  void CUnitGetBuiltTask::MemberSerialize(gpg::WriteArchive* const archive, const int, const gpg::RRef& ownerRef) const
  {
    archive->Write(CachedCCommandTaskTypeForGetBuiltTask(), static_cast<const CCommandTask*>(this), ownerRef);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CUnitGetBuiltTask>`, vtable 0x00E202FC.
   *
   * Address: 0x00BD05F0 (FUN_00BD05F0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF9BD0 (FUN_00BF9BD0 -- the global's destructor.)
   * Address: 0x0060BAE0 (FUN_0060BAE0 -- `Init`.)
   * Address: 0x0060A700 (FUN_0060A700 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x0060A740 (FUN_0060A740 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct CUnitGetBuiltTaskSerializer : gpg::SerSaveLoadHelper<CUnitGetBuiltTask>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B1378 -- process-global `CUnitGetBuiltTaskSerializer` singleton.
  moho::CUnitGetBuiltTaskSerializer gCUnitGetBuiltTaskSerializer;
} // namespace

#include "moho/unit/tasks/CUnitPatrolTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitPatrolTask.h"

namespace
{
  alignas(moho::CUnitPatrolTaskTypeInfo)
    unsigned char gCUnitPatrolTaskTypeInfoStorage[sizeof(moho::CUnitPatrolTaskTypeInfo)];
  bool gCUnitPatrolTaskTypeInfoConstructed = false;

  [[nodiscard]] moho::CUnitPatrolTaskTypeInfo& CUnitPatrolTaskTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::CUnitPatrolTaskTypeInfo*>(gCUnitPatrolTaskTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0061AB10 (FUN_0061AB10, preregister_CUnitPatrolTaskTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup `CUnitPatrolTaskTypeInfo`
   * reflection lane.
   */
  gpg::RType* preregister_CUnitPatrolTaskTypeInfo()
  {
    if (!gCUnitPatrolTaskTypeInfoConstructed) {
      new (gCUnitPatrolTaskTypeInfoStorage) CUnitPatrolTaskTypeInfo();
      gCUnitPatrolTaskTypeInfoConstructed = true;
    }

    gpg::PreRegisterRType(typeid(CUnitPatrolTask), &CUnitPatrolTaskTypeInfoStorageRef());
    return &CUnitPatrolTaskTypeInfoStorageRef();
  }

  const char* CUnitPatrolTaskTypeInfo::GetName() const
  {
    return "CUnitPatrolTask";
  }

  void CUnitPatrolTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitPatrolTask);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

#include "moho/unit/tasks/CUnitPatrolTaskTypeInfo.h"

#include <new>
#include <typeinfo>

#include "moho/unit/tasks/CUnitPatrolTask.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  /**
   * Address: 0x0061CAA0 (FUN_0061CAA0, Moho::CUnitPatrolTaskTypeInfo::AddBase_CCommandTask)
   */
  void CUnitPatrolTaskTypeInfo::AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(CCommandTask));
    }
    gpg::AddBaseIfPresent(typeInfo, sType, 0x00);
  }

  /**
   * Address: 0x0061CB00 (FUN_0061CB00, Moho::CUnitPatrolTaskTypeInfo::AddBase_Listener_ECommandEvent)
   */
  void CUnitPatrolTaskTypeInfo::AddBase_Listener_ECommandEvent(gpg::RType* const typeInfo)
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(Listener<ECommandEvent>));
    }
    gpg::AddBaseIfPresent(typeInfo, sType, 0x34);
  }

  /**
   * Address: 0x0061CB60 (FUN_0061CB60, Moho::CUnitPatrolTaskTypeInfo::AddBase_Listener_EFormationdStatus)
   *
   * The binary spells it `Formationd`; kept so the symbol still matches.
   */
  void CUnitPatrolTaskTypeInfo::AddBase_Listener_EFormationdStatus(gpg::RType* const typeInfo)
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(Listener<EFormationdStatus>));
    }
    gpg::AddBaseIfPresent(typeInfo, sType, 0x44);
  }

  void CUnitPatrolTaskTypeInfo::Init()
  {
    size_ = sizeof(CUnitPatrolTask);
    gpg::RType::Init();
    AddBase_CCommandTask(this);
    AddBase_Listener_ECommandEvent(this);
    AddBase_Listener_EFormationdStatus(this);
    Finish();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_CUnitPatrolTaskTypeInfo_fdce9d, moho::preregister_CUnitPatrolTaskTypeInfo)

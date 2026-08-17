#include "moho/ai/IAiCommandDispatchImplTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiCommandDispatchImpl.h"
#include "moho/misc/Listener.h"
#include "moho/task/CCommandTask.h"
#include "moho/unit/EUnitCommandQueueStatus.h"
#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  alignas(IAiCommandDispatchImplTypeInfo)
  unsigned char gIAiCommandDispatchImplTypeInfoStorage[sizeof(IAiCommandDispatchImplTypeInfo)] = {};
  bool gIAiCommandDispatchImplTypeInfoConstructed = false;

  [[nodiscard]] IAiCommandDispatchImplTypeInfo* AcquireIAiCommandDispatchImplTypeInfo()
  {
    return reinterpret_cast<IAiCommandDispatchImplTypeInfo*>(gIAiCommandDispatchImplTypeInfoStorage);
  }

  /**
   * Address: 0x00599130 (FUN_00599130, constructor lane for IAiCommandDispatchImplTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `IAiCommandDispatchImplTypeInfo` storage and
   * preregisters RTTI for `IAiCommandDispatchImpl`.
   */
  [[nodiscard]] gpg::RType* construct_IAiCommandDispatchImplTypeInfo()
  {
    if (!gIAiCommandDispatchImplTypeInfoConstructed) {
      IAiCommandDispatchImplTypeInfo* const typeInfo =
        new (gIAiCommandDispatchImplTypeInfoStorage) IAiCommandDispatchImplTypeInfo();
      gpg::PreRegisterRType(typeid(IAiCommandDispatchImpl), typeInfo);
      gIAiCommandDispatchImplTypeInfoConstructed = true;
    }

    return AcquireIAiCommandDispatchImplTypeInfo();
  }

  /**
   * Address: 0x00BF6660 (FUN_00BF6660, cleanup_IAiCommandDispatchImplTypeInfo)
   *
   * What it does:
   * Tears down startup-owned IAiCommandDispatchImpl type-info storage by
   * running the `gpg::RType` destructor lane.
   */
  void cleanup_IAiCommandDispatchImplTypeInfoStorage()
  {
    if (!gIAiCommandDispatchImplTypeInfoConstructed) {
      return;
    }

    AcquireIAiCommandDispatchImplTypeInfo()->gpg::RType::~RType();
    gIAiCommandDispatchImplTypeInfoConstructed = false;
  }

  [[nodiscard]] gpg::RType* CachedCCommandTaskType()
  {
    gpg::RType* type = CCommandTask::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CCommandTask));
      CCommandTask::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedIAiCommandDispatchType()
  {
    gpg::RType* type = IAiCommandDispatch::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IAiCommandDispatch));
      IAiCommandDispatch::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedQueueStatusListenerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(Listener<EUnitCommandQueueStatus>));
    }
    return type;
  }

} // namespace

/**
 * Address: 0x005991D0 (FUN_005991D0, scalar deleting thunk)
 */
IAiCommandDispatchImplTypeInfo::~IAiCommandDispatchImplTypeInfo() = default;

/**
 * Address: 0x005991C0 (FUN_005991C0, ?GetName@IAiCommandDispatchImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* IAiCommandDispatchImplTypeInfo::GetName() const
{
  return "IAiCommandDispatchImpl";
}

namespace
{
  /**
   * Address: 0x005998B0 (FUN_005998B0,
   *   Moho::IAiCommandDispatchImplTypeInfo::AddBase_CCommandTask)
   *
   * What it does:
   * Registers `Moho::CCommandTask` as a reflected base of `typeInfo`
   * at subobject offset 0x00.
   */
  void AddBase_CCommandTask(gpg::RType* const typeInfo)
  {
    AddBaseIfPresent(typeInfo, CachedCCommandTaskType(), 0x00);
  }

  /**
   * Address: 0x00599910 (FUN_00599910,
   *   Moho::IAiCommandDispatchImplTypeInfo::AddBase_IAiCommandDispatch)
   *
   * What it does:
   * Registers `Moho::IAiCommandDispatch` as a reflected base of `typeInfo`
   * at subobject offset 0x30.
   */
  void AddBase_IAiCommandDispatch(gpg::RType* const typeInfo)
  {
    AddBaseIfPresent(typeInfo, CachedIAiCommandDispatchType(), 0x30);
  }

  /**
   * Address: 0x00599970 (FUN_00599970,
   *   Moho::IAiCommandDispatchImplTypeInfo::AddBase_Listener_EUnitCommandQueueStatus)
   *
   * What it does:
   * Registers `Moho::Listener<EUnitCommandQueueStatus>` as a reflected base of `typeInfo`
   * at subobject offset 0x34.
   */
  void AddBase_Listener_EUnitCommandQueueStatus(gpg::RType* const typeInfo)
  {
    AddBaseIfPresent(typeInfo, CachedQueueStatusListenerType(), 0x34);
  }

} // namespace

/**
 * Address: 0x00599190 (FUN_00599190, ?Init@IAiCommandDispatchImplTypeInfo@Moho@@UAEXXZ)
 */
void IAiCommandDispatchImplTypeInfo::Init()
{
  size_ = sizeof(IAiCommandDispatchImpl);
  gpg::RType::Init();

  AddBase_CCommandTask(this);
  AddBase_IAiCommandDispatch(this);
  AddBase_Listener_EUnitCommandQueueStatus(this);

  Finish();
}

/**
 * Address: 0x00BCBEA0 (FUN_00BCBEA0, register_IAiCommandDispatchImplTypeInfo)
 *
 * What it does:
 * Constructs/preregisters startup RTTI storage for
 * `IAiCommandDispatchImpl` and installs process-exit cleanup.
 */
int moho::register_IAiCommandDispatchImplTypeInfo()
{
  (void)construct_IAiCommandDispatchImplTypeInfo();
  return std::atexit(&cleanup_IAiCommandDispatchImplTypeInfoStorage);
}

namespace
{
  struct IAiCommandDispatchImplTypeInfoBootstrap
  {
    IAiCommandDispatchImplTypeInfoBootstrap()
    {
      (void)moho::register_IAiCommandDispatchImplTypeInfo();
    }
  };

  [[maybe_unused]] IAiCommandDispatchImplTypeInfoBootstrap gIAiCommandDispatchImplTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_IAiCommandDispatchImplTypeInfo_aaf8a9, moho::register_IAiCommandDispatchImplTypeInfo)

GPG_PREREGISTER_INIT(construct_IAiCommandDispatchImplTypeInfo_aaf8a9, construct_IAiCommandDispatchImplTypeInfo)

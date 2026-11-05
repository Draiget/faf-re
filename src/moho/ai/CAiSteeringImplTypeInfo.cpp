#include "moho/ai/CAiSteeringImplTypeInfo.h"
#include "gpg/core/reflection/Reflection.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSteeringImpl.h"

#include "gpg/core/reflection/StaticInitPhase.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x00BF8130 (FUN_00BF8130, atexit destructor of the CAiSteeringImplTypeInfo object)
   */
  [[nodiscard]] CAiSteeringImplTypeInfo* AcquireCAiSteeringImplTypeInfo()
  {
    static CAiSteeringImplTypeInfo sInstance;
    return &sInstance;
  }

  /**
   * Address: 0x005D4270 (FUN_005D4270, Moho::CAiSteeringImplTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CAiSteeringImpl`, runs constructor initialization, and
   * returns a typed reflection reference.
   */
  [[nodiscard]] gpg::RRef CreateAiSteeringImplRefOwned()
  {
    return gpg::MakeTypedRef(new CAiSteeringImpl(), gpg::CachedLookup<CAiSteeringImpl>(CAiSteeringImpl::sType));
  }

  void DeleteAiSteeringImplOwned(void* object)
  {
    delete static_cast<CAiSteeringImpl*>(object);
  }

  void DestroyAiSteeringImplInPlace(void* object)
  {
    auto* const steering = static_cast<CAiSteeringImpl*>(object);
    if (steering) {
      steering->~CAiSteeringImpl();
    }
  }

  /**
   * Address: 0x005D3DC0 (FUN_005D3DC0)
   *
   * What it does:
   * Assigns all lifecycle callback slots (`NewRef`, `CtrRef`, `Delete`,
   * `Destruct`) on one `CAiSteeringImplTypeInfo` descriptor.
   */
  [[maybe_unused]] [[nodiscard]] CAiSteeringImplTypeInfo* AssignCAiSteeringImplLifecycleCallbacks(
    CAiSteeringImplTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->newRefFunc_ = &CreateAiSteeringImplRefOwned;
    typeInfo->ctorRefFunc_ = &CAiSteeringImplTypeInfo::CtrRef;
    typeInfo->deleteFunc_ = &DeleteAiSteeringImplOwned;
    typeInfo->dtrFunc_ = &DestroyAiSteeringImplInPlace;
    return typeInfo;
  }

  struct CAiSteeringImplTypeInfoBootstrap
  {
    CAiSteeringImplTypeInfoBootstrap()
    {
      (void)moho::register_CAiSteeringImplTypeInfo();
    }
  };

  [[maybe_unused]] CAiSteeringImplTypeInfoBootstrap gCAiSteeringImplTypeInfoBootstrap;
} // namespace

/**
 * Address: 0x005D22A0 (FUN_005D22A0, scalar deleting thunk)
 */
CAiSteeringImplTypeInfo::~CAiSteeringImplTypeInfo() = default;

/**
 * Address: 0x005D21E0 (FUN_005D21E0, ??0CAiSteeringImplTypeInfo@Moho@@QAE@@Z)
 *
 * What it does:
 * Preregisters `CAiSteeringImpl` RTTI so lookup resolves to this type helper.
 */
CAiSteeringImplTypeInfo::CAiSteeringImplTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiSteeringImpl), this);
}

/**
 * Address: 0x005D2290 (FUN_005D2290, ?GetName@CAiSteeringImplTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiSteeringImplTypeInfo::GetName() const
{
  return "CAiSteeringImpl";
}

/**
 * Address: 0x005D44D0 (FUN_005D44D0, Moho::CAiSteeringImplTypeInfo::AddBase_IAiSteering)
 */
void CAiSteeringImplTypeInfo::AddBase_IAiSteering(gpg::RType* const typeInfo)
{
  gpg::AddBaseIfPresent(typeInfo, gpg::RTypeOf<IAiSteering>(), 0);
}

/**
 * Address: 0x005D4530 (FUN_005D4530, Moho::CAiSteeringImplTypeInfo::AddBase_CTask)
 *
 * Offset 4: CTask is the second base, after IAiSteering at 0.
 */
void CAiSteeringImplTypeInfo::AddBase_CTask(gpg::RType* const typeInfo)
{
  gpg::AddBaseIfPresent(typeInfo, gpg::RTypeOf<CTask>(), gpg::BaseSubobjectOffset<CAiSteeringImpl, CTask>());
}

/**
 * Address: 0x005D2240 (FUN_005D2240, ?Init@CAiSteeringImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiSteeringImplTypeInfo::Init()
{
  size_ = sizeof(CAiSteeringImpl);
  (void)AssignCAiSteeringImplLifecycleCallbacks(this);
  gpg::RType::Init();
  AddBase_IAiSteering(this);
  AddBase_CTask(this);
  Finish();
}

/**
 * Address: 0x005D4310 (FUN_005D4310, Moho::CAiSteeringImplTypeInfo::CtrRef)
 *
 * What it does:
 * Placement-constructs one `CAiSteeringImpl` in caller storage and returns a
 * typed reflection reference.
 */
gpg::RRef CAiSteeringImplTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const steering = gpg::ConstructInStorage<CAiSteeringImpl>(objectStorage);
  return gpg::MakeTypedRef(steering, gpg::CachedLookup<CAiSteeringImpl>(CAiSteeringImpl::sType));
}

/**
 * Address: 0x00BCE480 (FUN_00BCE480, register_CAiSteeringImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiSteeringImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
void moho::register_CAiSteeringImplTypeInfo()
{
  CAiSteeringImplTypeInfo* const typeInfo = AcquireCAiSteeringImplTypeInfo();
  CAiSteeringImpl::sType = typeInfo;
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_CAiSteeringImplTypeInfo_8b6b3f, moho::register_CAiSteeringImplTypeInfo)

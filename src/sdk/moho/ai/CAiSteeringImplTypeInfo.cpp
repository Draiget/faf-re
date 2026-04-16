#include "moho/ai/CAiSteeringImplTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiSteeringImpl.h"

using namespace moho;

namespace
{
  alignas(CAiSteeringImplTypeInfo) unsigned char gCAiSteeringImplTypeInfoStorage[sizeof(CAiSteeringImplTypeInfo)];
  bool gCAiSteeringImplTypeInfoConstructed = false;

  [[nodiscard]] CAiSteeringImplTypeInfo* AcquireCAiSteeringImplTypeInfo()
  {
    if (!gCAiSteeringImplTypeInfoConstructed) {
      new (gCAiSteeringImplTypeInfoStorage) CAiSteeringImplTypeInfo();
      gCAiSteeringImplTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiSteeringImplTypeInfo*>(gCAiSteeringImplTypeInfoStorage);
  }

  /**
   * Address: 0x005D4220 (FUN_005D4220)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for `CAiSteeringImpl`.
   */
  [[nodiscard]] gpg::RType* CachedCAiSteeringImplType()
  {
    if (!CAiSteeringImpl::sType) {
      CAiSteeringImpl::sType = gpg::LookupRType(typeid(CAiSteeringImpl));
    }
    return CAiSteeringImpl::sType;
  }

  [[nodiscard]] gpg::RType* CachedIAiSteeringType()
  {
    if (!IAiSteering::sType) {
      IAiSteering::sType = gpg::LookupRType(typeid(IAiSteering));
    }
    return IAiSteering::sType;
  }

  [[nodiscard]] gpg::RType* CachedCTaskType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(CTask));
    }
    return cached;
  }

  template <typename T>
  [[nodiscard]] gpg::RRef MakeTypedRef(T* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
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
    return MakeTypedRef(new CAiSteeringImpl(), CachedCAiSteeringImplType());
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

  void AddIAiSteeringBase(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedIAiSteeringType();
    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 0;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  void AddCTaskBase(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedCTaskType();
    gpg::RField field{};
    field.mName = baseType->GetName();
    field.mType = baseType;
    field.mOffset = 4;
    field.v4 = 0;
    field.mDesc = nullptr;
    typeInfo->AddBase(field);
  }

  /**
   * Address: 0x00BF8130 (FUN_00BF8130, cleanup_CAiSteeringImplTypeInfo)
   *
   * What it does:
   * Tears down recovered static `CAiSteeringImplTypeInfo` storage.
   */
  void cleanup_CAiSteeringImplTypeInfo()
  {
    if (!gCAiSteeringImplTypeInfoConstructed) {
      return;
    }

    AcquireCAiSteeringImplTypeInfo()->~CAiSteeringImplTypeInfo();
    gCAiSteeringImplTypeInfoConstructed = false;
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
 * Address: 0x005D2240 (FUN_005D2240, ?Init@CAiSteeringImplTypeInfo@Moho@@UAEXXZ)
 */
void CAiSteeringImplTypeInfo::Init()
{
  size_ = sizeof(CAiSteeringImpl);
  (void)AssignCAiSteeringImplLifecycleCallbacks(this);
  gpg::RType::Init();
  AddIAiSteeringBase(this);
  AddCTaskBase(this);
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
  auto* const steering = static_cast<CAiSteeringImpl*>(objectStorage);
  if (steering) {
    new (steering) CAiSteeringImpl();
  }
  return MakeTypedRef(steering, CachedCAiSteeringImplType());
}

/**
 * Address: 0x00BCE480 (FUN_00BCE480, register_CAiSteeringImplTypeInfo)
 *
 * What it does:
 * Constructs startup-owned `CAiSteeringImplTypeInfo` storage and installs
 * process-exit cleanup.
 */
int moho::register_CAiSteeringImplTypeInfo()
{
  CAiSteeringImplTypeInfo* const typeInfo = AcquireCAiSteeringImplTypeInfo();
  CAiSteeringImpl::sType = typeInfo;
  return std::atexit(&cleanup_CAiSteeringImplTypeInfo);
}

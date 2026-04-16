#include "moho/ai/CAiPathNavigatorTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CAiPathNavigator.h"
#include "moho/misc/Listener.h"

using namespace moho;

namespace
{
  alignas(CAiPathNavigatorTypeInfo) unsigned char gCAiPathNavigatorTypeInfoStorage[sizeof(CAiPathNavigatorTypeInfo)] = {};
  bool gCAiPathNavigatorTypeInfoConstructed = false;
  gpg::RType* gListenerNavPathType = nullptr;

  /**
   * Address: 0x005B0380 (FUN_005B0380)
   *
   * What it does:
   * Wires the allocation callbacks used by `CAiPathNavigatorTypeInfo`.
   */
  [[maybe_unused]] void BindCAiPathNavigatorTypeInfoConstructionCallbacks(CAiPathNavigatorTypeInfo& typeInfo)
  {
    typeInfo.newRefFunc_ = &CAiPathNavigatorTypeInfo::NewRef;
    typeInfo.ctorRefFunc_ = &CAiPathNavigatorTypeInfo::CtrRef;
  }

  /**
   * Address: 0x005B0390 (FUN_005B0390)
   *
   * What it does:
   * Wires the destruction callbacks used by `CAiPathNavigatorTypeInfo`.
   */
  [[maybe_unused]] void BindCAiPathNavigatorTypeInfoDestructionCallbacks(CAiPathNavigatorTypeInfo& typeInfo)
  {
    typeInfo.deleteFunc_ = &CAiPathNavigatorTypeInfo::Delete;
    typeInfo.dtrFunc_ = &CAiPathNavigatorTypeInfo::Destruct;
  }

  /**
   * Address: 0x005B00E0 (FUN_005B00E0)
   *
   * What it does:
   * Wires the full callback set used by `CAiPathNavigatorTypeInfo`.
   */
  void BindCAiPathNavigatorTypeInfoCallbacks(CAiPathNavigatorTypeInfo& typeInfo)
  {
    typeInfo.newRefFunc_ = &CAiPathNavigatorTypeInfo::NewRef;
    typeInfo.ctorRefFunc_ = &CAiPathNavigatorTypeInfo::CtrRef;
    typeInfo.deleteFunc_ = &CAiPathNavigatorTypeInfo::Delete;
    typeInfo.dtrFunc_ = &CAiPathNavigatorTypeInfo::Destruct;
  }

  /**
   * Address: 0x005B0AE0 (FUN_005B0AE0)
   *
   * What it does:
   * Builds a reflected `RRef` for one `CAiPathNavigator` into caller storage.
   */
  gpg::RRef* PopulateCAiPathNavigatorRef(gpg::RRef* const out, CAiPathNavigator* const value)
  {
    gpg::RRef temp{};
    gpg::RRef_CAiPathNavigator(&temp, value);
    *out = temp;
    return out;
  }

  [[nodiscard]] CAiPathNavigatorTypeInfo* AcquireCAiPathNavigatorTypeInfo()
  {
    if (!gCAiPathNavigatorTypeInfoConstructed) {
      new (gCAiPathNavigatorTypeInfoStorage) CAiPathNavigatorTypeInfo();
      gCAiPathNavigatorTypeInfoConstructed = true;
    }

    return reinterpret_cast<CAiPathNavigatorTypeInfo*>(gCAiPathNavigatorTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedListenerNavPathType()
  {
    if (!gListenerNavPathType) {
      gListenerNavPathType = gpg::LookupRType(typeid(moho::Listener<const moho::SNavPath&>));
    }
    return gListenerNavPathType;
  }

  /**
   * Address: 0x00BF7360 (FUN_00BF7360, cleanup_CAiPathNavigatorTypeInfo)
   *
   * What it does:
   * Tears down the recovered static `CAiPathNavigatorTypeInfo` storage.
   */
  void cleanup_CAiPathNavigatorTypeInfo()
  {
    if (!gCAiPathNavigatorTypeInfoConstructed) {
      return;
    }

    AcquireCAiPathNavigatorTypeInfo()->~CAiPathNavigatorTypeInfo();
    gCAiPathNavigatorTypeInfoConstructed = false;
  }
} // namespace

/**
 * Address: 0x005AFA70 (FUN_005AFA70, ??0CAiPathNavigatorTypeInfo@Moho@@QAE@XZ)
 *
 * What it does:
 * Preregisters `CAiPathNavigator` RTTI for this type-info helper.
 */
CAiPathNavigatorTypeInfo::CAiPathNavigatorTypeInfo()
  : gpg::RType()
{
  gpg::PreRegisterRType(typeid(CAiPathNavigator), this);
}

/**
 * Address: 0x005AFB30 (FUN_005AFB30, scalar deleting thunk)
 */
CAiPathNavigatorTypeInfo::~CAiPathNavigatorTypeInfo() = default;

/**
 * Address: 0x005AFB20 (FUN_005AFB20, ?GetName@CAiPathNavigatorTypeInfo@Moho@@UBEPBDXZ)
 */
const char* CAiPathNavigatorTypeInfo::GetName() const
{
  return "CAiPathNavigator";
}

/**
 * Address: 0x005AFAD0 (FUN_005AFAD0, ?Init@CAiPathNavigatorTypeInfo@Moho@@UAEXXZ)
 */
void CAiPathNavigatorTypeInfo::Init()
{
  size_ = sizeof(CAiPathNavigator);
  BindCAiPathNavigatorTypeInfoCallbacks(*this);
  gpg::RType::Init();
  AddBase_Listener_NavPath(this);
  Version(1);
  Finish();
}

/**
 * Address: 0x005B0930 (FUN_005B0930, Moho::CAiPathNavigatorTypeInfo::AddBase_Listener_NavPath)
 */
void __stdcall CAiPathNavigatorTypeInfo::AddBase_Listener_NavPath(gpg::RType* const typeInfo)
{
  gpg::RType* const baseType = CachedListenerNavPathType();

  gpg::RField baseField{};
  baseField.mName = baseType->GetName();
  baseField.mType = baseType;
  baseField.mOffset = 0;
  baseField.v4 = 0;
  baseField.mDesc = nullptr;
  typeInfo->AddBase(baseField);
}

/**
 * Address: 0x005B0740 (FUN_005B0740, Moho::CAiPathNavigatorTypeInfo::NewRef)
 *
 * What it does:
 * Allocates one detached `CAiPathNavigator` and returns a typed reflection
 * reference for it.
 */
gpg::RRef CAiPathNavigatorTypeInfo::NewRef()
{
  auto* const navigator = new (std::nothrow) CAiPathNavigator();
  gpg::RRef out{};
  PopulateCAiPathNavigatorRef(&out, navigator);
  return out;
}

/**
 * Address: 0x005B07E0 (FUN_005B07E0, Moho::CAiPathNavigatorTypeInfo::CtrRef)
 *
 * What it does:
 * Constructs one detached `CAiPathNavigator` in caller-provided storage and
 * returns a typed reflection reference for it.
 */
gpg::RRef CAiPathNavigatorTypeInfo::CtrRef(void* const objectStorage)
{
  auto* const navigator = static_cast<CAiPathNavigator*>(objectStorage);
  if (navigator) {
    new (navigator) CAiPathNavigator();
  }

  gpg::RRef out{};
  PopulateCAiPathNavigatorRef(&out, navigator);
  return out;
}

/**
 * Address: 0x005B07C0 (FUN_005B07C0, Moho::CAiPathNavigatorTypeInfo::Delete)
 */
void CAiPathNavigatorTypeInfo::Delete(void* const objectStorage)
{
  delete static_cast<CAiPathNavigator*>(objectStorage);
}

/**
 * Address: 0x005B0850 (FUN_005B0850, Moho::CAiPathNavigatorTypeInfo::Destruct)
 */
void CAiPathNavigatorTypeInfo::Destruct(void* const objectStorage)
{
  static_cast<CAiPathNavigator*>(objectStorage)->~CAiPathNavigator();
}

/**
 * Address: 0x00BCD020 (FUN_00BCD020, register_CAiPathNavigatorTypeInfo)
 *
 * What it does:
 * Forces startup construction of `CAiPathNavigatorTypeInfo` and installs
 * process-exit cleanup.
 */
void moho::register_CAiPathNavigatorTypeInfo()
{
  (void)AcquireCAiPathNavigatorTypeInfo();
  (void)std::atexit(&cleanup_CAiPathNavigatorTypeInfo);
}

namespace
{
  struct CAiPathNavigatorTypeInfoBootstrap
  {
    CAiPathNavigatorTypeInfoBootstrap()
    {
      moho::register_CAiPathNavigatorTypeInfo();
    }
  };

  [[maybe_unused]] CAiPathNavigatorTypeInfoBootstrap gCAiPathNavigatorTypeInfoBootstrap;
} // namespace

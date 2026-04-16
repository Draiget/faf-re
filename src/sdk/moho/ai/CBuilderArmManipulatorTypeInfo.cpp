#include "moho/ai/CBuilderArmManipulatorTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/ai/CBuilderArmManipulator.h"
#include "moho/animation/IAniManipulator.h"

namespace moho
{
  gpg::RType* CBuilderArmManipulator::sType = nullptr;
}

namespace
{
  using TypeInfo = moho::CBuilderArmManipulatorTypeInfo;

  alignas(TypeInfo) unsigned char gCBuilderArmManipulatorTypeInfoStorage[sizeof(TypeInfo)];
  bool gCBuilderArmManipulatorTypeInfoConstructed = false;

  /**
   * Address: 0x00635990 (FUN_00635990, bootstrap ctor lane)
   *
   * What it does:
   * Constructs startup-owned `CBuilderArmManipulatorTypeInfo` storage and
   * preregisters `CBuilderArmManipulator` RTTI binding.
   */
  [[nodiscard]] TypeInfo& AcquireTypeInfo()
  {
    if (!gCBuilderArmManipulatorTypeInfoConstructed) {
      auto* const typeInfo = new (gCBuilderArmManipulatorTypeInfoStorage) TypeInfo();
      gpg::PreRegisterRType(typeid(moho::CBuilderArmManipulator), typeInfo);
      gCBuilderArmManipulatorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCBuilderArmManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00BFAA60 (FUN_00BFAA60, cleanup_CBuilderArmManipulatorTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `CBuilderArmManipulatorTypeInfo` storage.
   */
  void cleanup_CBuilderArmManipulatorTypeInfo()
  {
    if (!gCBuilderArmManipulatorTypeInfoConstructed) {
      return;
    }

    AcquireTypeInfo().~TypeInfo();
    gCBuilderArmManipulatorTypeInfoConstructed = false;
  }

  /**
   * Address: 0x006358F0 (FUN_006358F0)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for
   * `CBuilderArmManipulator`.
   */
  [[nodiscard]] gpg::RType* ResolveCBuilderArmManipulatorTypeCachePrimary()
  {
    gpg::RType* type = moho::CBuilderArmManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CBuilderArmManipulator));
      moho::CBuilderArmManipulator::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00636F10 (FUN_00636F10)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches
   * `CBuilderArmManipulator` reflection type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveCBuilderArmManipulatorTypeCacheSecondary()
  {
    gpg::RType* type = moho::CBuilderArmManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CBuilderArmManipulator));
      moho::CBuilderArmManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* CachedCBuilderArmManipulatorType()
  {
    return ResolveCBuilderArmManipulatorTypeCachePrimary();
  }

  [[nodiscard]] gpg::RType* CachedIAniManipulatorType()
  {
    gpg::RType* type = moho::IAniManipulator::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::IAniManipulator));
      moho::IAniManipulator::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RRef MakeBuilderArmManipulatorRef(moho::CBuilderArmManipulator* const object)
  {
    gpg::RRef out{};
    out.mObj = object;
    out.mType = CachedCBuilderArmManipulatorType();
    return out;
  }

  struct CBuilderArmManipulatorTypeInfoBootstrap
  {
    CBuilderArmManipulatorTypeInfoBootstrap()
    {
      (void)moho::register_CBuilderArmManipulatorTypeInfo();
    }
  };

  [[maybe_unused]] CBuilderArmManipulatorTypeInfoBootstrap gCBuilderArmManipulatorTypeInfoBootstrap{};
} // namespace

namespace moho
{
  /**
   * Address: 0x00635A40 (FUN_00635A40, scalar deleting thunk)
   */
  /**
   * Address: 0x00635AA0 (FUN_00635AA0, CBuilderArmManipulatorTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Executes one non-deleting destruction lane for
   * `CBuilderArmManipulatorTypeInfo`.
   */
  [[maybe_unused]] void DestroyCBuilderArmManipulatorTypeInfoBody(
    CBuilderArmManipulatorTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->~CBuilderArmManipulatorTypeInfo();
  }

  CBuilderArmManipulatorTypeInfo::~CBuilderArmManipulatorTypeInfo() = default;

  /**
   * Address: 0x00635A30 (FUN_00635A30, Moho::CBuilderArmManipulatorTypeInfo::GetName)
   *
   * What it does:
   * Returns the reflected type-name literal for `CBuilderArmManipulator`.
   */
  const char* CBuilderArmManipulatorTypeInfo::GetName() const
  {
    return "CBuilderArmManipulator";
  }

  /**
   * Address: 0x006359F0 (FUN_006359F0, Moho::CBuilderArmManipulatorTypeInfo::Init)
   *
   * What it does:
   * Sets reflected size/callback lanes, registers reflected
   * `IAniManipulator` base, and finalizes type-info initialization.
   */
  void CBuilderArmManipulatorTypeInfo::Init()
  {
    size_ = sizeof(CBuilderArmManipulator);
    AssignAllLifecycleCallbacks(*this);
    AddBase_IAniManipulator(this);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00636F30 (FUN_00636F30, callback shard)
   *
   * What it does:
   * Assigns all lifecycle callback slots (`NewRef`, `CtrRef`, `Delete`,
   * `Destruct`) on one type descriptor.
   */
  void CBuilderArmManipulatorTypeInfo::AssignAllLifecycleCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo)
  {
    AssignCtorCallbacks(typeInfo);
    AssignDtorCallbacks(typeInfo);
  }

  /**
   * Address: 0x00636FF0 (FUN_00636FF0, callback shard)
   *
   * What it does:
   * Assigns constructor-lane callback slots (`NewRef`, `CtrRef`) on one type
   * descriptor.
   */
  void CBuilderArmManipulatorTypeInfo::AssignCtorCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo)
  {
    typeInfo.newRefFunc_ = &CBuilderArmManipulatorTypeInfo::NewRef;
    typeInfo.ctorRefFunc_ = &CBuilderArmManipulatorTypeInfo::CtrRef;
  }

  /**
   * Address: 0x00637000 (FUN_00637000, callback shard)
   *
   * What it does:
   * Assigns destructor-lane callback slots (`Delete`, `Destruct`) on one
   * type descriptor.
   */
  void CBuilderArmManipulatorTypeInfo::AssignDtorCallbacks(CBuilderArmManipulatorTypeInfo& typeInfo)
  {
    typeInfo.deleteFunc_ = &CBuilderArmManipulatorTypeInfo::Delete;
    typeInfo.dtrFunc_ = &CBuilderArmManipulatorTypeInfo::Destruct;
  }

  /**
   * Address: 0x00637010 (FUN_00637010, Moho::CBuilderArmManipulatorTypeInfo::NewRef)
   *
   * What it does:
   * Allocates one `CBuilderArmManipulator` and returns a typed reflection
   * reference.
   */
  gpg::RRef CBuilderArmManipulatorTypeInfo::NewRef()
  {
    auto* const manipulator = new (std::nothrow) CBuilderArmManipulator();
    return MakeBuilderArmManipulatorRef(manipulator);
  }

  /**
   * Address: 0x006370B0 (FUN_006370B0, Moho::CBuilderArmManipulatorTypeInfo::CtrRef)
   *
   * What it does:
   * Placement-constructs one `CBuilderArmManipulator` in caller storage and
   * returns a typed reflection reference.
   */
  gpg::RRef CBuilderArmManipulatorTypeInfo::CtrRef(void* const objectStorage)
  {
    auto* const manipulator = static_cast<CBuilderArmManipulator*>(objectStorage);
    if (manipulator) {
      new (manipulator) CBuilderArmManipulator();
    }

    return MakeBuilderArmManipulatorRef(manipulator);
  }

  void CBuilderArmManipulatorTypeInfo::Delete(void* const objectStorage)
  {
    delete static_cast<CBuilderArmManipulator*>(objectStorage);
  }

  void CBuilderArmManipulatorTypeInfo::Destruct(void* const objectStorage)
  {
    auto* const manipulator = static_cast<CBuilderArmManipulator*>(objectStorage);
    if (!manipulator) {
      return;
    }

    manipulator->~CBuilderArmManipulator();
  }

  void CBuilderArmManipulatorTypeInfo::AddBase_IAniManipulator(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00BD2590 (FUN_00BD2590, register_CBuilderArmManipulatorTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `CBuilderArmManipulatorTypeInfo` storage and
   * installs process-exit cleanup.
   */
  int register_CBuilderArmManipulatorTypeInfo()
  {
    (void)AcquireTypeInfo();
    return std::atexit(&cleanup_CBuilderArmManipulatorTypeInfo);
  }
} // namespace moho

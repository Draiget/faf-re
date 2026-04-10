#include "moho/entity/CollisionBeamEntity.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace
{
  using TypeInfo = moho::CollisionBeamEntityTypeInfo;

  alignas(TypeInfo) unsigned char gCollisionBeamEntityTypeInfoStorage[sizeof(TypeInfo)];
  bool gCollisionBeamEntityTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& GetCollisionBeamEntityTypeInfo() noexcept
  {
    if (!gCollisionBeamEntityTypeInfoConstructed) {
      new (gCollisionBeamEntityTypeInfoStorage) TypeInfo();
      gCollisionBeamEntityTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gCollisionBeamEntityTypeInfoStorage);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00673720 (FUN_00673720, Moho::CollisionBeamEntityTypeInfo::CollisionBeamEntityTypeInfo)
   */
  CollisionBeamEntityTypeInfo::CollisionBeamEntityTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CollisionBeamEntity), this);
  }

  /**
   * Address: 0x006737C0 (FUN_006737C0, Moho::CollisionBeamEntityTypeInfo::dtr)
   */
  CollisionBeamEntityTypeInfo::~CollisionBeamEntityTypeInfo() = default;

  /**
   * Address: 0x006737B0 (FUN_006737B0, Moho::CollisionBeamEntityTypeInfo::GetName)
   */
  const char* CollisionBeamEntityTypeInfo::GetName() const
  {
    return "CollisionBeamEntity";
  }

  /**
   * Address: 0x00673780 (FUN_00673780, Moho::CollisionBeamEntityTypeInfo::Init)
   */
  void CollisionBeamEntityTypeInfo::Init()
  {
    size_ = sizeof(CollisionBeamEntity);
    AddBase_Entity(this);
    gpg::RType::Init();
    Finish();
  }

  void CollisionBeamEntityTypeInfo::AddBase_Entity(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = gpg::LookupRType(typeid(Entity));

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * What it does:
   * Releases startup-owned `CollisionBeamEntityTypeInfo` storage at process teardown.
   */
  void cleanup_CollisionBeamEntityTypeInfo()
  {
    if (!gCollisionBeamEntityTypeInfoConstructed) {
      return;
    }

    GetCollisionBeamEntityTypeInfo().~CollisionBeamEntityTypeInfo();
    gCollisionBeamEntityTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD4C40 (FUN_00BD4C40, register_CollisionBeamEntityTypeInfo)
   */
  int register_CollisionBeamEntityTypeInfo()
  {
    (void)GetCollisionBeamEntityTypeInfo();
    return std::atexit(&cleanup_CollisionBeamEntityTypeInfo);
  }
} // namespace moho

namespace
{
  struct CollisionBeamEntityTypeInfoBootstrap
  {
    CollisionBeamEntityTypeInfoBootstrap()
    {
      (void)moho::register_CollisionBeamEntityTypeInfo();
    }
  };

  [[maybe_unused]] CollisionBeamEntityTypeInfoBootstrap gCollisionBeamEntityTypeInfoBootstrap;
} // namespace

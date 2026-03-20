#include "moho/entity/EntityCategoryReflection.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/containers/BVIntSet.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedBVIntSetType()
  {
    if (!moho::BVIntSet::sType) {
      moho::BVIntSet::sType = gpg::LookupRType(typeid(moho::BVIntSet));
    }
    return moho::BVIntSet::sType;
  }

  [[nodiscard]] const gpg::RRef& NullOwnerRef()
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  moho::EntityCategoryHelperTypeInfo gEntityCategoryHelperTypeInfo;
  moho::EntityCategoryHelperSerializer gEntityCategoryHelperSerializer;

  struct EntityCategoryHelperRegistration
  {
    EntityCategoryHelperRegistration()
    {
      gpg::PreRegisterRType(typeid(moho::EntityCategoryHelper), &gEntityCategoryHelperTypeInfo);
      gEntityCategoryHelperSerializer.mNext = nullptr;
      gEntityCategoryHelperSerializer.mPrev = nullptr;
      gEntityCategoryHelperSerializer.mSerLoadFunc = &moho::EntityCategory::SerLoad;
      gEntityCategoryHelperSerializer.mSerSaveFunc = &moho::EntityCategory::SerSave;
      gEntityCategoryHelperSerializer.RegisterSerializeFunctions();
    }
  };

  EntityCategoryHelperRegistration gEntityCategoryHelperRegistration;
} // namespace

namespace moho
{
  gpg::RType* EntityCategoryHelper::sType = nullptr;

  gpg::RType* EntityCategoryHelper::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(EntityCategoryHelper));
    }
    return sType;
  }

  /**
   * Address: 0x005567F0 (FUN_005567F0, Moho::EntityCategory::SerSave)
   */
  void EntityCategory::SerSave(gpg::WriteArchive* archive, const int objectPtr, const int, gpg::RRef* ownerRef)
  {
    auto* const set = reinterpret_cast<EntityCategorySet*>(objectPtr);
    GPG_ASSERT(set != nullptr);
    if (!set) {
      return;
    }

    auto* const helper = reinterpret_cast<EntityCategoryHelper*>(set);
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();

    archive->Write(EntityCategoryHelper::StaticGetClass(), helper, owner);
    archive->Write(CachedBVIntSetType(), &set->mBits, NullOwnerRef());
  }

  /**
   * Address: 0x00556870 (FUN_00556870, Moho::EntityCategory::SerLoad)
   */
  void EntityCategory::SerLoad(gpg::ReadArchive* archive, const int objectPtr, const int, gpg::RRef* ownerRef)
  {
    auto* const set = reinterpret_cast<EntityCategorySet*>(objectPtr);
    GPG_ASSERT(set != nullptr);
    if (!set) {
      return;
    }

    auto* const helper = reinterpret_cast<EntityCategoryHelper*>(set);
    const gpg::RRef owner = ownerRef ? *ownerRef : NullOwnerRef();

    archive->Read(EntityCategoryHelper::StaticGetClass(), helper, owner);
    archive->Read(CachedBVIntSetType(), &set->mBits, NullOwnerRef());
  }

  /**
   * Address: 0x0052B7B0 (FUN_0052B7B0, deleting dtor thunk)
   */
  EntityCategoryHelperTypeInfo::~EntityCategoryHelperTypeInfo() = default;

  /**
   * Address: 0x0052B7A0 (FUN_0052B7A0, Moho::EntityCategoryHelperTypeInfo::GetName)
   */
  const char* EntityCategoryHelperTypeInfo::GetName() const
  {
    return "EntityCategoryHelper";
  }

  /**
   * Address: 0x0052B780 (FUN_0052B780, Moho::EntityCategoryHelperTypeInfo::Init)
   */
  void EntityCategoryHelperTypeInfo::Init()
  {
    size_ = sizeof(EntityCategoryHelper);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0052C8E0 (FUN_0052C8E0, gpg::SerSaveLoadHelper_EntityCategoryHelper::Init)
   */
  void EntityCategoryHelperSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = EntityCategoryHelper::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho

#include "moho/entity/EntityCategoryReflection.h"

#include <cstdlib>
#include <new>
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

  alignas(moho::EntityCategoryHelperTypeInfo)
    unsigned char gEntityCategoryHelperTypeInfoStorage[sizeof(moho::EntityCategoryHelperTypeInfo)];
  bool gEntityCategoryHelperTypeInfoConstructed = false;

  moho::EntityCategoryHelperSerializer gEntityCategoryHelperSerializer;

  [[nodiscard]] moho::EntityCategoryHelperTypeInfo& AcquireEntityCategoryHelperTypeInfo()
  {
    if (!gEntityCategoryHelperTypeInfoConstructed) {
      new (gEntityCategoryHelperTypeInfoStorage) moho::EntityCategoryHelperTypeInfo();
      gEntityCategoryHelperTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::EntityCategoryHelperTypeInfo*>(gEntityCategoryHelperTypeInfoStorage);
  }

  void cleanup_EntityCategoryHelperTypeInfo()
  {
    if (!gEntityCategoryHelperTypeInfoConstructed) {
      return;
    }

    AcquireEntityCategoryHelperTypeInfo().~EntityCategoryHelperTypeInfo();
    gEntityCategoryHelperTypeInfoConstructed = false;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    auto* const next = static_cast<gpg::SerHelperBase*>(helper.mNext);
    auto* const prev = static_cast<gpg::SerHelperBase*>(helper.mPrev);
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mPrev = self;
    helper.mNext = self;
    return self;
  }

  void cleanup_EntityCategoryHelperSerializerAtexit()
  {
    gEntityCategoryHelperSerializer.~EntityCategoryHelperSerializer();
  }

  struct EntityCategoryHelperRegistration
  {
    EntityCategoryHelperRegistration()
    {
      (void)moho::register_EntityCategoryHelperTypeInfoStartup();
      moho::register_EntityCategoryHelperSerializer();
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
   * Address: 0x0052B720 (FUN_0052B720, Moho::EntityCategoryHelperTypeInfo::EntityCategoryHelperTypeInfo)
   */
  EntityCategoryHelperTypeInfo::EntityCategoryHelperTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntityCategoryHelper), this);
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
   * Address: 0x00BF3AD0 (FUN_00BF3AD0, Moho::EntityCategoryHelperSerializer::dtr)
   */
  EntityCategoryHelperSerializer::~EntityCategoryHelperSerializer()
  {
    (void)UnlinkHelperNode(gEntityCategoryHelperSerializer);
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

  /**
   * Address: 0x00BC8F10 (FUN_00BC8F10, register_EntityCategoryHelperTypeInfoStartup)
   */
  int register_EntityCategoryHelperTypeInfoStartup()
  {
    (void)AcquireEntityCategoryHelperTypeInfo();
    return std::atexit(&cleanup_EntityCategoryHelperTypeInfo);
  }

  /**
   * Address: 0x00BC8F30 (FUN_00BC8F30, register_EntityCategoryHelperSerializer)
   */
  void register_EntityCategoryHelperSerializer()
  {
    InitializeHelperNode(gEntityCategoryHelperSerializer);
    gEntityCategoryHelperSerializer.mSerLoadFunc = &EntityCategory::SerLoad;
    gEntityCategoryHelperSerializer.mSerSaveFunc = &EntityCategory::SerSave;
    gEntityCategoryHelperSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_EntityCategoryHelperSerializerAtexit);
  }
} // namespace moho

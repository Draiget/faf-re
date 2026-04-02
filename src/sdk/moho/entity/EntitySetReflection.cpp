#include "moho/entity/EntitySetReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityFastVectorReflection.h"

namespace moho
{
  gpg::SerHelperBase* cleanup_EntitySetBaseSerializer();
  gpg::SerHelperBase* cleanup_EntitySetSerializer();
  gpg::SerHelperBase* cleanup_WeakEntitySetSerializer();
} // namespace moho

namespace
{
  using EntitySet = moho::EntitySetTemplate<moho::Entity>;
  using WeakEntitySet = moho::WeakEntitySetTemplate<moho::Entity>;

  alignas(moho::EntitySetBaseTypeInfo) unsigned char gEntitySetBaseTypeInfoStorage[sizeof(moho::EntitySetBaseTypeInfo)];
  bool gEntitySetBaseTypeInfoConstructed = false;

  alignas(moho::EntitySetTypeInfo) unsigned char gEntitySetTypeInfoStorage[sizeof(moho::EntitySetTypeInfo)];
  bool gEntitySetTypeInfoConstructed = false;

  alignas(moho::WeakEntitySetTypeInfo) unsigned char gWeakEntitySetTypeInfoStorage[sizeof(moho::WeakEntitySetTypeInfo)];
  bool gWeakEntitySetTypeInfoConstructed = false;

  moho::EntitySetBaseSerializer gEntitySetBaseSerializer{};
  moho::EntitySetSerializer gEntitySetSerializer{};
  moho::WeakEntitySetSerializer gWeakEntitySetSerializer{};

  [[nodiscard]] moho::EntitySetBaseTypeInfo& AcquireEntitySetBaseTypeInfo()
  {
    if (!gEntitySetBaseTypeInfoConstructed) {
      new (gEntitySetBaseTypeInfoStorage) moho::EntitySetBaseTypeInfo();
      gEntitySetBaseTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::EntitySetBaseTypeInfo*>(gEntitySetBaseTypeInfoStorage);
  }

  [[nodiscard]] moho::EntitySetTypeInfo& AcquireEntitySetTypeInfo()
  {
    if (!gEntitySetTypeInfoConstructed) {
      new (gEntitySetTypeInfoStorage) moho::EntitySetTypeInfo();
      gEntitySetTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::EntitySetTypeInfo*>(gEntitySetTypeInfoStorage);
  }

  [[nodiscard]] moho::WeakEntitySetTypeInfo& AcquireWeakEntitySetTypeInfo()
  {
    if (!gWeakEntitySetTypeInfoConstructed) {
      new (gWeakEntitySetTypeInfoStorage) moho::WeakEntitySetTypeInfo();
      gWeakEntitySetTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::WeakEntitySetTypeInfo*>(gWeakEntitySetTypeInfoStorage);
  }

  template <typename Serializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename Serializer>
  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename Serializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    if (!serializer.mHelperNext || !serializer.mHelperPrev) {
      serializer.mHelperNext = self;
      serializer.mHelperPrev = self;
      return self;
    }

    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetType()
  {
    gpg::RType* type = EntitySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(EntitySet));
      EntitySet::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakEntitySetType()
  {
    gpg::RType* type = WeakEntitySet::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(WeakEntitySet));
      WeakEntitySet::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveFastVectorEntityPointerType()
  {
    static gpg::RType* type = nullptr;
    if (!type) {
      type = gpg::LookupRType(typeid(gpg::fastvector<moho::Entity*>));
      if (!type) {
        type = moho::register_FastVectorEntityPtrType_00();
      }
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RRef MakeEntitySetBaseRef(moho::EntitySetBase* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = ResolveEntitySetBaseType();
    return ref;
  }

  /**
   * Address: 0x00693660 (FUN_00693660, sub_693660)
   *
   * What it does:
   * Clears reflected base/field vectors for `EntitySetBaseTypeInfo`.
   */
  void reset_EntitySetBaseTypeInfoVectors(moho::EntitySetBaseTypeInfo* const typeInfo)
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00693850 (FUN_00693850, sub_693850)
   *
   * What it does:
   * Clears reflected base/field vectors for `EntitySetTypeInfo`.
   */
  void reset_EntitySetTypeInfoVectors(moho::EntitySetTypeInfo* const typeInfo)
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00693AA0 (FUN_00693AA0, sub_693AA0)
   *
   * What it does:
   * Clears reflected base/field vectors for `WeakEntitySetTypeInfo`.
   */
  void reset_WeakEntitySetTypeInfoVectors(moho::WeakEntitySetTypeInfo* const typeInfo)
  {
    if (!typeInfo) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  void cleanup_EntitySetBaseSerializer_00BFCD20_atexit()
  {
    (void)moho::cleanup_EntitySetBaseSerializer();
  }

  void cleanup_EntitySetSerializer_00BFCDB0_atexit()
  {
    (void)moho::cleanup_EntitySetSerializer();
  }

  void cleanup_WeakEntitySetSerializer_00BFCE40_atexit()
  {
    (void)moho::cleanup_WeakEntitySetSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00693570 (FUN_00693570, sub_693570)
   */
  EntitySetBaseTypeInfo::EntitySetBaseTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntitySetBase), this);
  }

  /**
   * Address: 0x00693600 (FUN_00693600, Moho::EntitySetBaseTypeInfo::dtr)
   */
  EntitySetBaseTypeInfo::~EntitySetBaseTypeInfo()
  {
    reset_EntitySetBaseTypeInfoVectors(this);
  }

  /**
   * Address: 0x006935F0 (FUN_006935F0, Moho::EntitySetBaseTypeInfo::GetName)
   */
  const char* EntitySetBaseTypeInfo::GetName() const
  {
    return "EntitySetBase";
  }

  /**
   * Address: 0x006935D0 (FUN_006935D0, Moho::EntitySetBaseTypeInfo::Init)
   */
  void EntitySetBaseTypeInfo::Init()
  {
    size_ = sizeof(EntitySetBase);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00693760 (FUN_00693760, sub_693760)
   */
  EntitySetTypeInfo::EntitySetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(EntitySet), this);
  }

  /**
   * Address: 0x006937F0 (FUN_006937F0, Moho::EntitySetTypeInfo::dtr)
   */
  EntitySetTypeInfo::~EntitySetTypeInfo()
  {
    reset_EntitySetTypeInfoVectors(this);
  }

  /**
   * Address: 0x006937E0 (FUN_006937E0, Moho::EntitySetTypeInfo::GetName)
   */
  const char* EntitySetTypeInfo::GetName() const
  {
    return "EntitySet";
  }

  /**
   * Address: 0x00694180 (FUN_00694180, Moho::EntitySetTypeInfo::AddBase_EntitySetBase)
   */
  void EntitySetTypeInfo::AddBase_EntitySetBaseVariant1(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = ResolveEntitySetBaseType();

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00693890 (FUN_00693890, sub_693890)
   *
   * What it does:
   * Bridge thunk that forwards to `EntitySetTypeInfo::AddBase_EntitySetBase`.
   */
  void add_EntitySetBaseBase(gpg::RType* const typeInfo)
  {
    EntitySetTypeInfo::AddBase_EntitySetBaseVariant1(typeInfo);
  }

  /**
   * Address: 0x006937C0 (FUN_006937C0, Moho::EntitySetTypeInfo::Init)
   */
  void EntitySetTypeInfo::Init()
  {
    size_ = sizeof(EntitySet);
    gpg::RType::Init();
    add_EntitySetBaseBase(this);
    Finish();
  }

  /**
   * Address: 0x006939B0 (FUN_006939B0, sub_6939B0)
   */
  WeakEntitySetTypeInfo::WeakEntitySetTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(WeakEntitySet), this);
  }

  /**
   * Address: 0x00693A40 (FUN_00693A40, Moho::WeakEntitySetTypeInfo::dtr)
   */
  WeakEntitySetTypeInfo::~WeakEntitySetTypeInfo()
  {
    reset_WeakEntitySetTypeInfoVectors(this);
  }

  /**
   * Address: 0x00693A30 (FUN_00693A30, Moho::WeakEntitySetTypeInfo::GetName)
   */
  const char* WeakEntitySetTypeInfo::GetName() const
  {
    return "WeakEntitySet";
  }

  /**
   * Address: 0x00694260 (FUN_00694260, Moho::WeakEntitySetTypeInfo::AddBase_EntitySetTemplate_Entity)
   */
  void WeakEntitySetTypeInfo::AddBase_EntitySet(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = ResolveEntitySetType();

    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00693AE0 (FUN_00693AE0, sub_693AE0)
   *
   * What it does:
   * Bridge thunk that forwards to `WeakEntitySetTypeInfo::AddBase_EntitySet`.
   */
  void add_EntitySetBaseWeakBase(gpg::RType* const typeInfo)
  {
    WeakEntitySetTypeInfo::AddBase_EntitySet(typeInfo);
  }

  /**
   * Address: 0x00693A10 (FUN_00693A10, Moho::WeakEntitySetTypeInfo::Init)
   */
  void WeakEntitySetTypeInfo::Init()
  {
    size_ = sizeof(WeakEntitySet);
    gpg::RType::Init();
    add_EntitySetBaseWeakBase(this);
    Finish();
  }

  /**
   * Address: 0x006936A0 (FUN_006936A0, nullsub_1804)
   */
  void EntitySetBaseSerializer::RegisterSerializeFunctions()
  {
  }

  /**
   * Address: 0x006936B0 (FUN_006936B0, Moho::EntitySetBaseSerializer::Deserialize)
   */
  void EntitySetBaseSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    auto* const object = reinterpret_cast<EntitySetBase*>(objectPtr);
    const gpg::RRef selfRef = MakeEntitySetBaseRef(object);
    archive->TrackPointer(selfRef);

    const gpg::RRef nullOwner{};
    archive->Read(ResolveFastVectorEntityPointerType(), &object->mVec, nullOwner);
  }

  /**
   * Address: 0x006936C0 (FUN_006936C0, Moho::EntitySetBaseSerializer::Serialize)
   */
  void EntitySetBaseSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    auto* const object = reinterpret_cast<EntitySetBase*>(objectPtr);
    const gpg::RRef selfRef = MakeEntitySetBaseRef(object);
    archive->PreCreatedPtr(selfRef);

    const gpg::RRef nullOwner{};
    archive->Write(ResolveFastVectorEntityPointerType(), &object->mVec, nullOwner);
  }

  /**
   * What it does:
   * Binds `EntitySetTemplate<Entity>` RTTI serializer callbacks.
   */
  void EntitySetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveEntitySetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x006938A0 (FUN_006938A0, Moho::EntitySetSerializer::Deserialize)
   */
  void EntitySetSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveEntitySetBaseType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x006938E0 (FUN_006938E0, Moho::EntitySetSerializer::Serialize)
   */
  void EntitySetSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveEntitySetBaseType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * What it does:
   * Binds `WeakEntitySetTemplate<Entity>` RTTI serializer callbacks.
   */
  void WeakEntitySetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveWeakEntitySetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00693AF0 (FUN_00693AF0, Moho::WeakEntitySetSerializer::Deserialize)
   */
  void WeakEntitySetSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveEntitySetType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x00693B30 (FUN_00693B30, Moho::WeakEntitySetSerializer::Serialize)
   */
  void WeakEntitySetSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveEntitySetType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x00693570 (FUN_00693570, sub_693570)
   */
  gpg::RType* construct_EntitySetBaseTypeInfo()
  {
    return &AcquireEntitySetBaseTypeInfo();
  }

  /**
   * Address: 0x00BFCCC0 (FUN_00BFCCC0, sub_BFCCC0)
   *
   * What it does:
   * Tears down global `EntitySetBaseTypeInfo` storage at process exit.
   */
  void cleanup_EntitySetBaseTypeInfo()
  {
    if (!gEntitySetBaseTypeInfoConstructed) {
      return;
    }

    AcquireEntitySetBaseTypeInfo().~EntitySetBaseTypeInfo();
    gEntitySetBaseTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5770 (FUN_00BD5770, sub_BD5770)
   */
  int register_EntitySetBaseTypeInfo()
  {
    (void)construct_EntitySetBaseTypeInfo();
    return std::atexit(&cleanup_EntitySetBaseTypeInfo);
  }

  /**
   * Address: 0x006936D0 (FUN_006936D0, sub_6936D0)
   *
   * What it does:
   * Initializes global `EntitySetBaseSerializer` links and callback pointers.
   */
  gpg::SerHelperBase* construct_EntitySetBaseSerializer()
  {
    InitializeSerializerNode(gEntitySetBaseSerializer);
    gEntitySetBaseSerializer.mDeserialize = &EntitySetBaseSerializer::Deserialize;
    gEntitySetBaseSerializer.mSerialize = &EntitySetBaseSerializer::Serialize;
    return SerializerSelfNode(gEntitySetBaseSerializer);
  }

  /**
   * Address: 0x00693700 (FUN_00693700, sub_693700)
   *
   * What it does:
   * Unlinks and rewires `EntitySetBaseSerializer` helper links to self.
   */
  gpg::SerHelperBase* reset_EntitySetBaseSerializerLinksVariant1()
  {
    return UnlinkSerializerNode(gEntitySetBaseSerializer);
  }

  /**
   * Address: 0x00693730 (FUN_00693730, sub_693730)
   *
   * What it does:
   * Duplicate cleanup lane for `EntitySetBaseSerializer` helper links.
   */
  gpg::SerHelperBase* reset_EntitySetBaseSerializerLinksVariant2()
  {
    return UnlinkSerializerNode(gEntitySetBaseSerializer);
  }

  /**
   * Address: 0x00BFCD20 (FUN_00BFCD20, Moho::EntitySetBaseSerializer::~EntitySetBaseSerializer)
   *
   * What it does:
   * Unlinks `EntitySetBaseSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_EntitySetBaseSerializer()
  {
    return reset_EntitySetBaseSerializerLinksVariant2();
  }

  /**
   * Address: 0x00BD5790 (FUN_00BD5790, sub_BD5790)
   */
  void register_EntitySetBaseSerializer()
  {
    (void)construct_EntitySetBaseSerializer();
    (void)std::atexit(&cleanup_EntitySetBaseSerializer_00BFCD20_atexit);
  }

  /**
   * Address: 0x00693760 (FUN_00693760, sub_693760)
   */
  gpg::RType* construct_EntitySetTypeInfo()
  {
    return &AcquireEntitySetTypeInfo();
  }

  /**
   * Address: 0x00BFCD50 (FUN_00BFCD50, sub_BFCD50)
   *
   * What it does:
   * Tears down global `EntitySetTypeInfo` storage at process exit.
   */
  void cleanup_EntitySetTypeInfo()
  {
    if (!gEntitySetTypeInfoConstructed) {
      return;
    }

    AcquireEntitySetTypeInfo().~EntitySetTypeInfo();
    gEntitySetTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD57D0 (FUN_00BD57D0, sub_BD57D0)
   */
  int register_EntitySetTypeInfo()
  {
    (void)construct_EntitySetTypeInfo();
    return std::atexit(&cleanup_EntitySetTypeInfo);
  }

  /**
   * Address: 0x00693920 (FUN_00693920, sub_693920)
   *
   * What it does:
   * Initializes global `EntitySetSerializer` links and callback pointers.
   */
  gpg::SerHelperBase* construct_EntitySetSerializer()
  {
    InitializeSerializerNode(gEntitySetSerializer);
    gEntitySetSerializer.mDeserialize = &EntitySetSerializer::Deserialize;
    gEntitySetSerializer.mSerialize = &EntitySetSerializer::Serialize;
    return SerializerSelfNode(gEntitySetSerializer);
  }

  /**
   * Address: 0x00693950 (FUN_00693950, sub_693950)
   *
   * What it does:
   * Unlinks and rewires `EntitySetSerializer` helper links to self.
   */
  gpg::SerHelperBase* reset_EntitySetSerializerLinksVariant1()
  {
    return UnlinkSerializerNode(gEntitySetSerializer);
  }

  /**
   * Address: 0x00693980 (FUN_00693980, sub_693980)
   *
   * What it does:
   * Duplicate cleanup lane for `EntitySetSerializer` helper links.
   */
  gpg::SerHelperBase* reset_EntitySetSerializerLinksVariant2()
  {
    return UnlinkSerializerNode(gEntitySetSerializer);
  }

  /**
   * Address: 0x00BFCDB0 (FUN_00BFCDB0, Moho::EntitySetSerializer::~EntitySetSerializer)
   *
   * What it does:
   * Unlinks `EntitySetSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_EntitySetSerializer()
  {
    return reset_EntitySetSerializerLinksVariant2();
  }

  /**
   * Address: 0x00BD57F0 (FUN_00BD57F0, register_EntitySetSerializer)
   */
  void register_EntitySetSerializer()
  {
    (void)construct_EntitySetSerializer();
    (void)std::atexit(&cleanup_EntitySetSerializer_00BFCDB0_atexit);
  }

  /**
   * Address: 0x006939B0 (FUN_006939B0, sub_6939B0)
   */
  gpg::RType* construct_WeakEntitySetTypeInfo()
  {
    return &AcquireWeakEntitySetTypeInfo();
  }

  /**
   * Address: 0x00BFCDE0 (FUN_00BFCDE0, sub_BFCDE0)
   *
   * What it does:
   * Tears down global `WeakEntitySetTypeInfo` storage at process exit.
   */
  void cleanup_WeakEntitySetTypeInfo()
  {
    if (!gWeakEntitySetTypeInfoConstructed) {
      return;
    }

    AcquireWeakEntitySetTypeInfo().~WeakEntitySetTypeInfo();
    gWeakEntitySetTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD5830 (FUN_00BD5830, sub_BD5830)
   */
  int register_WeakEntitySetTypeInfo()
  {
    (void)construct_WeakEntitySetTypeInfo();
    return std::atexit(&cleanup_WeakEntitySetTypeInfo);
  }

  /**
   * Address: 0x00693B70 (FUN_00693B70, sub_693B70)
   *
   * What it does:
   * Initializes global `WeakEntitySetSerializer` links and callback pointers.
   */
  gpg::SerHelperBase* construct_WeakEntitySetSerializer()
  {
    InitializeSerializerNode(gWeakEntitySetSerializer);
    gWeakEntitySetSerializer.mDeserialize = &WeakEntitySetSerializer::Deserialize;
    gWeakEntitySetSerializer.mSerialize = &WeakEntitySetSerializer::Serialize;
    return SerializerSelfNode(gWeakEntitySetSerializer);
  }

  /**
   * Address: 0x00693BA0 (FUN_00693BA0, sub_693BA0)
   *
   * What it does:
   * Unlinks and rewires `WeakEntitySetSerializer` helper links to self.
   */
  gpg::SerHelperBase* reset_WeakEntitySetSerializerLinksVariant1()
  {
    return UnlinkSerializerNode(gWeakEntitySetSerializer);
  }

  /**
   * Address: 0x00693BD0 (FUN_00693BD0, sub_693BD0)
   *
   * What it does:
   * Duplicate cleanup lane for `WeakEntitySetSerializer` helper links.
   */
  gpg::SerHelperBase* reset_WeakEntitySetSerializerLinksVariant2()
  {
    return UnlinkSerializerNode(gWeakEntitySetSerializer);
  }

  /**
   * Address: 0x00BFCE40 (FUN_00BFCE40, sub_BFCE40)
   *
   * What it does:
   * Unlinks `WeakEntitySetSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_WeakEntitySetSerializer()
  {
    return reset_WeakEntitySetSerializerLinksVariant2();
  }

  /**
   * Address: 0x00BD5850 (FUN_00BD5850, register_WeakEntitySetSerializer)
   */
  void register_WeakEntitySetSerializer()
  {
    (void)construct_WeakEntitySetSerializer();
    (void)std::atexit(&cleanup_WeakEntitySetSerializer_00BFCE40_atexit);
  }
} // namespace moho

namespace
{
  struct EntitySetReflectionBootstrap
  {
    EntitySetReflectionBootstrap()
    {
      (void)moho::register_EntitySetBaseTypeInfo();
      moho::register_EntitySetBaseSerializer();
      (void)moho::register_EntitySetTypeInfo();
      moho::register_EntitySetSerializer();
      (void)moho::register_WeakEntitySetTypeInfo();
      moho::register_WeakEntitySetSerializer();
    }
  };

  EntitySetReflectionBootstrap gEntitySetReflectionBootstrap;
} // namespace

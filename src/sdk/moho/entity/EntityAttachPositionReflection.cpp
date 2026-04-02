#include "moho/entity/Entity.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/render/camera/VTransform.h"
#include "moho/script/CScriptObject.h"
#include "moho/task/CTask.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E27654
   * COL: 0x00E871A4
   */
  class SEntAttachInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00676D50 (FUN_00676D50, sub_676D50)
     *
     * What it does:
     * Constructs and preregisters RTTI ownership for `SEntAttachInfo`.
     */
    SEntAttachInfoTypeInfo();

    /**
     * Address: 0x00676DE0 (FUN_00676DE0, Moho::SEntAttachInfoTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `SEntAttachInfoTypeInfo`.
     */
    ~SEntAttachInfoTypeInfo() override;

    /**
     * Address: 0x00676DD0 (FUN_00676DD0, Moho::SEntAttachInfoTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00676DB0 (FUN_00676DB0, Moho::SEntAttachInfoTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SEntAttachInfoTypeInfo) == 0x64, "SEntAttachInfoTypeInfo size must be 0x64");

  class SEntAttachInfoSerializer
  {
  public:
    /**
     * Address: 0x00676E90 (FUN_00676E90, Moho::SEntAttachInfoSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00676EA0 (FUN_00676EA0, Moho::SEntAttachInfoSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `SEntAttachInfo`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(SEntAttachInfoSerializer, mHelperNext) == 0x04, "SEntAttachInfoSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SEntAttachInfoSerializer, mHelperPrev) == 0x08, "SEntAttachInfoSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SEntAttachInfoSerializer, mDeserialize) == 0x0C,
    "SEntAttachInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SEntAttachInfoSerializer, mSerialize) == 0x10, "SEntAttachInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SEntAttachInfoSerializer) == 0x14, "SEntAttachInfoSerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E27694
   * COL: 0x00E8714C
   */
  class PositionHistoryTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00676F40 (FUN_00676F40, Moho::PositionHistoryTypeInfo::PositionHistoryTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI ownership for `PositionHistory`.
     */
    PositionHistoryTypeInfo();

    /**
     * Address: 0x00677000 (FUN_00677000, Moho::PositionHistoryTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `PositionHistoryTypeInfo`.
     */
    ~PositionHistoryTypeInfo() override;

    /**
     * Address: 0x00676FF0 (FUN_00676FF0, Moho::PositionHistoryTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00676FA0 (FUN_00676FA0, Moho::PositionHistoryTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(PositionHistoryTypeInfo) == 0x64, "PositionHistoryTypeInfo size must be 0x64");

  class PositionHistorySerializer
  {
  public:
    /**
     * Address: 0x00677120 (FUN_00677120, Moho::PositionHistorySerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00677140 (FUN_00677140, Moho::PositionHistorySerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * What it does:
     * Binds load/save callbacks into reflected RTTI for `PositionHistory`.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(PositionHistorySerializer, mHelperNext) == 0x04, "PositionHistorySerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(PositionHistorySerializer, mHelperPrev) == 0x08, "PositionHistorySerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(PositionHistorySerializer, mDeserialize) == 0x0C,
    "PositionHistorySerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(PositionHistorySerializer, mSerialize) == 0x10, "PositionHistorySerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(PositionHistorySerializer) == 0x14, "PositionHistorySerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E2759C
   * COL: 0x00E871F8
   */
  class EntityTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x006771F0 (FUN_006771F0, Moho::EntityTypeInfo::EntityTypeInfo)
     *
     * What it does:
     * Constructs and preregisters RTTI ownership for `Entity`.
     */
    EntityTypeInfo();

    /**
     * Address: 0x006772A0 (FUN_006772A0, Moho::EntityTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors for `EntityTypeInfo`.
     */
    ~EntityTypeInfo() override;

    /**
     * Address: 0x00677270 (FUN_00677270, Moho::EntityTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00677250 (FUN_00677250, Moho::EntityTypeInfo::Init)
     */
    void Init() override;

  private:
    static void AddBase_CScriptObjectVariant1(gpg::RType* typeInfo);
    static void AddBase_CTaskVariant1(gpg::RType* typeInfo);
  };

  static_assert(sizeof(EntityTypeInfo) == 0x64, "EntityTypeInfo size must be 0x64");

  /**
   * VFTABLE: 0x00E276DC
   * COL: 0x00E7FFE4
   */
  class EntitySaveConstruct
  {
  public:
    /**
     * Address: 0x0067B3E0 (FUN_0067B3E0, Moho::EntitySaveConstruct::Construct)
     *
     * What it does:
     * Forwards save-construct callback flow into `Entity::MemberSaveConstructArgs`.
     */
    static void Construct(gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result);

    /**
     * What it does:
     * Binds save-construct callback into reflected RTTI for `Entity`.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mConstructCallback;
  };

  static_assert(offsetof(EntitySaveConstruct, mHelperNext) == 0x04, "EntitySaveConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(EntitySaveConstruct, mHelperPrev) == 0x08, "EntitySaveConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(EntitySaveConstruct, mConstructCallback) == 0x0C,
    "EntitySaveConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(sizeof(EntitySaveConstruct) == 0x10, "EntitySaveConstruct size must be 0x10");

  /**
   * VFTABLE: 0x00E276EC
   * COL: 0x00E7FF38
   */
  class EntityConstruct
  {
  public:
    /**
     * Address: 0x0067B550 (FUN_0067B550, Moho::EntityConstruct::Construct)
     *
     * What it does:
     * Forwards construct callback flow into `Entity::MemberConstruct`.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0067F5D0 (FUN_0067F5D0, Moho::EntityConstruct::Deconstruct)
     *
     * What it does:
     * Executes virtual deleting-dtor lane for one constructed `Entity`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * What it does:
     * Binds construct/delete callbacks into reflected RTTI for `Entity`.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(offsetof(EntityConstruct, mHelperNext) == 0x04, "EntityConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(EntityConstruct, mHelperPrev) == 0x08, "EntityConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(EntityConstruct, mConstructCallback) == 0x0C,
    "EntityConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(EntityConstruct, mDeconstructCallback) == 0x10,
    "EntityConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(EntityConstruct) == 0x14, "EntityConstruct size must be 0x14");
} // namespace moho

namespace
{
  alignas(moho::SEntAttachInfoTypeInfo) unsigned char gSEntAttachInfoTypeInfoStorage[sizeof(moho::SEntAttachInfoTypeInfo)];
  bool gSEntAttachInfoTypeInfoConstructed = false;

  alignas(moho::PositionHistoryTypeInfo)
    unsigned char gPositionHistoryTypeInfoStorage[sizeof(moho::PositionHistoryTypeInfo)];
  bool gPositionHistoryTypeInfoConstructed = false;

  alignas(moho::EntityTypeInfo) unsigned char gEntityTypeInfoStorage[sizeof(moho::EntityTypeInfo)];
  bool gEntityTypeInfoConstructed = false;

  moho::SEntAttachInfoSerializer gSEntAttachInfoSerializer{};
  moho::PositionHistorySerializer gPositionHistorySerializer{};
  moho::EntitySaveConstruct gEntitySaveConstruct{};
  moho::EntityConstruct gEntityConstruct{};

  gpg::RType* gWeakPtrEntityType = nullptr;
  gpg::RType* gVTransformType = nullptr;
  gpg::RType* gCScriptObjectType = nullptr;
  gpg::RType* gCTaskType = nullptr;
  gpg::RType* gEntityType = nullptr;

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveSEntAttachInfoType()
  {
    return ResolveCachedType<moho::SEntAttachInfo>(moho::SEntAttachInfo::sType);
  }

  [[nodiscard]] gpg::RType* ResolvePositionHistoryType()
  {
    return ResolveCachedType<moho::PositionHistory>(moho::PositionHistory::sType);
  }

  [[nodiscard]] gpg::RType* ResolveEntityType()
  {
    return ResolveCachedType<moho::Entity>(gEntityType);
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrEntityType()
  {
    return ResolveCachedType<moho::WeakPtr<moho::Entity>>(gWeakPtrEntityType);
  }

  [[nodiscard]] gpg::RType* ResolveVTransformType()
  {
    return ResolveCachedType<moho::VTransform>(gVTransformType);
  }

  [[nodiscard]] moho::SEntAttachInfoTypeInfo& AcquireSEntAttachInfoTypeInfo()
  {
    if (!gSEntAttachInfoTypeInfoConstructed) {
      new (gSEntAttachInfoTypeInfoStorage) moho::SEntAttachInfoTypeInfo();
      gSEntAttachInfoTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::SEntAttachInfoTypeInfo*>(gSEntAttachInfoTypeInfoStorage);
  }

  [[nodiscard]] moho::PositionHistoryTypeInfo& AcquirePositionHistoryTypeInfo()
  {
    if (!gPositionHistoryTypeInfoConstructed) {
      new (gPositionHistoryTypeInfoStorage) moho::PositionHistoryTypeInfo();
      gPositionHistoryTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::PositionHistoryTypeInfo*>(gPositionHistoryTypeInfoStorage);
  }

  [[nodiscard]] moho::EntityTypeInfo& AcquireEntityTypeInfo()
  {
    if (!gEntityTypeInfoConstructed) {
      new (gEntityTypeInfoStorage) moho::EntityTypeInfo();
      gEntityTypeInfoConstructed = true;
    }
    return *reinterpret_cast<moho::EntityTypeInfo*>(gEntityTypeInfoStorage);
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
    return self;
  }

  void cleanup_SEntAttachInfoSerializer_Atexit()
  {
    (void)UnlinkHelperNode(gSEntAttachInfoSerializer);
  }

  void cleanup_PositionHistorySerializer_Atexit()
  {
    (void)UnlinkHelperNode(gPositionHistorySerializer);
  }

  void cleanup_EntitySaveConstruct_Atexit()
  {
    (void)UnlinkHelperNode(gEntitySaveConstruct);
  }

  void cleanup_EntityConstruct_Atexit()
  {
    (void)UnlinkHelperNode(gEntityConstruct);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0067ED40 (FUN_0067ED40, Moho::SEntAttachInfo::MemberDeserialize)
   */
  void SEntAttachInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};

    archive->Read(ResolveWeakPtrEntityType(), &mAttachTargetWeak, nullOwner);
    archive->ReadInt(&mParentBoneIndex);
    archive->ReadInt(&mChildBoneIndex);

    // Binary stores this 0x1C region through `VTransform` RTTI lanes.
    archive->Read(ResolveVTransformType(), &mRelativeOrientX, nullOwner);
  }

  /**
   * Address: 0x0067EDD0 (FUN_0067EDD0, Moho::SEntAttachInfo::MemberSerialize)
   */
  void SEntAttachInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};

    archive->Write(ResolveWeakPtrEntityType(), &mAttachTargetWeak, nullOwner);
    archive->WriteInt(mParentBoneIndex);
    archive->WriteInt(mChildBoneIndex);

    // Binary stores this 0x1C region through `VTransform` RTTI lanes.
    archive->Write(ResolveVTransformType(), &mRelativeOrientX, nullOwner);
  }

  /**
   * Address: 0x0067EE60 (FUN_0067EE60, Moho::PositionHistory::MemberDeserialize)
   */
  void PositionHistory::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    static_assert(sizeof(EntityTransformPayload) == sizeof(VTransform), "Position history sample must match VTransform layout");
    const gpg::RRef nullOwner{};
    gpg::RType* const transformType = ResolveVTransformType();

    for (EntityTransformPayload& sample : samples) {
      archive->Read(transformType, &sample, nullOwner);
    }
    archive->ReadInt(&cursor);
  }

  /**
   * Address: 0x0067EED0 (FUN_0067EED0, Moho::PositionHistory::MemberSerialize)
   */
  void PositionHistory::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    static_assert(sizeof(EntityTransformPayload) == sizeof(VTransform), "Position history sample must match VTransform layout");
    const gpg::RRef nullOwner{};
    gpg::RType* const transformType = ResolveVTransformType();

    for (const EntityTransformPayload& sample : samples) {
      archive->Write(transformType, &sample, nullOwner);
    }
    archive->WriteInt(cursor);
  }

  /**
   * Address: 0x00676D50 (FUN_00676D50, sub_676D50)
   */
  SEntAttachInfoTypeInfo::SEntAttachInfoTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SEntAttachInfo), this);
  }

  /**
   * Address: 0x00676DE0 (FUN_00676DE0, Moho::SEntAttachInfoTypeInfo::dtr)
   */
  SEntAttachInfoTypeInfo::~SEntAttachInfoTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00676DD0 (FUN_00676DD0, Moho::SEntAttachInfoTypeInfo::GetName)
   */
  const char* SEntAttachInfoTypeInfo::GetName() const
  {
    return "SEntAttachInfo";
  }

  /**
   * Address: 0x00676DB0 (FUN_00676DB0, Moho::SEntAttachInfoTypeInfo::Init)
   */
  void SEntAttachInfoTypeInfo::Init()
  {
    size_ = sizeof(SEntAttachInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00676E90 (FUN_00676E90, Moho::SEntAttachInfoSerializer::Deserialize)
   */
  void SEntAttachInfoSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef*)
  {
    auto* const attachInfo = reinterpret_cast<SEntAttachInfo*>(objectPtr);
    if (!archive || !attachInfo) {
      return;
    }
    attachInfo->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00676EA0 (FUN_00676EA0, Moho::SEntAttachInfoSerializer::Serialize)
   */
  void SEntAttachInfoSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef*)
  {
    const auto* const attachInfo = reinterpret_cast<const SEntAttachInfo*>(objectPtr);
    if (!archive || !attachInfo) {
      return;
    }
    attachInfo->MemberSerialize(archive);
  }

  void SEntAttachInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveSEntAttachInfoType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00676F40 (FUN_00676F40, Moho::PositionHistoryTypeInfo::PositionHistoryTypeInfo)
   */
  PositionHistoryTypeInfo::PositionHistoryTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(PositionHistory), this);
  }

  /**
   * Address: 0x00677000 (FUN_00677000, Moho::PositionHistoryTypeInfo::dtr)
   */
  PositionHistoryTypeInfo::~PositionHistoryTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00676FF0 (FUN_00676FF0, Moho::PositionHistoryTypeInfo::GetName)
   */
  const char* PositionHistoryTypeInfo::GetName() const
  {
    return "PositionHistory";
  }

  /**
   * Address: 0x00676FA0 (FUN_00676FA0, Moho::PositionHistoryTypeInfo::Init)
   */
  void PositionHistoryTypeInfo::Init()
  {
    size_ = sizeof(PositionHistory);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00677120 (FUN_00677120, Moho::PositionHistorySerializer::Deserialize)
   */
  void PositionHistorySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, int, gpg::RRef*)
  {
    auto* const history = reinterpret_cast<PositionHistory*>(objectPtr);
    if (!archive || !history) {
      return;
    }
    history->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00677140 (FUN_00677140, Moho::PositionHistorySerializer::Serialize)
   */
  void PositionHistorySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, int, gpg::RRef*)
  {
    const auto* const history = reinterpret_cast<const PositionHistory*>(objectPtr);
    if (!archive || !history) {
      return;
    }
    history->MemberSerialize(archive);
  }

  void PositionHistorySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolvePositionHistoryType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x006771F0 (FUN_006771F0, Moho::EntityTypeInfo::EntityTypeInfo)
   */
  EntityTypeInfo::EntityTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Entity), this);
  }

  /**
   * Address: 0x006772A0 (FUN_006772A0, Moho::EntityTypeInfo::dtr)
   */
  EntityTypeInfo::~EntityTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00677270 (FUN_00677270, Moho::EntityTypeInfo::GetName)
   */
  const char* EntityTypeInfo::GetName() const
  {
    return "Entity";
  }

  /**
   * Address: 0x0067EF40 (FUN_0067EF40, Moho::EntityTypeInfo::AddBase_CScriptObject)
   */
  void EntityTypeInfo::AddBase_CScriptObjectVariant1(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = ResolveCachedType<CScriptObject>(gCScriptObjectType);
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    typeInfo->AddBase(gpg::RField{baseType->GetName(), baseType, 0});
  }

  /**
   * Address: 0x0067EFA0 (FUN_0067EFA0, Moho::EntityTypeInfo::AddBase_CTask)
   */
  void EntityTypeInfo::AddBase_CTaskVariant1(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = ResolveCachedType<CTask>(gCTaskType);
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(baseType != nullptr);
    if (!typeInfo || !baseType) {
      return;
    }

    typeInfo->AddBase(gpg::RField{baseType->GetName(), baseType, 0x34});
  }

  /**
   * Address: 0x00677250 (FUN_00677250, Moho::EntityTypeInfo::Init)
   */
  void EntityTypeInfo::Init()
  {
    size_ = sizeof(Entity);
    AddBase_CScriptObjectVariant1(this);
    gpg::RType::Init();
    AddBase_CTaskVariant1(this);
    fields_.push_back(gpg::RField{"PendingCoords", ResolveVTransformType(), 0x150, 1, "Pending position and orientation"});
    Finish();
  }

  /**
   * Address: 0x0067B3E0 (FUN_0067B3E0, Moho::EntitySaveConstruct::Construct)
   */
  void EntitySaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const entity = reinterpret_cast<Entity*>(objectPtr);
    if (!archive || !entity || !result) {
      return;
    }

    const gpg::RRef ownerRef{};
    entity->MemberSaveConstructArgs(*archive, version, ownerRef, *result);
  }

  void EntitySaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = ResolveEntityType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mConstructCallback);
    type->serSaveConstructArgsFunc_ = mConstructCallback;
  }

  /**
   * Address: 0x0067B550 (FUN_0067B550, Moho::EntityConstruct::Construct)
   */
  void
  EntityConstruct::Construct(gpg::ReadArchive* const archive, const int, const int version, gpg::SerConstructResult* const result)
  {
    if (!archive || !result) {
      return;
    }

    const gpg::RRef ownerRef{};
    Entity::MemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x0067F5D0 (FUN_0067F5D0, Moho::EntityConstruct::Deconstruct)
   */
  void EntityConstruct::Deconstruct(void* const objectPtr)
  {
    if (!objectPtr) {
      return;
    }

    using deleting_dtor_t = void(__thiscall*)(void*, int);
    void** const vftable = *reinterpret_cast<void***>(objectPtr);
    auto* const deletingDtor = reinterpret_cast<deleting_dtor_t>(vftable[2]);
    deletingDtor(objectPtr, 1);
  }

  void EntityConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ResolveEntityType();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BFC690 (FUN_00BFC690, cleanup_SEntAttachInfoTypeInfo)
   */
  void cleanup_SEntAttachInfoTypeInfo()
  {
    if (!gSEntAttachInfoTypeInfoConstructed) {
      return;
    }

    AcquireSEntAttachInfoTypeInfo().~SEntAttachInfoTypeInfo();
    gSEntAttachInfoTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFC720 (FUN_00BFC720, cleanup_PositionHistoryTypeInfo)
   */
  void cleanup_PositionHistoryTypeInfo()
  {
    if (!gPositionHistoryTypeInfoConstructed) {
      return;
    }

    AcquirePositionHistoryTypeInfo().~PositionHistoryTypeInfo();
    gPositionHistoryTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFC7B0 (FUN_00BFC7B0, cleanup_EntityTypeInfo)
   */
  void cleanup_EntityTypeInfo()
  {
    if (!gEntityTypeInfoConstructed) {
      return;
    }

    AcquireEntityTypeInfo().~EntityTypeInfo();
    gEntityTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFC810 (FUN_00BFC810, cleanup_EntitySaveConstruct)
   *
   * What it does:
   * Unlinks `EntitySaveConstruct` helper node from global serializer list.
   */
  gpg::SerHelperBase* cleanup_EntitySaveConstruct()
  {
    return UnlinkHelperNode(gEntitySaveConstruct);
  }

  /**
   * Address: 0x00BFC840 (FUN_00BFC840, cleanup_EntityConstruct)
   *
   * What it does:
   * Unlinks `EntityConstruct` helper node from global serializer list.
   */
  gpg::SerHelperBase* cleanup_EntityConstruct()
  {
    return UnlinkHelperNode(gEntityConstruct);
  }

  /**
   * Address: 0x00BD4F00 (FUN_00BD4F00, register_SEntAttachInfoTypeInfo)
   *
   * What it does:
   * Constructs global `SEntAttachInfoTypeInfo` and registers exit cleanup.
   */
  int register_SEntAttachInfoTypeInfo()
  {
    (void)AcquireSEntAttachInfoTypeInfo();
    return std::atexit(&cleanup_SEntAttachInfoTypeInfo);
  }

  /**
   * Address: 0x00BD4F20 (FUN_00BD4F20, register_SEntAttachInfoSerializer)
   *
   * What it does:
   * Initializes `SEntAttachInfoSerializer` callback lanes and registers exit cleanup.
   */
  void register_SEntAttachInfoSerializer()
  {
    InitializeHelperNode(gSEntAttachInfoSerializer);
    gSEntAttachInfoSerializer.mDeserialize = &SEntAttachInfoSerializer::Deserialize;
    gSEntAttachInfoSerializer.mSerialize = &SEntAttachInfoSerializer::Serialize;
    gSEntAttachInfoSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SEntAttachInfoSerializer_Atexit);
  }

  /**
   * Address: 0x00BD4F60 (FUN_00BD4F60, register_PositionHistoryTypeInfo)
   *
   * What it does:
   * Constructs global `PositionHistoryTypeInfo` and registers exit cleanup.
   */
  int register_PositionHistoryTypeInfo()
  {
    (void)AcquirePositionHistoryTypeInfo();
    return std::atexit(&cleanup_PositionHistoryTypeInfo);
  }

  /**
   * Address: 0x00BD4F80 (FUN_00BD4F80, register_PositionHistorySerializer)
   *
   * What it does:
   * Initializes `PositionHistorySerializer` callback lanes and registers exit cleanup.
   */
  void register_PositionHistorySerializer()
  {
    InitializeHelperNode(gPositionHistorySerializer);
    gPositionHistorySerializer.mDeserialize = &PositionHistorySerializer::Deserialize;
    gPositionHistorySerializer.mSerialize = &PositionHistorySerializer::Serialize;
    gPositionHistorySerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_PositionHistorySerializer_Atexit);
  }

  /**
   * Address: 0x00BD4FC0 (FUN_00BD4FC0, register_EntityTypeInfo)
   *
   * What it does:
   * Constructs global `EntityTypeInfo` and registers exit cleanup.
   */
  int register_EntityTypeInfo()
  {
    (void)AcquireEntityTypeInfo();
    return std::atexit(&cleanup_EntityTypeInfo);
  }

  /**
   * Address: 0x00BD4FE0 (FUN_00BD4FE0, register_EntitySaveConstruct)
   *
   * What it does:
   * Initializes callback lanes for global `EntitySaveConstruct` helper.
   */
  void register_EntitySaveConstruct()
  {
    InitializeHelperNode(gEntitySaveConstruct);
    gEntitySaveConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&EntitySaveConstruct::Construct);
    gEntitySaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&cleanup_EntitySaveConstruct_Atexit);
  }

  /**
   * Address: 0x00BD5010 (FUN_00BD5010, register_EntityConstruct)
   *
   * What it does:
   * Initializes callback lanes for global `EntityConstruct` helper.
   */
  void register_EntityConstruct()
  {
    InitializeHelperNode(gEntityConstruct);
    gEntityConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&EntityConstruct::Construct);
    gEntityConstruct.mDeconstructCallback = &EntityConstruct::Deconstruct;
    gEntityConstruct.RegisterConstructFunction();
    (void)std::atexit(&cleanup_EntityConstruct_Atexit);
  }
} // namespace moho

namespace
{
  struct EntityAttachPositionReflectionBootstrap
  {
    EntityAttachPositionReflectionBootstrap()
    {
      (void)moho::register_SEntAttachInfoTypeInfo();
      moho::register_SEntAttachInfoSerializer();
      (void)moho::register_PositionHistoryTypeInfo();
      moho::register_PositionHistorySerializer();
      (void)moho::register_EntityTypeInfo();
      moho::register_EntitySaveConstruct();
      moho::register_EntityConstruct();
    }
  };

  [[maybe_unused]] EntityAttachPositionReflectionBootstrap gEntityAttachPositionReflectionBootstrap;
} // namespace

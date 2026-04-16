#include "moho/entity/MotorSinkAway.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"

#pragma init_seg(lib)

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  alignas(moho::MotorSinkAwayTypeInfo)
    unsigned char gMotorSinkAwayTypeInfoStorage[sizeof(moho::MotorSinkAwayTypeInfo)];
  bool gMotorSinkAwayTypeInfoConstructed = false;
  moho::MotorSinkAwaySerializer gMotorSinkAwaySerializer{};
  moho::MotorSinkAwayConstruct gMotorSinkAwayConstruct{};
  std::int32_t gRecoveredCScrLuaMetatableFactoryMotorSinkAwayIndex = 0;

  [[nodiscard]] moho::MotorSinkAwayTypeInfo& MotorSinkAwayTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::MotorSinkAwayTypeInfo*>(gMotorSinkAwayTypeInfoStorage);
  }

  /**
   * Address: 0x00696390 (FUN_00696390)
   *
   * What it does:
   * Resolves and caches RTTI for one `MotorSinkAway` lane.
   */
  [[nodiscard]] gpg::RType* CachedMotorSinkAwayType()
  {
    if (!moho::MotorSinkAway::sType) {
      moho::MotorSinkAway::sType = gpg::LookupRType(typeid(moho::MotorSinkAway));
    }

    GPG_ASSERT(moho::MotorSinkAway::sType != nullptr);
    return moho::MotorSinkAway::sType;
  }

  /**
   * Address: 0x00696C10 (FUN_00696C10)
   *
   * What it does:
   * Secondary duplicated RTTI-resolve lane for `MotorSinkAway`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedMotorSinkAwayTypeVariantB()
  {
    return CachedMotorSinkAwayType();
  }

  [[nodiscard]] gpg::RType* CachedMotorType()
  {
    if (!moho::EntityMotor::sType) {
      moho::EntityMotor::sType = gpg::LookupRType(typeid(moho::EntityMotor));
    }

    GPG_ASSERT(moho::EntityMotor::sType != nullptr);
    return moho::EntityMotor::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!moho::CScriptObject::sType) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }

    GPG_ASSERT(moho::CScriptObject::sType != nullptr);
    return moho::CScriptObject::sType;
  }

  /**
   * Address: 0x006962A0 (FUN_006962A0)
   *
   * What it does:
   * Deserializes one `Motor` object lane through archive owner context and
   * returns the archive instance.
   */
  gpg::ReadArchive* ReadMotorArchiveAdapter(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    archive->Read(CachedMotorType(), object, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x006962E0 (FUN_006962E0)
   *
   * What it does:
   * Serializes one `Motor` object lane through archive owner context and
   * returns the archive instance.
   */
  gpg::WriteArchive* WriteMotorArchiveAdapter(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(CachedMotorType(), objectSlot, *ownerRef);
    return archive;
  }

  /**
   * Address: 0x00696320 (FUN_00696320)
   *
   * What it does:
   * Deserializes one `Motor` object lane through archive owner context.
   */
  void ReadMotorArchiveObjectLane1(gpg::ReadArchive* const archive, void* const object, gpg::RRef* const ownerRef)
  {
    archive->Read(CachedMotorType(), object, *ownerRef);
  }

  /**
   * Address: 0x00696350 (FUN_00696350)
   *
   * What it does:
   * Serializes one `Motor` object lane through archive owner context.
   */
  void WriteMotorArchiveObjectLane1(
    gpg::WriteArchive* const archive,
    void** const objectSlot,
    const gpg::RRef* const ownerRef
  )
  {
    archive->Write(CachedMotorType(), objectSlot, *ownerRef);
  }

  /**
   * Address: 0x00696E70 (FUN_00696E70, Lua factory lookup thunk)
   */
  [[nodiscard]] LuaPlus::LuaObject GetMotorSinkAwayLuaFactoryObject(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::MotorSinkAway>::Instance().Get(state);
  }

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }
#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
  }

  [[nodiscard]] gpg::RRef MakeMotorSinkAwayRef(moho::MotorSinkAway* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedMotorSinkAwayType();
    return ref;
  }

  /**
   * Address: 0x00696F80 (FUN_00696F80)
   *
   * What it does:
   * Builds one temporary `RRef_MotorSinkAway` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_MotorSinkAway(
    gpg::RRef* const out,
    moho::MotorSinkAway* const value
  )
  {
    const gpg::RRef ref = MakeMotorSinkAwayRef(value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return &helper.mHelperLinks;
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mNext = self;
    helper.mHelperLinks.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperLinks.mNext != nullptr && helper.mHelperLinks.mPrev != nullptr) {
      helper.mHelperLinks.mNext->mPrev = helper.mHelperLinks.mPrev;
      helper.mHelperLinks.mPrev->mNext = helper.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mPrev = self;
    helper.mHelperLinks.mNext = self;
    return self;
  }

  /**
   * Address: 0x006967F0 (FUN_006967F0, construct helper body)
   * Address: 0x00696F70 (FUN_00696F70, construct helper thunk)
   */
  void Construct_MotorSinkAway_Object(gpg::SerConstructResult* const result)
  {
    moho::MotorSinkAway* const object = new (std::nothrow) moho::MotorSinkAway();
    if (!result) {
      return;
    }

    const gpg::RRef ref = MakeMotorSinkAwayRef(object);
    result->SetUnowned(ref, 0u);
  }

  /**
    * Alias of FUN_006967E0 (non-canonical helper lane).
   */
  void Construct_MotorSinkAway_Callback(
    gpg::ReadArchive*, const int, const int, gpg::SerConstructResult* const result
  )
  {
    Construct_MotorSinkAway_Object(result);
  }

  /**
   * Address: 0x00696F50 (FUN_00696F50, delete callback thunk)
   */
  void DeleteConstructedMotorSinkAway(void* const objectPtr)
  {
    delete static_cast<moho::MotorSinkAway*>(objectPtr);
  }

  /**
   * Address: 0x00696C30 (FUN_00696C30)
   *
   * What it does:
   * Initializes the generic construct-helper lane for `MotorSinkAway`.
   */
  [[nodiscard]] moho::MotorSinkAwayConstruct* InitializeMotorSinkAwayConstructGenericHelperLane()
  {
    InitializeHelperNode(gMotorSinkAwayConstruct);
    gMotorSinkAwayConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_MotorSinkAway_Callback);
    gMotorSinkAwayConstruct.mDeleteCallback = &DeleteConstructedMotorSinkAway;
    return &gMotorSinkAwayConstruct;
  }

  /**
   * Address: 0x00696750 (FUN_00696750)
   *
   * What it does:
   * Initializes the custom construct-helper lane for `MotorSinkAway`.
   */
  [[nodiscard]] moho::MotorSinkAwayConstruct* InitializeMotorSinkAwayConstructCustomHelperLane()
  {
    return InitializeMotorSinkAwayConstructGenericHelperLane();
  }

  /**
   * Address: 0x00696CB0 (FUN_00696CB0)
   *
   * What it does:
   * Initializes the save/load serializer helper lane for `MotorSinkAway`.
   */
  [[nodiscard]] moho::MotorSinkAwaySerializer* InitializeMotorSinkAwaySerializerHelperLane()
  {
    InitializeHelperNode(gMotorSinkAwaySerializer);
    gMotorSinkAwaySerializer.mDeserialize = &moho::MotorSinkAwaySerializer::Deserialize;
    gMotorSinkAwaySerializer.mSerialize = &moho::MotorSinkAwaySerializer::Serialize;
    return &gMotorSinkAwaySerializer;
  }

  /**
   * Address: 0x00697200 (FUN_00697200, serializer load body)
   */
  void DeserializeMotorSinkAwayBody(moho::MotorSinkAway* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedMotorType(), static_cast<moho::EntityMotor*>(object), nullOwner);
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(object), nullOwner);
    archive->ReadFloat(&object->mSinkDeltaY);
  }

  /**
   * Address: 0x00697290 (FUN_00697290, serializer save body)
   */
  void SerializeMotorSinkAwayBody(const moho::MotorSinkAway* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedMotorType(), static_cast<const moho::EntityMotor*>(object), nullOwner);
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(object), nullOwner);
    archive->WriteFloat(object->mSinkDeltaY);
  }

  /**
   * Address: 0x00696FB0 (FUN_00696FB0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the MotorSinkAway deserialize thunk alias to the recovered
   * serializer load body.
   */
  void DeserializeMotorSinkAwayThunkVariantA(moho::MotorSinkAway* const object, gpg::ReadArchive* const archive)
  {
    DeserializeMotorSinkAwayBody(object, archive);
  }

  /**
   * Address: 0x00696FC0 (FUN_00696FC0, serializer save thunk alias)
   * Address: 0x00672550 (FUN_00672550)
   *
   * What it does:
   * Tail-forwards the MotorSinkAway serialize thunk alias to the recovered
   * serializer save body.
   */
  void SerializeMotorSinkAwayThunkVariantA(const moho::MotorSinkAway* const object, gpg::WriteArchive* const archive)
  {
    SerializeMotorSinkAwayBody(object, archive);
  }

  /**
   * Address: 0x006971B0 (FUN_006971B0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the second MotorSinkAway deserialize thunk alias to the
   * recovered serializer load body.
   */
  void DeserializeMotorSinkAwayThunkVariantB(moho::MotorSinkAway* const object, gpg::ReadArchive* const archive)
  {
    DeserializeMotorSinkAwayBody(object, archive);
  }

  /**
   * Address: 0x006971C0 (FUN_006971C0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards the second MotorSinkAway serialize thunk alias to the
   * recovered serializer save body.
   */
  void SerializeMotorSinkAwayThunkVariantB(const moho::MotorSinkAway* const object, gpg::WriteArchive* const archive)
  {
    SerializeMotorSinkAwayBody(object, archive);
  }

  void cleanup_MotorSinkAwayConstruct_atexit()
  {
    (void)moho::cleanup_MotorSinkAwayConstruct();
  }

  void cleanup_MotorSinkAwaySerializer_atexit()
  {
    (void)moho::cleanup_MotorSinkAwaySerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* MotorSinkAway::sType = nullptr;
  CScrLuaMetatableFactory<MotorSinkAway> CScrLuaMetatableFactory<MotorSinkAway>::sInstance{};

  CScrLuaMetatableFactory<MotorSinkAway>& CScrLuaMetatableFactory<MotorSinkAway>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x006971D0 (FUN_006971D0)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<MotorSinkAway>` and returns that singleton.
   */
  CScrLuaMetatableFactory<MotorSinkAway>* startup_CScrLuaMetatableFactory_MotorSinkAway_Index()
  {
    auto& instance = CScrLuaMetatableFactory<MotorSinkAway>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  /**
   * Address: 0x00696FD0 (FUN_00696FD0, Moho::CScrLuaMetatableFactory<Moho::MotorSinkAway>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<MotorSinkAway>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00696500 (FUN_00696500, default ctor)
   */
  MotorSinkAway::MotorSinkAway()
    : EntityMotor()
    , CScriptObject()
    , mSinkDeltaY(0.0f)
  {
    AddInstanceCounterDelta(InstanceCounter<MotorSinkAway>::GetStatItem(), 1);
  }

  /**
   * Address: 0x006963F0 (FUN_006963F0, Lua ctor lane)
   */
  MotorSinkAway::MotorSinkAway(LuaPlus::LuaState* const state, const float sinkDeltaY)
    : EntityMotor()
    , CScriptObject(GetMotorSinkAwayLuaFactoryObject(state), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
    , mSinkDeltaY(sinkDeltaY)
  {
    AddInstanceCounterDelta(InstanceCounter<MotorSinkAway>::GetStatItem(), 1);
  }

  /**
   * Address: 0x00696580 (FUN_00696580, deleting-thunk chain)
   * Address: 0x006965A0 (FUN_006965A0, non-deleting body)
   */
  MotorSinkAway::~MotorSinkAway()
  {
    AddInstanceCounterDelta(InstanceCounter<MotorSinkAway>::GetStatItem(), -1);
  }

  /**
   * Address: 0x006963B0 (FUN_006963B0, Moho::MotorSinkAway::GetClass)
   */
  gpg::RType* MotorSinkAway::GetClass() const
  {
    return CachedMotorSinkAwayType();
  }

  /**
   * Address: 0x006963D0 (FUN_006963D0, Moho::MotorSinkAway::GetDerivedObjectRef)
   */
  gpg::RRef MotorSinkAway::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00696940 (FUN_00696940, update lane)
   */
  void MotorSinkAway::Update(Entity* const)
  {}

  /**
   * Address: 0x00696600 (FUN_00696600, Moho::MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo)
   */
  MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(MotorSinkAway), this);
  }

  /**
   * Address: 0x00696700 (FUN_00696700, MotorSinkAwayTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `MotorSinkAwayTypeInfo`
   * instance while preserving outer storage ownership.
   */
  [[maybe_unused]] void DestroyMotorSinkAwayTypeInfoBody(MotorSinkAwayTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x006966A0 (FUN_006966A0, Moho::MotorSinkAwayTypeInfo::dtr)
   */
  MotorSinkAwayTypeInfo::~MotorSinkAwayTypeInfo()
  {
    DestroyMotorSinkAwayTypeInfoBody(this);
  }

  /**
   * Address: 0x00696690 (FUN_00696690, Moho::MotorSinkAwayTypeInfo::GetName)
   */
  const char* MotorSinkAwayTypeInfo::GetName() const
  {
    return "MotorSinkAway";
  }

  /**
   * Address: 0x00696E90 (FUN_00696E90, Moho::MotorSinkAwayTypeInfo::AddBase_CScriptObject)
   */
  void MotorSinkAwayTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = gpg::RType::BaseSubobjectOffset<MotorSinkAway, CScriptObject>();
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00696EF0 (FUN_00696EF0, Moho::MotorSinkAwayTypeInfo::AddBase_Motor)
   * Address: 0x00696740 (FUN_00696740, add-base thunk lane)
   */
  void MotorSinkAwayTypeInfo::AddBase_Motor(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedMotorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00696660 (FUN_00696660, Moho::MotorSinkAwayTypeInfo::Init)
   */
  void MotorSinkAwayTypeInfo::Init()
  {
    size_ = sizeof(MotorSinkAway);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    AddBase_Motor(this);
    Finish();
  }

  /**
   * Address: 0x00696880 (FUN_00696880, serializer load thunk)
   */
  void MotorSinkAwaySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    DeserializeMotorSinkAwayBody(reinterpret_cast<MotorSinkAway*>(objectPtr), archive);
  }

  /**
   * Address: 0x00696890 (FUN_00696890, serializer save thunk)
   */
  void MotorSinkAwaySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SerializeMotorSinkAwayBody(reinterpret_cast<const MotorSinkAway*>(objectPtr), archive);
  }

  /**
   * Address: 0x006968B0 (FUN_006968B0, serializer registration lane)
   */
  void MotorSinkAwaySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedMotorSinkAwayType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00696C60 (FUN_00696C60, Moho::MotorSinkAwayConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `MotorSinkAway`.
   */
  void MotorSinkAwayConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedMotorSinkAwayType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BFD210 (FUN_00BFD210, cleanup_MotorSinkAwayTypeInfo)
   */
  void cleanup_MotorSinkAwayTypeInfo()
  {
    if (!gMotorSinkAwayTypeInfoConstructed) {
      return;
    }

    MotorSinkAwayTypeInfoStorageRef().~MotorSinkAwayTypeInfo();
    gMotorSinkAwayTypeInfoConstructed = false;
    MotorSinkAway::sType = nullptr;
  }

  /**
   * Address: 0x00BFD270 (FUN_00BFD270, cleanup_MotorSinkAwayConstruct)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwayConstruct()
  {
    return UnlinkHelperNode(gMotorSinkAwayConstruct);
  }

  /**
   * Address: 0x00BFD2A0 (FUN_00BFD2A0, cleanup_MotorSinkAwaySerializer)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwaySerializer()
  {
    return UnlinkHelperNode(gMotorSinkAwaySerializer);
  }

  /**
   * Address: 0x00BD5D50 (FUN_00BD5D50, register_MotorSinkAwayTypeInfo)
   */
  void register_MotorSinkAwayTypeInfo()
  {
    if (!gMotorSinkAwayTypeInfoConstructed) {
      new (gMotorSinkAwayTypeInfoStorage) MotorSinkAwayTypeInfo();
      gMotorSinkAwayTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_MotorSinkAwayTypeInfo);
  }

  /**
   * Address: 0x00BD5D70 (FUN_00BD5D70, register_MotorSinkAwayConstruct)
   */
  int register_MotorSinkAwayConstruct()
  {
    (void)InitializeMotorSinkAwayConstructCustomHelperLane();
    gMotorSinkAwayConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_MotorSinkAwayConstruct_atexit);
  }

  /**
   * Address: 0x00BD5DB0 (FUN_00BD5DB0, register_MotorSinkAwaySerializer)
   */
  int register_MotorSinkAwaySerializer()
  {
    (void)InitializeMotorSinkAwaySerializerHelperLane();
    return std::atexit(&cleanup_MotorSinkAwaySerializer_atexit);
  }

  /**
   * Address: 0x00BD5E00 (FUN_00BD5E00, register_CScrLuaMetatableFactory_MotorSinkAway_Index)
   */
  int register_CScrLuaMetatableFactory_MotorSinkAway_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<MotorSinkAway>::Instance().SetFactoryObjectIndexForRecovery(index);
    gRecoveredCScrLuaMetatableFactoryMotorSinkAwayIndex = index;
    return index;
  }
} // namespace moho

namespace
{
  /**
   * Address: 0x00696BD0 (FUN_00696BD0)
   *
   * What it does:
   * Increments the `MotorSinkAway` instance-counter lane and returns the
   * caller-provided passthrough value.
   */
  [[maybe_unused]] void* IncrementMotorSinkAwayInstanceCounterPassThrough(void* const value) noexcept
  {
    AddInstanceCounterDelta(moho::InstanceCounter<moho::MotorSinkAway>::GetStatItem(), 1);
    return value;
  }

  /**
   * Address: 0x00696BF0 (FUN_00696BF0)
   *
   * What it does:
   * Decrements the `MotorSinkAway` instance-counter lane and returns the
   * address of that counter slot.
   */
  [[maybe_unused]] volatile std::int32_t* DecrementMotorSinkAwayInstanceCounterAndReturnLane() noexcept
  {
    moho::StatItem* const statItem = moho::InstanceCounter<moho::MotorSinkAway>::GetStatItem();
    if (!statItem) {
      return nullptr;
    }

    AddInstanceCounterDelta(statItem, -1);
    return &statItem->mPrimaryValueBits;
  }
} // namespace

/**
 * Address: 0x00696D90 (FUN_00696D90, Moho::InstanceCounter<Moho::MotorSinkAway>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for motor-sink-away
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::MotorSinkAway>::GetStatItem()
{
  static moho::StatItem* sEngineStat_InstanceCounts_MotorSinkAway = nullptr;
  if (sEngineStat_InstanceCounts_MotorSinkAway) {
    return sEngineStat_InstanceCounts_MotorSinkAway;
  }

  std::string statPath("Instance Counts_");
  const char* const rawTypeName = typeid(moho::MotorSinkAway).name();
  for (const char* it = rawTypeName; it && *it != '\0'; ++it) {
    if (*it != '_') {
      statPath.push_back(*it);
    }
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sEngineStat_InstanceCounts_MotorSinkAway = engineStats->GetItem(statPath.c_str(), true);
  return sEngineStat_InstanceCounts_MotorSinkAway;
}

namespace
{
  struct MotorSinkAwayBootstrap
  {
    MotorSinkAwayBootstrap()
    {
      moho::register_MotorSinkAwayTypeInfo();
      (void)moho::register_MotorSinkAwayConstruct();
      (void)moho::register_MotorSinkAwaySerializer();
      (void)moho::register_CScrLuaMetatableFactory_MotorSinkAway_Index();
    }
  };

  [[maybe_unused]] MotorSinkAwayBootstrap gMotorSinkAwayBootstrap;
} // namespace

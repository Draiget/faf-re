#include "moho/entity/MotorSinkAway.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/VTransform.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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
  // Address: 0x00BD5DB0 (dynamic initializer for the global
  // `MotorSinkAwaySerializer` singleton, __xc_a-reachable) -- MSVC's own
  // compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<MotorSinkAway>` ctor (self-links into
  // `sNewHelpers`, binds `mLoadCallback`/`mSaveCallback` to the template's
  // `Deserialize`/`Serialize`, installs the vtable) and registers the real
  // destructor (0x00BFD2A0, no recovered mangled name; body confirmed via
  // raw asm to just call `ResetLinks()`) via `atexit`. Dead zero-xref COMDAT
  // duplicate ctor: 0x00696CB0. `FUN_006968E0` and `FUN_00696910` are
  // duplicate-emission twins of this exact unlink/reset lane (same
  // `ResetLinks()` shape, folded to separate addresses); they have no
  // distinct source-level body of their own.
  moho::MotorSinkAwaySerializer gMotorSinkAwaySerializer;
  // Address: 0x010B528C -- process-global `MotorSinkAwayConstruct` singleton.
  moho::MotorSinkAwayConstruct gMotorSinkAwayConstruct;
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

  template <class TObject>
  [[nodiscard]] gpg::RRef MakeDerivedRef(TObject* const object, gpg::RType* const baseType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = baseType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = baseType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = baseType;
    }

    std::int32_t baseOffset = 0;
    const bool isDerived =
      dynamicType != nullptr && baseType != nullptr && dynamicType->IsDerivedFrom(baseType, &baseOffset);
    if (!isDerived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj = reinterpret_cast<void*>(reinterpret_cast<char*>(object) - baseOffset);
    out.mType = dynamicType;
    return out;
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
    gpg::RRef ref{};
    (void)gpg::RRef_MotorSinkAway(&ref, value);
    out->mObj = ref.mObj;
    out->mType = ref.mType;
    return out;
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

    gpg::RRef ref{};
    (void)gpg::RRef_MotorSinkAway(&ref, object);
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
   * Address: 0x00696940 (FUN_00696940, Moho::MotorSinkAway::Update)
   *
   * What it does:
   * Sinks the entity by nudging its current transform down `mSinkDeltaY * 0.1`
   * along Y each tick, preserving orientation and X/Z, then submits it as the
   * pending transform (used for destroyed units settling under the surface).
   */
  void MotorSinkAway::Update(Entity* const entity)
  {
    VTransform tran = entity->GetTransformWm3();
    tran.pos_.y = (mSinkDeltaY * 0.1f) + tran.pos_.y;
    entity->SetPendingTransform(tran, 1.0f);
  }

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
  void DestroyMotorSinkAwayTypeInfoBody(MotorSinkAwayTypeInfo* const typeInfo) noexcept
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
   * Address: 0x00697200 (FUN_00697200, Moho::MotorSinkAway::MemberDeserialize)
   */
  void MotorSinkAway::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedMotorType(), static_cast<moho::EntityMotor*>(this), nullOwner);
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(this), nullOwner);
    archive->ReadFloat(&mSinkDeltaY);
  }

  /**
   * Address: 0x00697290 (FUN_00697290, Moho::MotorSinkAway::MemberSerialize)
   */
  void MotorSinkAway::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedMotorType(), static_cast<const moho::EntityMotor*>(this), nullOwner);
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(this), nullOwner);
    archive->WriteFloat(mSinkDeltaY);
  }

  /**
   * Address: 0x00BD5D70 (FUN_00BD5D70, dynamic initializer for the global
   * `MotorSinkAwayConstruct` singleton)
   */
  MotorSinkAwayConstruct::MotorSinkAwayConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&Construct_MotorSinkAway_Callback))
    , mDeleteCallback(&DeleteConstructedMotorSinkAway)
  {}

  /**
   * Address: 0x00BFD270 (FUN_00BFD270, Moho::MotorSinkAwayConstruct::~MotorSinkAwayConstruct)
   *
   * `FUN_00696780` and `FUN_006967B0` are duplicate-emission twins of this
   * exact unlink/reset lane (same `ResetLinks()` shape, folded to separate
   * addresses); they have no distinct source-level body of their own.
   */
  MotorSinkAwayConstruct::~MotorSinkAwayConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00696C60 (FUN_00696C60, Moho::MotorSinkAwayConstruct::Init)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `MotorSinkAway`.
   */
  void MotorSinkAwayConstruct::Init()
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
   * Address: 0x00BD5DB0 (FUN_00BD5DB0, register_MotorSinkAwaySerializer)
   *
   * What it does:
   * Forces this translation unit's global `MotorSinkAwaySerializer` instance
   * to link into the reflection bootstrap sequence. See the Doxygen comment
   * on the declaration (MotorSinkAway.h) and on `gMotorSinkAwaySerializer`
   * above for why this function's body has no field-setting logic of its
   * own.
   */
  int register_MotorSinkAwaySerializer()
  {
    (void)gMotorSinkAwaySerializer;
    return 0;
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

namespace gpg
{
  /**
   * Address: 0x00697000 (FUN_00697000, gpg::RRef_MotorSinkAway)
   * Mangled: ?RRef_MotorSinkAway@gpg@@ (per-type reflection-ref builder)
   *
   * IDA signature:
   * gpg::RRef* __cdecl gpg::RRef_MotorSinkAway(gpg::RRef* out, Moho::MotorSinkAway* value);
   *
   * What it does:
   * Builds one typed reflection reference for `moho::MotorSinkAway*`. On the
   * exact-type fast path returns `{value, sType}`; for a derived object it
   * resolves the most-derived RType, asserts derivation, and stores
   * `{value - baseOffset, dynamicType}`.
   */
  gpg::RRef* RRef_MotorSinkAway(gpg::RRef* const out, moho::MotorSinkAway* const value)
  {
    if (!out) {
      return nullptr;
    }

    *out = MakeDerivedRef(value, CachedMotorSinkAwayType());
    return out;
  }
} // namespace gpg

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
      (void)moho::register_MotorSinkAwaySerializer();
      (void)moho::register_CScrLuaMetatableFactory_MotorSinkAway_Index();
    }
  };

  [[maybe_unused]] MotorSinkAwayBootstrap gMotorSinkAwayBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_MotorSinkAwayTypeInfo_905beb, moho::register_MotorSinkAwayTypeInfo)

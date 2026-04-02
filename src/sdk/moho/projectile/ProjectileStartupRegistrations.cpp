#include "moho/projectile/ProjectileStartupRegistrations.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/projectile/Projectile.h"
#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/Sim.h"

#pragma init_seg(lib)

namespace moho
{
  bool dbg_Projectile = false;
  gpg::RType* CProjectileAttributes::sType = nullptr;
  CScrLuaMetatableFactory<Projectile> CScrLuaMetatableFactory<Projectile>::sInstance{};
} // namespace moho

namespace
{
  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(TSerializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  template <typename TSerializer>
  void InitializeSerializerNode(TSerializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  template <typename TSerializer>
  [[nodiscard]] gpg::SerHelperBase* UnlinkSerializerNode(TSerializer& serializer) noexcept
  {
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;

    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] moho::TConVar<bool>& GetDbgProjectileConVar()
  {
    static moho::TConVar<bool> conVar(
      "dbg_Projectile",
      "Enable projectile debug diagnostics",
      &moho::dbg_Projectile
    );
    return conVar;
  }

  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kSetLocalAngularVelocityHelpText = "Projectile:SetLocalAngularVelocity(x,y,z)";
  constexpr const char* kCreateChildProjectileHelpText = "Projectile:CreateChildProjectile(blueprint)";
  constexpr const char* kMissingProjectileBlueprintError =
    "Blueprint for projectile %s not found!, returning a nil object instead";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("sim");
    return sSet;
  }

  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  [[nodiscard]] gpg::RType* CachedRProjectileBlueprintType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCProjectileAttributesType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CProjectileAttributes));
    }
    return cached;
  }

  [[nodiscard]] moho::RProjectileBlueprint* ReadProjectileBlueprintPointer(
    gpg::ReadArchive* archive,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedRProjectileBlueprintType());
    GPG_ASSERT(upcast.mObj != nullptr);
    return static_cast<moho::RProjectileBlueprint*>(upcast.mObj);
  }

  [[nodiscard]] gpg::RRef MakeProjectileBlueprintRef(moho::RProjectileBlueprint* blueprint)
  {
    gpg::RRef ref{};
    ref.mObj = blueprint;
    ref.mType = CachedRProjectileBlueprintType();
    return ref;
  }

  class RManyToOneBroadcasterProjectileImpactTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "ManyToOneBroadcaster<EProjectileImpactEvent>";
    }

    void Init() override
    {
      size_ = 0x08;
      gpg::RType::Init();
      Finish();
    }
  };

  class RManyToOneListenerProjectileImpactTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override
    {
      return "ManyToOneListener<EProjectileImpactEvent>";
    }

    void Init() override
    {
      size_ = 0x0C;
      gpg::RType::Init();
      Finish();
    }
  };

  template <typename TEnum>
  class PrimitiveEnumSerializer
  {
  public:
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mHelperNext) == 0x04,
    "PrimitiveEnumSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mHelperPrev) == 0x08,
    "PrimitiveEnumSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mDeserialize) == 0x0C,
    "PrimitiveEnumSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>, mSerialize) == 0x10,
    "PrimitiveEnumSerializer::mSerialize offset must be 0x10"
  );
  static_assert(
    sizeof(PrimitiveEnumSerializer<moho::EProjectileImpactEvent>) == 0x14,
    "PrimitiveEnumSerializer size must be 0x14"
  );

  alignas(moho::EProjectileImpactEventTypeInfo)
    unsigned char gEProjectileImpactEventTypeInfoStorage[sizeof(moho::EProjectileImpactEventTypeInfo)];
  bool gEProjectileImpactEventTypeInfoConstructed = false;

  alignas(moho::CProjectileAttributesTypeInfo)
    unsigned char gCProjectileAttributesTypeInfoStorage[sizeof(moho::CProjectileAttributesTypeInfo)];
  bool gCProjectileAttributesTypeInfoConstructed = false;

  alignas(moho::CProjectileAttributesSerializer)
    unsigned char gCProjectileAttributesSerializerStorage[sizeof(moho::CProjectileAttributesSerializer)];
  bool gCProjectileAttributesSerializerConstructed = false;

  alignas(RManyToOneBroadcasterProjectileImpactTypeInfo)
    unsigned char gManyToOneBroadcasterProjectileImpactTypeInfoStorage[sizeof(RManyToOneBroadcasterProjectileImpactTypeInfo)];
  bool gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = false;

  alignas(RManyToOneListenerProjectileImpactTypeInfo)
    unsigned char gManyToOneListenerProjectileImpactTypeInfoStorage[sizeof(RManyToOneListenerProjectileImpactTypeInfo)];
  bool gManyToOneListenerProjectileImpactTypeInfoConstructed = false;

  PrimitiveEnumSerializer<moho::EProjectileImpactEvent> gEProjectileImpactEventPrimitiveSerializer{};

  [[nodiscard]] moho::EProjectileImpactEventTypeInfo& EProjectileImpactEventTypeInfoStorageRef()
  {
    return *reinterpret_cast<moho::EProjectileImpactEventTypeInfo*>(gEProjectileImpactEventTypeInfoStorage);
  }

  [[nodiscard]] moho::CProjectileAttributesTypeInfo& CProjectileAttributesTypeInfoStorageRef()
  {
    return *reinterpret_cast<moho::CProjectileAttributesTypeInfo*>(gCProjectileAttributesTypeInfoStorage);
  }

  [[nodiscard]] moho::CProjectileAttributesSerializer& CProjectileAttributesSerializerStorageRef()
  {
    return *reinterpret_cast<moho::CProjectileAttributesSerializer*>(gCProjectileAttributesSerializerStorage);
  }

  [[nodiscard]] RManyToOneBroadcasterProjectileImpactTypeInfo& ManyToOneBroadcasterTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneBroadcasterProjectileImpactTypeInfo*>(gManyToOneBroadcasterProjectileImpactTypeInfoStorage);
  }

  [[nodiscard]] RManyToOneListenerProjectileImpactTypeInfo& ManyToOneListenerTypeInfoStorageRef()
  {
    return *reinterpret_cast<RManyToOneListenerProjectileImpactTypeInfo*>(gManyToOneListenerProjectileImpactTypeInfoStorage);
  }

  [[nodiscard]] gpg::REnumType* ConstructEProjectileImpactEventTypeInfo()
  {
    if (!gEProjectileImpactEventTypeInfoConstructed) {
      new (gEProjectileImpactEventTypeInfoStorage) moho::EProjectileImpactEventTypeInfo();
      gEProjectileImpactEventTypeInfoConstructed = true;
    }

    auto& typeInfo = EProjectileImpactEventTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::EProjectileImpactEvent), &typeInfo);
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructCProjectileAttributesTypeInfo()
  {
    if (!gCProjectileAttributesTypeInfoConstructed) {
      new (gCProjectileAttributesTypeInfoStorage) moho::CProjectileAttributesTypeInfo();
      gCProjectileAttributesTypeInfoConstructed = true;
    }

    auto& typeInfo = CProjectileAttributesTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::CProjectileAttributes), &typeInfo);
    moho::CProjectileAttributes::sType = &typeInfo;
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructManyToOneBroadcasterProjectileImpactTypeInfo()
  {
    if (!gManyToOneBroadcasterProjectileImpactTypeInfoConstructed) {
      new (gManyToOneBroadcasterProjectileImpactTypeInfoStorage) RManyToOneBroadcasterProjectileImpactTypeInfo();
      gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneBroadcasterTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::ManyToOneBroadcaster_EProjectileImpactEvent), &typeInfo);
    moho::ManyToOneBroadcaster_EProjectileImpactEvent::sType = &typeInfo;
    return &typeInfo;
  }

  [[nodiscard]] gpg::RType* ConstructManyToOneListenerProjectileImpactTypeInfo()
  {
    if (!gManyToOneListenerProjectileImpactTypeInfoConstructed) {
      new (gManyToOneListenerProjectileImpactTypeInfoStorage) RManyToOneListenerProjectileImpactTypeInfo();
      gManyToOneListenerProjectileImpactTypeInfoConstructed = true;
    }

    auto& typeInfo = ManyToOneListenerTypeInfoStorageRef();
    gpg::PreRegisterRType(typeid(moho::ManyToOneListener_EProjectileImpactEvent), &typeInfo);
    moho::ManyToOneListener_EProjectileImpactEvent::sType = &typeInfo;
    return &typeInfo;
  }

  /**
   * Address: 0x0069EEC0 (FUN_0069EEC0)
   */
  void Deserialize_EProjectileImpactEvent_Primitive(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    int value = 0;
    archive->ReadInt(&value);
    *reinterpret_cast<moho::EProjectileImpactEvent*>(static_cast<std::uintptr_t>(objectPtr)) =
      static_cast<moho::EProjectileImpactEvent>(value);
  }

  /**
   * Address: 0x0069EEE0 (FUN_0069EEE0)
   */
  void Serialize_EProjectileImpactEvent_Primitive(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef*
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto value = *reinterpret_cast<const moho::EProjectileImpactEvent*>(static_cast<std::uintptr_t>(objectPtr));
    archive->WriteInt(static_cast<int>(value));
  }

  /**
   * Address: 0x0069F470 (FUN_0069F470)
   */
  void Deserialize_CProjectileAttributesBody(
    gpg::ReadArchive* archive,
    moho::CProjectileAttributes& attributes,
    const gpg::RRef& ownerRef
  )
  {
    attributes.mBlueprint = ReadProjectileBlueprintPointer(archive, ownerRef);
    archive->ReadFloat(&attributes.mMaxZigZag);
    archive->ReadFloat(&attributes.mZigZagFrequency);
    archive->ReadFloat(&attributes.mDetonateAboveHeight);
    archive->ReadFloat(&attributes.mDetonateBelowHeight);
  }

  /**
   * Address: 0x0069F4D0 (FUN_0069F4D0)
   */
  void Serialize_CProjectileAttributesBody(
    gpg::WriteArchive* archive,
    const moho::CProjectileAttributes& attributes,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef blueprintRef = MakeProjectileBlueprintRef(attributes.mBlueprint);
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, ownerRef);
    archive->WriteFloat(attributes.mMaxZigZag);
    archive->WriteFloat(attributes.mZigZagFrequency);
    archive->WriteFloat(attributes.mDetonateAboveHeight);
    archive->WriteFloat(attributes.mDetonateBelowHeight);
  }

  void cleanup_EProjectileImpactEventPrimitiveSerializer_atexit()
  {
    (void)moho::cleanup_EProjectileImpactEventPrimitiveSerializer();
  }

  void cleanup_CProjectileAttributesSerializer_atexit()
  {
    (void)moho::cleanup_CProjectileAttributesSerializer();
  }

  struct ProjectileStartupBootstrap
  {
    ProjectileStartupBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_Projectile_Index();
      moho::register_TConVar_dbg_Projectile();
      (void)moho::register_EProjectileImpactEventTypeInfo();
      (void)moho::register_EProjectileImpactEventPrimitiveSerializer();
      (void)moho::register_CProjectileAttributesTypeInfo();
      (void)moho::register_CProjectileAttributesSerializer();
      (void)moho::register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo();
      (void)moho::register_ManyToOneListener_EProjectileImpactEvent_TypeInfo();
    }
  };

  [[maybe_unused]] ProjectileStartupBootstrap gProjectileStartupBootstrap;

  template <typename TEnum>
  void PrimitiveEnumSerializer<TEnum>::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = gpg::LookupRType(typeid(TEnum));
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0067FFE0 (FUN_0067FFE0, Moho::CScrLuaMetatableFactory<Moho::Projectile>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<Projectile>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  CScrLuaMetatableFactory<Projectile>& CScrLuaMetatableFactory<Projectile>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00BD50D0 (FUN_00BD50D0, register_CScrLuaMetatableFactory_Projectile_Index)
   *
   * What it does:
   * Allocates one factory-object index and assigns it to projectile metatable factory singleton.
   */
  int register_CScrLuaMetatableFactory_Projectile_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<Projectile>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x006A0FB0 (FUN_006A0FB0, Moho::PROJ_Create)
   *
   * What it does:
   * Allocates one projectile and forwards launch parameters into the
   * projectile constructor path.
   */
  Projectile* PROJ_Create(
    Sim* const sim,
    const RProjectileBlueprint* const blueprint,
    CArmyImpl* const army,
    Entity* const sourceEntity,
    const VTransform& launchTransform,
    const float damage,
    const float damageRadius,
    const msvc8::string& damageTypeName,
    const CAiTarget& target,
    const bool isChildProjectile
  )
  {
    if (blueprint == nullptr) {
      return nullptr;
    }

    return new Projectile(
      blueprint,
      sim,
      army,
      sourceEntity,
      launchTransform,
      damage,
      damageRadius,
      damageTypeName,
      target,
      isChildProjectile
    );
  }

  /**
   * Address: 0x006A2FE0 (FUN_006A2FE0, cfunc_ProjectileSetLocalAngularVelocityL)
   *
   * What it does:
   * Reads `(projectile, x, y, z)` from Lua and writes local angular velocity
   * lanes before returning the projectile Lua object.
   */
  int cfunc_ProjectileSetLocalAngularVelocityL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 4) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetLocalAngularVelocityHelpText, 4, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const projectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&xArg, "number");
    }
    const float localAngularVelocityX = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&yArg, "number");
    }
    const float localAngularVelocityY = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject zArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&zArg, "number");
    }
    projectile->mLocalAngularVelocity.z = static_cast<float>(lua_tonumber(rawState, 4));
    projectile->mLocalAngularVelocity.x = localAngularVelocityX;
    projectile->mLocalAngularVelocity.y = localAngularVelocityY;

    projectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A2F60 (FUN_006A2F60, cfunc_ProjectileSetLocalAngularVelocity)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileSetLocalAngularVelocityL`.
   */
  int cfunc_ProjectileSetLocalAngularVelocity(lua_State* const luaContext)
  {
    return cfunc_ProjectileSetLocalAngularVelocityL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A2F80 (FUN_006A2F80, func_ProjectileSetLocalAngularVelocity_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:SetLocalAngularVelocity(x,y,z)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileSetLocalAngularVelocity_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "SetLocalAngularVelocity",
      &moho::cfunc_ProjectileSetLocalAngularVelocity,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kSetLocalAngularVelocityHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006A3B20 (FUN_006A3B20, cfunc_ProjectileCreateChildProjectileL)
   *
   * What it does:
   * Reads `(projectile, blueprintId)`, creates one child projectile from the
   * source projectile launch profile, and returns the created Lua projectile.
   */
  int cfunc_ProjectileCreateChildProjectileL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateChildProjectileHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject projectileObject(LuaPlus::LuaStackObject(state, 1));
    Projectile* const sourceProjectile = SCR_FromLua_Projectile(projectileObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* blueprintText = lua_tostring(rawState, 2);
    if (!blueprintText) {
      LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
      blueprintText = "";
    }

    RResId projectileId{};
    gpg::STR_InitFilename(&projectileId.name, blueprintText);

    Sim* const sim = sourceProjectile ? sourceProjectile->SimulationRef : nullptr;
    RProjectileBlueprint* const blueprint =
      (sim && sim->mRules) ? sim->mRules->GetProjectileBlueprint(projectileId) : nullptr;
    if (!blueprint) {
      LuaPlus::LuaState::Error(state, kMissingProjectileBlueprintError, blueprintText);
      lua_pushnil(rawState);
      (void)lua_gettop(rawState);
      return 1;
    }

    Projectile* const childProjectile = PROJ_Create(
      sim,
      blueprint,
      sourceProjectile->ArmyRef,
      sourceProjectile,
      sourceProjectile->GetTransformWm3(),
      sourceProjectile->mDamage,
      sourceProjectile->mDamageRadius,
      sourceProjectile->mDamageTypeName,
      sourceProjectile->mTargetPosData,
      true
    );
    childProjectile->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006A3AA0 (FUN_006A3AA0, cfunc_ProjectileCreateChildProjectile)
   *
   * What it does:
   * Unwraps Lua callback context and forwards to
   * `cfunc_ProjectileCreateChildProjectileL`.
   */
  int cfunc_ProjectileCreateChildProjectile(lua_State* const luaContext)
  {
    return cfunc_ProjectileCreateChildProjectileL(ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006A3AC0 (FUN_006A3AC0, func_ProjectileCreateChildProjectile_LuaFuncDef)
   *
   * What it does:
   * Publishes `Projectile:CreateChildProjectile(blueprint)` Lua binder
   * definition in the `sim` init-form set.
   */
  CScrLuaInitForm* func_ProjectileCreateChildProjectile_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateChildProjectile",
      &moho::cfunc_ProjectileCreateChildProjectile,
      &CScrLuaMetatableFactory<Projectile>::Instance(),
      "Projectile",
      kCreateChildProjectileHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x0069A7B0 (FUN_0069A7B0, Moho::EProjectileImpactEventTypeInfo::dtr)
   */
  EProjectileImpactEventTypeInfo::~EProjectileImpactEventTypeInfo() = default;

  /**
   * Address: 0x0069A7A0 (FUN_0069A7A0, Moho::EProjectileImpactEventTypeInfo::GetName)
   */
  const char* EProjectileImpactEventTypeInfo::GetName() const
  {
    return "EProjectileImpactEvent";
  }

  /**
   * Address: 0x0069A780 (FUN_0069A780, Moho::EProjectileImpactEventTypeInfo::Init)
   */
  void EProjectileImpactEventTypeInfo::Init()
  {
    size_ = sizeof(EProjectileImpactEvent);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0069A8E0 (FUN_0069A8E0, Moho::CProjectileAttributesTypeInfo::dtr)
   */
  CProjectileAttributesTypeInfo::~CProjectileAttributesTypeInfo() = default;

  /**
   * Address: 0x0069A8D0 (FUN_0069A8D0, Moho::CProjectileAttributesTypeInfo::GetName)
   */
  const char* CProjectileAttributesTypeInfo::GetName() const
  {
    return "CProjectileAttributes";
  }

  /**
   * Address: 0x0069A8B0 (FUN_0069A8B0, Moho::CProjectileAttributesTypeInfo::Init)
   */
  void CProjectileAttributesTypeInfo::Init()
  {
    size_ = sizeof(CProjectileAttributes);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x0069A990 (FUN_0069A990, Moho::CProjectileAttributesSerializer::Deserialize)
   */
  void CProjectileAttributesSerializer::Deserialize(
    gpg::ReadArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    gpg::RRef owner{};
    if (ownerRef != nullptr) {
      owner = *ownerRef;
    }

    auto& attributes = *reinterpret_cast<CProjectileAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    Deserialize_CProjectileAttributesBody(archive, attributes, owner);
  }

  /**
   * Address: 0x0069A9A0 (FUN_0069A9A0, Moho::CProjectileAttributesSerializer::Serialize)
   */
  void CProjectileAttributesSerializer::Serialize(
    gpg::WriteArchive* archive,
    int objectPtr,
    int,
    gpg::RRef* ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    gpg::RRef owner{};
    if (ownerRef != nullptr) {
      owner = *ownerRef;
    }

    const auto& attributes = *reinterpret_cast<const CProjectileAttributes*>(static_cast<std::uintptr_t>(objectPtr));
    Serialize_CProjectileAttributesBody(archive, attributes, owner);
  }

  /**
   * Address: 0x0069E900 (FUN_0069E900, serializer registration lane)
   */
  void CProjectileAttributesSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const typeInfo = CachedCProjectileAttributesType();
    GPG_ASSERT(typeInfo->serLoadFunc_ == nullptr || typeInfo->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(typeInfo->serSaveFunc_ == nullptr || typeInfo->serSaveFunc_ == mSerialize);
    typeInfo->serLoadFunc_ = mDeserialize;
    typeInfo->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD510 (FUN_00BFD510, cleanup_TConVar_dbg_Projectile)
   */
  void cleanup_TConVar_dbg_Projectile()
  {
    TeardownConCommandRegistration(GetDbgProjectileConVar());
  }

  /**
   * Address: 0x00BD62F0 (FUN_00BD62F0, register_TConVar_dbg_Projectile)
   */
  void register_TConVar_dbg_Projectile()
  {
    RegisterConCommand(GetDbgProjectileConVar());
    (void)std::atexit(&cleanup_TConVar_dbg_Projectile);
  }

  /**
   * Address: 0x00BFD540 (FUN_00BFD540, cleanup_EProjectileImpactEventTypeInfo)
   */
  void cleanup_EProjectileImpactEventTypeInfo()
  {
    if (!gEProjectileImpactEventTypeInfoConstructed) {
      return;
    }

    EProjectileImpactEventTypeInfoStorageRef().~EProjectileImpactEventTypeInfo();
    gEProjectileImpactEventTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BD6330 (FUN_00BD6330, register_EProjectileImpactEventTypeInfo)
   */
  int register_EProjectileImpactEventTypeInfo()
  {
    (void)ConstructEProjectileImpactEventTypeInfo();
    return std::atexit(&cleanup_EProjectileImpactEventTypeInfo);
  }

  /**
   * Address: 0x00BFD550 (FUN_00BFD550, cleanup_EProjectileImpactEventPrimitiveSerializer)
   */
  gpg::SerHelperBase* cleanup_EProjectileImpactEventPrimitiveSerializer()
  {
    return UnlinkSerializerNode(gEProjectileImpactEventPrimitiveSerializer);
  }

  /**
   * Address: 0x00BD6350 (FUN_00BD6350, register_EProjectileImpactEventPrimitiveSerializer)
   */
  int register_EProjectileImpactEventPrimitiveSerializer()
  {
    new (&gEProjectileImpactEventPrimitiveSerializer) PrimitiveEnumSerializer<EProjectileImpactEvent>();
    InitializeSerializerNode(gEProjectileImpactEventPrimitiveSerializer);
    gEProjectileImpactEventPrimitiveSerializer.mDeserialize = &Deserialize_EProjectileImpactEvent_Primitive;
    gEProjectileImpactEventPrimitiveSerializer.mSerialize = &Serialize_EProjectileImpactEvent_Primitive;
    return std::atexit(&cleanup_EProjectileImpactEventPrimitiveSerializer_atexit);
  }

  /**
   * Address: 0x00BFD580 (FUN_00BFD580, cleanup_CProjectileAttributesTypeInfo)
   */
  void cleanup_CProjectileAttributesTypeInfo()
  {
    if (!gCProjectileAttributesTypeInfoConstructed) {
      return;
    }

    CProjectileAttributesTypeInfoStorageRef().~CProjectileAttributesTypeInfo();
    gCProjectileAttributesTypeInfoConstructed = false;
    CProjectileAttributes::sType = nullptr;
  }

  /**
   * Address: 0x00BD6390 (FUN_00BD6390, register_CProjectileAttributesTypeInfo)
   */
  int register_CProjectileAttributesTypeInfo()
  {
    (void)ConstructCProjectileAttributesTypeInfo();
    return std::atexit(&cleanup_CProjectileAttributesTypeInfo);
  }

  /**
   * Address: 0x00BFD5E0 (FUN_00BFD5E0, cleanup_CProjectileAttributesSerializer)
   */
  gpg::SerHelperBase* cleanup_CProjectileAttributesSerializer()
  {
    return UnlinkSerializerNode(CProjectileAttributesSerializerStorageRef());
  }

  /**
   * Address: 0x00BD63B0 (FUN_00BD63B0, register_CProjectileAttributesSerializer)
   */
  int register_CProjectileAttributesSerializer()
  {
    if (!gCProjectileAttributesSerializerConstructed) {
      new (gCProjectileAttributesSerializerStorage) CProjectileAttributesSerializer();
      gCProjectileAttributesSerializerConstructed = true;
    }

    CProjectileAttributesSerializer& serializer = CProjectileAttributesSerializerStorageRef();
    InitializeSerializerNode(serializer);
    serializer.mDeserialize = &CProjectileAttributesSerializer::Deserialize;
    serializer.mSerialize = &CProjectileAttributesSerializer::Serialize;
    return std::atexit(&cleanup_CProjectileAttributesSerializer_atexit);
  }

  /**
   * Address: 0x00BFD7C0 (FUN_00BFD7C0, cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   */
  void cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo()
  {
    if (!gManyToOneBroadcasterProjectileImpactTypeInfoConstructed) {
      return;
    }

    ManyToOneBroadcasterTypeInfoStorageRef().~RManyToOneBroadcasterProjectileImpactTypeInfo();
    gManyToOneBroadcasterProjectileImpactTypeInfoConstructed = false;
    ManyToOneBroadcaster_EProjectileImpactEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD64C0 (FUN_00BD64C0, register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo)
   */
  int register_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo()
  {
    (void)ConstructManyToOneBroadcasterProjectileImpactTypeInfo();
    return std::atexit(&cleanup_ManyToOneBroadcaster_EProjectileImpactEvent_TypeInfo);
  }

  /**
   * Address: 0x00BFD760 (FUN_00BFD760, cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   */
  void cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo()
  {
    if (!gManyToOneListenerProjectileImpactTypeInfoConstructed) {
      return;
    }

    ManyToOneListenerTypeInfoStorageRef().~RManyToOneListenerProjectileImpactTypeInfo();
    gManyToOneListenerProjectileImpactTypeInfoConstructed = false;
    ManyToOneListener_EProjectileImpactEvent::sType = nullptr;
  }

  /**
   * Address: 0x00BD64E0 (FUN_00BD64E0, register_ManyToOneListener_EProjectileImpactEvent_TypeInfo)
   */
  int register_ManyToOneListener_EProjectileImpactEvent_TypeInfo()
  {
    (void)ConstructManyToOneListenerProjectileImpactTypeInfo();
    return std::atexit(&cleanup_ManyToOneListener_EProjectileImpactEvent_TypeInfo);
  }
} // namespace moho

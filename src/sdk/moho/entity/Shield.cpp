#include "Shield.h"

#include <Windows.h>

#include <cstring>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityDb.h"
#include "moho/lua/CScrLuaBaseClassSpec.h"
#include "moho/lua/CScrLuaClassBinder.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace gpg
{

  // Declared locally: gpg::RRef_Sim (defined + address-cited in
  // src/sdk/gpg/core/containers/ArchiveSerialization.cpp) has external
  // linkage but is not yet exposed from a shared header.
} // namespace gpg

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kCreateShieldName = "_c_CreateShield";
  constexpr const char* kCreateShieldHelpText = "_c_CreateShield(spec)";
  constexpr const char* kOwnerFieldName = "Owner";
  constexpr std::uint32_t kShieldCollisionBucketFlags = 0x800u;
  constexpr std::uint32_t kShieldFamilyMaskSourceBits = 0x400u;
  constexpr std::uint32_t kInvalidArmySourceIndex = 0xFFu;

  gpg::RType* CachedShieldType()
  {
    static gpg::RType* sShieldType = nullptr;
    if (!sShieldType) {
      sShieldType = gpg::LookupRType(typeid(moho::Shield));
    }
    return sShieldType;
  }

  gpg::RType* CachedEntityType()
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(moho::Entity));
    }
    return sEntityType;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("Sim");
    return fallbackSet;
  }

  [[nodiscard]] std::uint32_t BuildShieldFamilySourceBits(const std::uint32_t armySourceIndex) noexcept
  {
    const std::uint32_t clampedSourceIndex = armySourceIndex & 0xFFu;
    return (clampedSourceIndex | kShieldFamilyMaskSourceBits) << moho::kEntityIdSourceShift;
  }

  /**
   * Address: 0x00776F60 (FUN_00776F60, sub_776F60)
   *
   * What it does:
   * Adds `Entity` as a reflected base of `Shield`.
   */
  void AddEntityBaseToShieldTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const entityType = CachedEntityType();
    gpg::RField baseField{};
    baseField.mName = entityType->GetName();
    baseField.mType = entityType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void UnlinkShieldFromSimList(moho::Shield* const shield)
  {
    if (!shield || !shield->SimulationRef) {
      return;
    }

    msvc8::list<moho::Shield*>& shieldList = shield->SimulationRef->mShields;
    for (msvc8::list<moho::Shield*>::iterator it = shieldList.begin(); it != shieldList.end();) {
      it = (*it == shield) ? shieldList.erase(it) : std::next(it);
    }
  }

} // namespace

namespace moho
{
  gpg::RType* Shield::sPointerType = nullptr;

  /**
   * Address: 0x00776340 (FUN_00776340, preregister_ShieldTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::Shield`.
   */
  [[nodiscard]] gpg::RType* preregister_ShieldTypeInfo()
  {
    static ShieldTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(Shield), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00776590 (FUN_00776590, ??0Shield@Moho@@QAE@@ZZ)
   *
   * What it does:
   * Serializer construction lane: initializes Shield with default collision
   * bucket flags under one simulation owner.
   */
  Shield::Shield(Sim* const sim)
    : Entity(sim, kShieldCollisionBucketFlags)
  {}

  /**
   * Address: 0x00776490 (FUN_00776490, ??0Shield@Moho@@QAE@@Z)
   *
   * What it does:
   * Lua construction lane: reserves one Shield-family entity id using the
   * provided source index, binds Lua object state, and links into
   * `Sim::mShields`.
   */
  Shield::Shield(Sim* const sim, const LuaPlus::LuaObject& luaObject, const std::uint32_t armySourceIndex)
    : Entity(
        luaObject,
        sim,
        static_cast<EntId>(sim != nullptr && sim->mEntityDB != nullptr
                             ? sim->mEntityDB->DoReserveId(BuildShieldFamilySourceBits(armySourceIndex))
                             : BuildShieldFamilySourceBits(kInvalidArmySourceIndex) | 1u)
      )
  {
    if (SimulationRef != nullptr) {
      SimulationRef->mShields.push_back(this);
    }
  }

  /**
   * Address: 0x00776860 (FUN_00776860)
   */
  void Shield::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    Sim* sim = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&sim, &owner);
    result.SetUnowned(gpg::MakeRRef(new Shield(sim)), 0u);
  }

  void Shield::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->Read(CachedEntityType(), static_cast<Entity*>(this), gpg::RRef{});
  }

  void Shield::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->Write(CachedEntityType(), static_cast<const Entity*>(this), gpg::RRef{});
  }

  /**
   * Address: 0x007762F0 (FUN_007762F0)
   *
   * What it does:
   * Returns cached reflection descriptor for Shield.
   */
  gpg::RType* Shield::GetClass() const
  {
    return CachedShieldType();
  }

  /**
   * Address: 0x0074E5D0 (FUN_0074E5D0, Moho::Shield::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflected pointer type for `Shield*` by
   * driving the startup registrar `preregister_ShieldPointerTypeStartup`
   * (FUN_00750280), falling back to a plain `LookupRType` when the descriptor
   * is not yet registered.
   */
  gpg::RType* Shield::GetPointerType()
  {
    (void)CachedShieldType();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::preregister_ShieldPointerTypeStartup();
      if (!cached) {
        cached = gpg::LookupRType(typeid(Shield*));
      }
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x00776310 (FUN_00776310)
   *
   * What it does:
   * Packs {this, GetClass()} as a reflection reference handle.
   */
  gpg::RRef Shield::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00776570 (FUN_00776570, deleting dtor thunk)
   * Address: 0x00776600 (FUN_00776600, non-deleting dtor core)
   *
   * What it does:
   * Unlinks this shield from Sim shield-list; the `InstanceCounter<Shield>`
   * and `Entity` bases' teardown follows.
   */
  Shield::~Shield()
  {
    UnlinkShieldFromSimList(this);
  }

  /**
   * Address: 0x00776330 (FUN_00776330)
   *
   * What it does:
   * Runtime type probe override for shield entities.
   */
  Shield* Shield::IsShield()
  {
    return this;
  }

  /**
   * Address: 0x00776A20 (FUN_00776A20, cfunc__c_CreateShield)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc__c_CreateShieldL`.
   */
  int cfunc__c_CreateShield(lua_State* const luaContext)
  {
    return cfunc__c_CreateShieldL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x00776A40 (FUN_00776A40, func__c_CreateShield_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `_c_CreateShield`.
   */
  CScrLuaInitForm* func__c_CreateShield_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreateShieldName,
      &cfunc__c_CreateShield,
      nullptr,
      "<global>",
      kCreateShieldHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00776AA0 (FUN_00776AA0, cfunc__c_CreateShieldL)
   *
   * What it does:
   * Validates `(luaobj, spec)`, derives shield source index from optional
   * `spec.Owner`, creates one `Shield`, and pushes its Lua object.
   */
  int cfunc__c_CreateShieldL(LuaPlus::LuaState* const state)
  {
    if (state == nullptr || state->m_state == nullptr) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateShieldHelpText, 2, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);
    std::uint32_t armySourceIndex = kInvalidArmySourceIndex;
    if (lua_type(rawState, 2) == LUA_TTABLE) {
      lua_pushstring(rawState, kOwnerFieldName);
      lua_gettable(rawState, 2);

      const int ownerStackIndex = lua_gettop(rawState);
      if (lua_type(rawState, ownerStackIndex) != LUA_TNIL) {
        const LuaPlus::LuaObject ownerObject(LuaPlus::LuaStackObject(state, ownerStackIndex));
        Entity* const ownerEntity = SCR_FromLua_EntityOpt(ownerObject);
        if (ownerEntity != nullptr && ownerEntity->ArmyRef != nullptr) {
          armySourceIndex = static_cast<std::uint32_t>(ownerEntity->ArmyRef->mConstDat.mArmyIndex) & 0xFFu;
        }
      }
    }

    const LuaPlus::LuaObject luaObjectArg(LuaPlus::LuaStackObject(state, 1));
    Shield* const shield = new Shield(sim, luaObjectArg, armySourceIndex);
    shield->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * `gpg::SerSaveConstructHelper<Shield>`, vtable 0x00E3713C.
   *
   * Address: 0x00BDD520 (FUN_00BDD520 -- constructs the global and registers its destructor.)
   * Address: 0x00C02590 (FUN_00C02590 -- the global's destructor.)
   * Address: 0x00776D20 (FUN_00776D20 -- `Init`.)
   * Address: 0x007766B0 (FUN_007766B0 -- `SaveConstructArgs`, `MemberSaveConstructArgs` inlined.)
   */
  struct ShieldSaveConstruct : gpg::SerSaveConstructHelper<Shield>
  {};

  /**
   * `gpg::SerConstructHelper<Shield>`, vtable 0x00E3714C.
   *
   * Address: 0x00BDD550 (FUN_00BDD550 -- constructs the global and registers its destructor.)
   * Address: 0x00C025C0 (FUN_00C025C0 -- the global's destructor.)
   * Address: 0x00776DA0 (FUN_00776DA0 -- `Init`.)
   * Address: 0x00776840 (FUN_00776840 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x00776FC0 (FUN_00776FC0 -- `Delete`.)
   */
  struct ShieldConstruct : gpg::SerConstructHelper<Shield>
  {};

  /**
   * `gpg::SerSaveLoadHelper<Shield>`, vtable 0x00E3715C.
   *
   * Address: 0x00BDD590 (FUN_00BDD590 -- constructs the global and registers its destructor.)
   * Address: 0x00C025F0 (FUN_00C025F0 -- the global's destructor.)
   * Address: 0x00776E20 (FUN_00776E20 -- `Init`.)
   * Address: 0x00776910 (FUN_00776910 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00776950 (FUN_00776950 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct ShieldSerializer : gpg::SerSaveLoadHelper<Shield>
  {};

  /**
   * Address: 0x007763E0 (FUN_007763E0, sub_7763E0)
   */
  ShieldTypeInfo::~ShieldTypeInfo() = default;

  /**
   * Address: 0x007763D0 (FUN_007763D0)
   */
  const char* ShieldTypeInfo::GetName() const
  {
    return "Shield";
  }

  /**
   * Address: 0x007763A0 (FUN_007763A0)
   *
   * What it does:
   * Sets Shield size and registers Entity base-field metadata.
   */
  void ShieldTypeInfo::Init()
  {
    size_ = sizeof(Shield);
    AddEntityBaseToShieldTypeInfo(this);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_ShieldTypeInfo_0bcbf6, moho::preregister_ShieldTypeInfo)

namespace
{
  // Address: 0x010BBB4C -- process-global `ShieldSaveConstruct` singleton.
  moho::ShieldSaveConstruct gShieldSaveConstruct;

  // Address: 0x010BBA9C -- process-global `ShieldConstruct` singleton.
  moho::ShieldConstruct gShieldConstruct;

  // Address: 0x010BBB38 -- process-global `ShieldSerializer` singleton.
  moho::ShieldSerializer gShieldSerializer;
} // namespace

namespace
{
  /**
   * Address: 0x00BDD4C0 (FUN_00BDD4C0) -- record at 0x00F5A1A4
   *
   * What it does:
   * Publishes Shield's method table as `moho.shield_methods`;
   * /lua/shield.lua builds its class from this table.
   */
  moho::CScrLuaInitForm* register_moho_shield_methods()
  {
    static moho::CScrLuaClassBinder binder(
      SimLuaInitSet(), "moho.shield_methods", &moho::CScrLuaMetatableFactory<moho::Shield>::Instance(), "Shield", ""
    );
    return &binder;
  }

  /**
   * Address: 0x00BDD4E0 (FUN_00BDD4E0) -- record at 0x00F5A1BC
   *
   * What it does:
   * Declares `Shield` as deriving from `Entity` for the Lua class system, so
   * `moho.shield_methods` carries `moho.entity_methods` in its array part and
   * /lua/shield.lua's class picks up the inherited entity methods.
   */
  moho::CScrLuaInitForm* register_ShieldLuaBaseClass()
  {
    static moho::CScrLuaBaseClassSpec spec(
      SimLuaInitSet(),
      &moho::CScrLuaMetatableFactory<moho::Shield>::Instance(),
      &moho::CScrLuaMetatableFactory<moho::Entity>::Instance(),
      "Shield",
      "derived from Entity"
    );
    return &spec;
  }

  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct ShieldLuaFuncDefBootstrap
  {
    ShieldLuaFuncDefBootstrap()
    {
      (void)::moho::func__c_CreateShield_LuaFuncDef();
      (void)register_moho_shield_methods();
      (void)register_ShieldLuaBaseClass();
    }
  };

  const ShieldLuaFuncDefBootstrap gShieldLuaFuncDefBootstrap{};
} // namespace

#include "Shield.h"

#include <cstring>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityDb.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/Stats.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"

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
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
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
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void UnlinkShieldFromSimList(moho::Shield* const shield)
  {
    if (!shield || !shield->SimulationRef) {
      return;
    }

    auto& shields = shield->SimulationRef->mShields;
    for (auto it = shields.begin(); it != shields.end();) {
      if (*it == shield) {
        it = shields.erase(it);
        continue;
      }

      ++it;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00776E90 (FUN_00776E90, Moho::InstanceCounter<Moho::Shield>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for Shield instance
   * counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::Shield>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::Shield).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
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
  {
    ++InstanceCounter<Shield>::s_count;
  }

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
    ++InstanceCounter<Shield>::s_count;

    if (SimulationRef != nullptr) {
      SimulationRef->mShields.push_back(this);
    }
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
   * Address: 0x00776570 (FUN_00776570)
   *
   * What it does:
   * Unlinks this shield from Sim shield-list and decrements shield instance
   * counter before base entity teardown.
   */
  Shield::~Shield()
  {
    UnlinkShieldFromSimList(this);
    --InstanceCounter<Shield>::s_count;
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
          armySourceIndex = static_cast<std::uint32_t>(ownerEntity->ArmyRef->ArmyId) & 0xFFu;
        }
      }
    }

    const LuaPlus::LuaObject luaObjectArg(LuaPlus::LuaStackObject(state, 1));
    Shield* const shield = new Shield(sim, luaObjectArg, armySourceIndex);
    shield->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x00776D20 (FUN_00776D20, sub_776D20)
   *
   * What it does:
   * Binds save-construct-args callback into Shield RTTI (`serSaveConstructArgsFunc_`).
   */
  void ShieldSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }

  /**
   * Address: 0x00776DA0 (FUN_00776DA0, sub_776DA0)
   *
   * What it does:
   * Binds construct/delete callbacks into Shield RTTI (`serConstructFunc_`, `deleteFunc_`).
   */
  void ShieldConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x00776E20 (FUN_00776E20, sub_776E20)
   *
   * What it does:
   * Binds load/save serializer callbacks into Shield RTTI (`serLoadFunc_`, `serSaveFunc_`).
   */
  void ShieldSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

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

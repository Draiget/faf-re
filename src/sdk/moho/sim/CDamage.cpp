#include "moho/sim/CDamage.h"

#include <cmath>
#include <cstdlib>
#include <cstdint>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <typeinfo>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/Shield.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/projectile/Projectile.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CDamageEMethodTypeInfo.h"
#include "moho/sim/CDamageLuaFunctionRegistrations.h"
#include "moho/sim/CDebugCanvas.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/SMinMax.h"
#include "moho/sim/Sim.h"
#include "moho/ui/SDebugLine.h"
#include "moho/unit/core/Unit.h"

namespace
{
  alignas(moho::CDamageTypeInfo) unsigned char gCDamageTypeInfoStorage[sizeof(moho::CDamageTypeInfo)];
  bool gCDamageTypeInfoConstructed = false;
  bool gCDamageTypeInfoPreregistered = false;

  [[nodiscard]] moho::CDamageTypeInfo* AcquireCDamageTypeInfo()
  {
    if (!gCDamageTypeInfoConstructed) {
      new (gCDamageTypeInfoStorage) moho::CDamageTypeInfo();
      gCDamageTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::CDamageTypeInfo*>(gCDamageTypeInfoStorage);
  }

  /**
   * Address: 0x00C00B10 (FUN_00C00B10, cleanup_CDamageTypeInfo)
   *
   * What it does:
   * Tears down process-global `CDamageTypeInfo` storage.
   */
  void cleanup_CDamageTypeInfo()
  {
    if (!gCDamageTypeInfoConstructed) {
      return;
    }

    AcquireCDamageTypeInfo()->~CDamageTypeInfo();
    gCDamageTypeInfoConstructed = false;
    gCDamageTypeInfoPreregistered = false;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    gpg::RType* type = moho::CScriptObject::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CScriptObject));
      moho::CScriptObject::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x00739B00 (FUN_00739B00)
   *
   * What it does:
   * Atomically increments the `CDamage` instance stat lane and returns the
   * original caller payload pointer unchanged.
   */
  [[maybe_unused]] [[nodiscard]] void* IncrementCDamageInstanceCounterAndReturnPayload(void* const payload) noexcept
  {
#if defined(_WIN32)
    (void)::InterlockedExchangeAdd(
      reinterpret_cast<volatile long*>(&moho::InstanceCounter<moho::CDamage>::GetStatItem()->mPrimaryValueBits),
      1L
    );
#else
    ++moho::InstanceCounter<moho::CDamage>::GetStatItem()->mPrimaryValueBits;
#endif
    return payload;
  }

  /**
   * Address: 0x00739B30 (FUN_00739B30)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CDamage`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedCDamageTypeBridge()
  {
    gpg::RType* type = moho::CDamage::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::CDamage));
      moho::CDamage::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0073AAC0 (FUN_0073AAC0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `CDamageMethod`.
   */
  [[nodiscard]] gpg::RType* CachedDamageMethodType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      (void)moho::preregister_CDamageEMethodTypeInfo();
      cached = gpg::LookupRType(typeid(moho::CDamageMethod));
    }
    return cached;
  }

  /**
   * Address: 0x0073AAE0 (FUN_0073AAE0)
   *
   * What it does:
   * Returns the lazily cached reflection descriptor for `SMinMax<float>`.
   */
  [[nodiscard]] gpg::RType* CachedSMinMaxFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SMinMax<float>));
    }
    return cached;
  }

  void AddStatCounter(moho::StatItem* const statItem, const long delta) noexcept
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

  [[nodiscard]] LuaPlus::LuaObject CreateDamageLuaFactoryObject(moho::Sim* const sim)
  {
    LuaPlus::LuaObject scriptFactory{};
    moho::func_CreateLuaCDamage(&scriptFactory, sim->mLuaState);
    return scriptFactory;
  }

  /**
   * Address: 0x00736DB0 (FUN_00736DB0)
   *
   * What it does:
   * Returns true when one shield owns a collision primitive and that
   * primitive contains the target entity world-position lane.
   */
  [[maybe_unused]] bool ShieldContainsEntityPosition(moho::Shield* const shield, moho::Entity* const entity)
  {
    if (shield != nullptr) {
      moho::EntityCollisionUpdater* const collisionShape = shield->CollisionExtents;
      if (collisionShape != nullptr) {
        return collisionShape->PointInShape(&entity->Position);
      }
    }

    gpg::Logf("invalid shield or missing collision primitive!");
    return false;
  }

  /**
   * Address: 0x00736DE0 (FUN_00736DE0, sub_736DE0)
   *
   * What it does:
   * Returns true when `entity` lies inside at least one active shield
   * collision primitive in `sim`.
   */
  [[maybe_unused]] bool EntityOverlapsAnyShield(moho::Sim* const sim, moho::Entity* const entity)
  {
    if (sim == nullptr || entity == nullptr) {
      return false;
    }

    for (moho::Shield* const shield : sim->mShields) {
      if (ShieldContainsEntityPosition(shield, entity)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00739BB0 (FUN_00739BB0)
   *
   * What it does:
   * Removes one shield entry from the active damage-iteration list and returns
   * the next iterator lane.
   */
  [[maybe_unused]] msvc8::list<moho::Shield*>::iterator RemoveDamageShieldEntry(
    msvc8::list<moho::Shield*>& shields,
    const msvc8::list<moho::Shield*>::iterator current
  )
  {
    return shields.erase(current);
  }

  /**
   * Address: 0x00739DD0 (FUN_00739DD0)
   *
   * What it does:
   * Clears the temporary shield-iteration list used by the damage path and
   * releases its owned entries.
   */
  [[maybe_unused]] void ResetDamageShieldIterationList(msvc8::list<moho::Shield*>& shields)
  {
    shields.clear();
  }

  struct DamageShieldListSentinelRuntimeNode
  {
    DamageShieldListSentinelRuntimeNode* next;
    DamageShieldListSentinelRuntimeNode* prev;
    std::uint32_t valueLane;
  };
  static_assert(
    sizeof(DamageShieldListSentinelRuntimeNode) == 0x0C,
    "DamageShieldListSentinelRuntimeNode size must be 0x0C"
  );

  /**
   * Address: 0x00739DB0 (FUN_00739DB0, SIM shield-list sentinel allocator)
   *
   * What it does:
   * Allocates one 12-byte shield-list sentinel lane and self-links its
   * `{next,prev}` pointers.
   */
  [[maybe_unused]] [[nodiscard]] DamageShieldListSentinelRuntimeNode* AllocateSelfLinkedDamageShieldSentinel()
  {
    auto* const node =
      static_cast<DamageShieldListSentinelRuntimeNode*>(gpg::core::legacy::AllocateChecked12ByteLane(1u));
    node->next = node;
    node->prev = node;
    return node;
  }

  struct DamagePairSeed
  {
    std::uint32_t first;
    std::uint32_t second;
  };
  static_assert(sizeof(DamagePairSeed) == 0x08, "DamagePairSeed size must be 0x08");

  struct DamageLinkedPairNodeRuntime
  {
    DamageLinkedPairNodeRuntime* next;
    DamageLinkedPairNodeRuntime* prev;
    std::uint32_t payload0;
    std::uint32_t payload1;
  };
  static_assert(sizeof(DamageLinkedPairNodeRuntime) == 0x10, "DamageLinkedPairNodeRuntime size must be 0x10");

  /**
   * Address: 0x0073A120 (FUN_0073A120, SIM damage linked-pair node allocator)
   *
   * What it does:
   * Allocates one 16-byte linked node, seeds `{next,prev}` from caller lanes,
   * and copies one 8-byte payload pair into the node tail.
   */
  [[maybe_unused]] [[nodiscard]] DamageLinkedPairNodeRuntime* AllocateLinkedDamagePairNode(
    const DamagePairSeed& seed,
    DamageLinkedPairNodeRuntime* const next,
    DamageLinkedPairNodeRuntime* const prev
  )
  {
    auto* const node = static_cast<DamageLinkedPairNodeRuntime*>(gpg::core::legacy::AllocateChecked16ByteLane(1u));
    node->next = next;
    node->prev = prev;
    node->payload0 = seed.first;
    node->payload1 = seed.second;
    return node;
  }
} // namespace

namespace moho
{
  gpg::RType* CDamage::sType = nullptr;

  /**
   * Address: 0x0064C080 (FUN_0064C080, Moho::InstanceCounter<Moho::CDamage>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for CDamage instance
   * counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  StatItem* InstanceCounter<CDamage>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::CDamage).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  /**
   * Address: 0x00736C40 (FUN_00736C40, ??0CDamage@Moho@@QAE@CDamage@Z)
   *
   * What it does:
   * Copy-constructs one detached damage payload and re-links copied
   * instigator/target weak lanes into owner intrusive weak chains.
   */
  CDamage::CDamage(const CDamage& other)
    : CScriptObject()
  {
    AddStatCounter(InstanceCounter<CDamage>::GetStatItem(), 1);

    mMethod = other.mMethod;
    mInstigator.ResetFromOwnerLinkSlot(other.mInstigator.ownerLinkSlot);
    mTarget.ResetFromOwnerLinkSlot(other.mTarget.ownerLinkSlot);
    mRadius = other.mRadius;
    mMaxRadius = other.mMaxRadius;
    mOrigin = other.mOrigin;
    mAmount = other.mAmount;
    mType.assign(other.mType, 0, msvc8::string::npos);
    mDamageFriendly = other.mDamageFriendly;
    mDamageNeutral = other.mDamageNeutral;
    mDamageSelf = other.mDamageSelf;
    mVector = other.mVector;
  }

  /**
   * Address: 0x007384C0 (FUN_007384C0, ??0CDamage@Moho@@QAE@@Z)
   *
   * What it does:
   * Creates script-backed CDamage object state and initializes runtime fields
   * used by damage apply helpers.
   */
  CDamage::CDamage(Sim* const sim)
    : CScriptObject(CreateDamageLuaFactoryObject(sim), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{})
  {
    AddStatCounter(InstanceCounter<CDamage>::GetStatItem(), 1);

    mRadius = 0.0f;
    mMaxRadius = 0.0f;
    mInstigator.ResetFromObject(nullptr);
    mTarget.ResetFromObject(nullptr);
    mAmount = std::numeric_limits<float>::quiet_NaN();
    mDamageFriendly = 1;
    mDamageNeutral = 1;
    mDamageSelf = 0;
    mVector = Wm3::Vec3f::Zero();
  }

  /**
   * Address: 0x0064BAD0 (FUN_0064BAD0, ??1CDamage@Moho@@QAE@@Z)
   * Deleting destructor thunk: 0x00736D50 (FUN_00736D50, Moho::CDamage::dtr)
   *
   * What it does:
   * Releases string storage, unlinks weak lanes, and decrements CDamage
   * instance stats before base teardown.
   */
  CDamage::~CDamage()
  {
    mType.tidy(true, 0u);
    mTarget.ResetFromObject(nullptr);
    mInstigator.ResetFromObject(nullptr);
    AddStatCounter(InstanceCounter<CDamage>::GetStatItem(), -1);
  }

  /**
   * Address: 0x00736C00 (FUN_00736C00, Moho::CDamage::GetClass)
   */
  gpg::RType* CDamage::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CDamage));
    }
    return sType;
  }

  /**
   * Address: 0x00736C20 (FUN_00736C20, Moho::CDamage::GetDerivedObjectRef)
   */
  gpg::RRef CDamage::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x007382A0 (FUN_007382A0, Moho::CDamageTypeInfo::dtr)
   */
  CDamageTypeInfo::~CDamageTypeInfo() = default;

  /**
   * Address: 0x00738290 (FUN_00738290, Moho::CDamageTypeInfo::GetName)
   */
  const char* CDamageTypeInfo::GetName() const
  {
    return "CDamage";
  }

  /**
   * Address: 0x0073A6B0 (FUN_0073A6B0, Moho::CDamageTypeInfo::AddBase_CScriptObject)
   *
   * What it does:
   * Adds reflected `CScriptObject` base lane at zero offset.
   */
  void CDamageTypeInfo::AddBaseScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const scriptObjectType = CachedCScriptObjectType();
    gpg::RField baseField{};
    baseField.mName = scriptObjectType->GetName();
    baseField.mType = scriptObjectType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x0073A710 (FUN_0073A710, gpg::RType::AddField_CDamage_EMethod_0x34Method)
   *
   * What it does:
   * Appends reflected `Method` enum lane at `+0x34`.
   */
  gpg::RField* CDamageTypeInfo::AddFieldMethod(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);

    typeInfo->fields_.push_back(gpg::RField("Method", CachedDamageMethodType(), 0x34, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x0073A790 (FUN_0073A790, gpg::RType::AddField_SMinMax_float_0x48MinMaxRadius)
   *
   * What it does:
   * Appends reflected `MinMaxRadius` lane (`SMinMax<float>`) at `+0x48`.
   */
  gpg::RField* CDamageTypeInfo::AddFieldMinMaxRadius(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);

    typeInfo->fields_.push_back(gpg::RField("MinMaxRadius", CachedSMinMaxFloatType(), 0x48, 0, nullptr));
    return &typeInfo->fields_.back();
  }

  /**
   * Address: 0x00738340 (FUN_00738340, Moho::CDamageTypeInfo::AddFields)
   *
   * What it does:
   * Publishes `CDamage` reflected lanes in binary call order.
   */
  void CDamageTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    (void)AddFieldMethod(typeInfo);
    (void)AddFieldMinMaxRadius(typeInfo);
    typeInfo->AddFieldVector3f("Origin", 0x50);
    typeInfo->AddFieldFloat("Amount", 0x5C);
    typeInfo->AddFieldString("Type", 0x60);
    typeInfo->AddFieldBool("DamageFriendly", 0x7C);
    typeInfo->AddFieldBool("DamageNeutral", 0x7D);
    typeInfo->AddFieldBool("DamageSelf", 0x7E);
    typeInfo->AddFieldVector3f("Vector", 0x80);
  }

  /**
   * Address: 0x00738260 (FUN_00738260, Moho::CDamageTypeInfo::Init)
   */
  void CDamageTypeInfo::Init()
  {
    size_ = sizeof(CDamage);
    AddBaseScriptObject(this);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00738200 (FUN_00738200, preregister_CDamageTypeInfo)
   */
  gpg::RType* preregister_CDamageTypeInfo()
  {
    gpg::RType* const typeInfo = AcquireCDamageTypeInfo();
    if (!gCDamageTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(CDamage), typeInfo);
      gCDamageTypeInfoPreregistered = true;
    }
    return typeInfo;
  }

  /**
   * Address: 0x00BDB6F0 (FUN_00BDB6F0, register_CDamageTypeInfo)
   */
  int register_CDamageTypeInfo()
  {
    (void)preregister_CDamageTypeInfo();
    return std::atexit(&cleanup_CDamageTypeInfo);
  }

  /**
   * Address: 0x00737140 (FUN_00737140, Moho::SIM_DoDamagePoint)
   * Mangled: ?SIM_DoDamagePoint@Moho@@YAXPAVSim@1@ABVCDamage@1@@Z
   *
   * IDA signature:
   * void __cdecl Moho::SIM_DoDamagePoint(Moho::Sim *sim, const Moho::CDamage &damage);
   *
   * What it does:
   * Applies one point-damage payload to a single target unit:
   *   - When `sim_ShowDamage` is enabled, draws a debug arrow from impact
   *     origin to the target and (when |amount| is large enough) an
   *     amount-scaled wire sphere around the target.
   *   - Skips the body entirely when `damage.mAmount == 0`.
   *   - Walks one step through any projectile-launcher chain on the
   *     instigator side and silently returns if the (possibly substituted)
   *     instigator equals the target and `mDamageSelf` is false.
   *   - If the target is a unit, applies `Unit::ProcessArmorOnDamage`,
   *     divides by `(handicap + 1)`, fires the `OnDamageBy` script with
   *     the instigator's army id, and fires `OnExtraDamageDealt` when the
   *     post-armor amount is >= 2x the original.
   *   - When the instigator has an army, accumulates
   *     `DamageStats_TotalDamageDealt` and the per-blueprint
   *     `Units_TotalDamageDealt` lane and adds `amount` to that army's
   *     platoon-for-instigator `mLifetimeStat3` accumulator.
   *   - When the target has an army, mirrors the same accumulation into
   *     `DamageStats_TotalDamageReceived` /
   *     `Units_TotalDamageReceive` and the target platoon's
   *     `mLifetimeStat4` lane.
   *   - When the post-armor amount is positive, logs
   *     `"DealDamage(target=0x%08x, amt=%.1f)"`, packs `mVector` into a
   *     Lua vec3, and invokes the target's `OnDamage` script callback.
   */
  void SIM_DoDamagePoint(Sim* const sim, const CDamage& damage)
  {
    Entity* const targetEntity = damage.mTarget.GetObjectPtr();

    // Optional debug overlay: arrow from impact origin to target, plus an
    // amount-scaled wire sphere when |amount * 0.01| exceeds 1e-6.
    if (sim_ShowDamage) {
      CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
      if (targetEntity != nullptr && debugCanvas != nullptr) {
        const Wm3::Vec3f& targetPosition = targetEntity->Position;
        SDebugLine debugLine{};
        debugLine.p0 = targetPosition;
        debugLine.p1.x = targetPosition.x - damage.mVector.x;
        debugLine.p1.y = targetPosition.y - damage.mVector.y;
        debugLine.p1.z = targetPosition.z - damage.mVector.z;
        debugLine.depth0 = -65536;
        debugLine.depth1 = -65536;
        debugCanvas->DebugDrawLine(debugLine);

        const float scaledAmount = damage.mAmount * 0.0099999998f;
        if (std::fabs(0.000001f) <= std::fabs(scaledAmount)) {
          const Wm3::Vec3f upAxis{0.0f, 1.0f, 0.0f};
          debugCanvas->AddWireSphere(targetPosition, upAxis, scaledAmount, static_cast<std::uint32_t>(-65536));
        }
      }
    }

    if (damage.mAmount == 0.0f) {
      return;
    }

    // Self-damage suppression: walk one step through the projectile
    // launcher chain on the instigator side, then early-return if the
    // resolved instigator equals the target.
    //
    // Binary edge case: when the instigator IS a projectile but has no
    // bound launcher weak-link, the comparison is skipped entirely
    // (control falls out of the self-damage block without performing
    // any equality test), so a launcher-less projectile cannot suppress
    // damage to itself via this path.
    if (!damage.mDamageSelf) {
      Entity* const directTarget = damage.mTarget.GetObjectPtr();
      if (Entity* const rawInstigator = damage.mInstigator.GetObjectPtr(); rawInstigator != nullptr) {
        Entity* resolvedInstigator = rawInstigator;
        bool runEqualityCheck = true;
        if (Projectile* const projectile = rawInstigator->IsProjectile(); projectile != nullptr) {
          if (Entity* const launcherEntity = projectile->GetLauncherEntity(); launcherEntity != nullptr) {
            resolvedInstigator = launcherEntity;
          } else {
            runEqualityCheck = false;
          }
        }
        if (runEqualityCheck && resolvedInstigator == directTarget) {
          return;
        }
      }
    }

    // Armor scaling + per-army handicap divisor for the target unit.
    float postArmorAmount = damage.mAmount;
    Unit* const targetUnit = (targetEntity != nullptr) ? targetEntity->IsUnit() : nullptr;
    if (targetUnit != nullptr) {
      const float armoredAmount = targetUnit->ProcessArmorOnDamage(damage.mAmount, damage.mType);
      CArmyImpl* const targetArmy = targetUnit->ArmyRef;
      float handicap = 0.0f;
      if (targetArmy != nullptr && targetArmy->HasHandicap != 0.0f) {
        handicap = targetArmy->Handicap;
      }
      postArmorAmount = armoredAmount / (handicap + 1.0f);
      const float relativeDamage = postArmorAmount / damage.mAmount;

      if (postArmorAmount > 0.0f) {
        if (Entity* const scriptInstigator = damage.mInstigator.GetObjectPtr();
            scriptInstigator != nullptr && scriptInstigator->ArmyRef != nullptr)
        {
          const int instigatorArmyIndex = scriptInstigator->ArmyRef->ArmyId + 1;
          targetUnit->RunScriptInt("OnDamageBy", instigatorArmyIndex);
        }
      }

      if (relativeDamage >= 2.0f) {
        const std::string_view typeView = damage.mType.view();
        targetUnit->CallString("OnExtraDamageDealt", std::string(typeView.data(), typeView.size()));
      }
    }

    // Instigator-side army-wide and per-platoon damage-dealt stats.
    if (damage.mInstigator.HasValue()) {
      if (Entity* const instigatorEntity = damage.mInstigator.GetObjectPtr();
          instigatorEntity != nullptr && instigatorEntity->ArmyRef != nullptr)
      {
        CArmyImpl* const instigatorArmy = instigatorEntity->ArmyRef;
        CArmyStats* const armyStats = instigatorArmy->GetArmyStats();
        if (armyStats != nullptr) {
          CArmyStatItem* const dealtItem = ResolveArmyStatItemCachedCreate(armyStats, "DamageStats_TotalDamageDealt");
          if (dealtItem != nullptr) {
            dealtItem->SynchronizeAsFloat();
            (void)dealtItem->AddFloat(&postArmorAmount);
          }

          if (Unit* const instigatorUnit = instigatorEntity->IsUnit(); instigatorUnit != nullptr) {
            const RUnitBlueprint* const blueprint = instigatorUnit->GetBlueprint();
            (void)armyStats->AddBlueprintStatDelta(
              "Units_TotalDamageDealt",
              reinterpret_cast<const ArmyBlueprintNameView*>(blueprint),
              postArmorAmount
            );

            ESquadClass squadClass{};
            CPlatoon* const platoon = instigatorArmy->GetPlatoonFor(
              static_cast<int>(reinterpret_cast<std::uintptr_t>(instigatorUnit)),
              &squadClass
            );
            if (platoon != nullptr) {
              platoon->mLifetimeStat3 += postArmorAmount;
            }
          }
        }
      }
    }

    // Target-side army-wide and per-platoon damage-received stats. The
    // binary gates both the instigator-side and target-side stat blocks
    // on the instigator weak-link being non-null and non-sentinel; that
    // behavior is preserved here (an unbound instigator skips target
    // stats too).
    if (damage.mInstigator.HasValue()) {
      if (Entity* const targetForStats = damage.mTarget.GetObjectPtr();
          targetForStats != nullptr && targetForStats->ArmyRef != nullptr)
      {
        CArmyImpl* const targetArmy = targetForStats->ArmyRef;
        CArmyStats* const armyStats = targetArmy->GetArmyStats();
        if (armyStats != nullptr) {
          CArmyStatItem* const receivedItem = ResolveArmyStatItemCachedCreate(armyStats, "DamageStats_TotalDamageReceived");
          if (receivedItem != nullptr) {
            receivedItem->SynchronizeAsFloat();
            (void)receivedItem->AddFloat(&postArmorAmount);
          }

          if (Unit* const targetUnitForStats = targetForStats->IsUnit(); targetUnitForStats != nullptr) {
            const RUnitBlueprint* const targetBlueprint = targetUnitForStats->GetBlueprint();
            (void)armyStats->AddBlueprintStatDelta(
              "Units_TotalDamageReceive",
              reinterpret_cast<const ArmyBlueprintNameView*>(targetBlueprint),
              postArmorAmount
            );

            ESquadClass squadClass{};
            CPlatoon* const platoon = targetArmy->GetPlatoonFor(
              static_cast<int>(reinterpret_cast<std::uintptr_t>(targetUnitForStats)),
              &squadClass
            );
            if (platoon != nullptr) {
              platoon->mLifetimeStat4 += postArmorAmount;
            }
          }
        }
      }
    }

    // Log and fire target's OnDamage script when the post-armor amount is
    // still positive after armor/handicap scaling.
    if (postArmorAmount > 0.0f) {
      Entity* const finalTarget = damage.mTarget.GetObjectPtr();
      const EntId targetId = (finalTarget != nullptr) ? finalTarget->id_ : EntId{0};
      sim->Logf("DealDamage(target=0x%08x, amt=%.1f)\n", targetId, postArmorAmount);

      const LuaPlus::LuaObject damagePayload = SCR_ToLua<Wm3::Vector3<float>>(sim->mLuaState, damage.mVector);
      if (finalTarget != nullptr) {
        const std::string_view typeView = damage.mType.view();
        finalTarget->RunScriptEntityOnDamage(
          damage.mInstigator,
          postArmorAmount,
          damagePayload,
          std::string(typeView.data(), typeView.size())
        );
      }
    }
  }

  /**
   * Address: 0x00737E60 (FUN_00737E60, Moho::SIM_Damage)
   * Mangled: ?SIM_Damage@Moho@@YAXPAVSim@1@ABVCDamage@1@@Z
   *
   * IDA signature:
   * void __fastcall Moho::SIM_Damage(Moho::Sim *sim, const Moho::CDamage &damage);
   *
   * What it does:
   * Dispatches one damage payload by `damage.mMethod` to the matching
   * applier free function. The single-target lane additionally skips the
   * call when the target entity is already dead.
   */
  void SIM_Damage(Sim* const sim, const CDamage& damage)
  {
    switch (damage.mMethod) {
    case CDamage_AREA_EFFECT:
      SIM_DoDamageArea(sim, damage);
      return;
    case CDamage_RING_EFFECT:
      func_DoDamageRing(sim, damage);
      return;
    case CDamage_SINGLE_TARGET:
    default: {
      Entity* const targetEntity = damage.mTarget.GetObjectPtr();
      if (targetEntity == nullptr) {
        return;
      }
      if (!targetEntity->Dead) {
        SIM_DoDamagePoint(sim, damage);
      }
      return;
    }
    }
  }
} // namespace moho

namespace
{
  struct CDamageTypeInfoBootstrap
  {
    CDamageTypeInfoBootstrap()
    {
      (void)moho::register_CDamageTypeInfo();
    }
  };

  [[maybe_unused]] CDamageTypeInfoBootstrap gCDamageTypeInfoBootstrap;
} // namespace

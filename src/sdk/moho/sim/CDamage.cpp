#include "moho/sim/CDamage.h"

#include <cstdlib>
#include <cstdint>
#include <limits>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/CheckedArrayAllocationLanes.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/Shield.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/sim/CDamageEMethodTypeInfo.h"
#include "moho/sim/CDamageLuaFunctionRegistrations.h"
#include "moho/sim/SMinMax.h"
#include "moho/sim/Sim.h"

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

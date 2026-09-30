#include "moho/misc/CEconomyEvent.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/exceptions/StdExcept.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/CEconomy.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  constexpr const char* kCreateEconomyEventHelp = "CreateEconomyEvent";
  constexpr const char* kRemoveEconomyEventHelp = "RemoveEconomyEvent";
  constexpr const char* kEconomyEventIsDoneHelp = "EconomyEventIsDone";
  constexpr const char* kCreateEconomyEventLuaHelp = "event = CreateEconomyEvent(unit, energy, mass, timeInSeconds)";
  constexpr const char* kRemoveEconomyEventLuaHelp = "RemoveEconomyEvent(unit, event)";
  constexpr const char* kEconomyEventIsDoneLuaHelp = "bool = EconomyEventIsDone(event)";
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kDestroyedGameObjectError = "Game object has been destroyed";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    // Every file that wants this set must resolve the one that already
    // exists. Declaring a fresh static here creates a second set with the
    // same name, and SCR_FindLuaInitFormSet returns only the first - so
    // half the binders never get run.
    if (moho::CScrLuaInitFormSet* const existing = moho::SCR_FindLuaInitFormSet("Sim"); existing != nullptr) {
      return *existing;
    }

    static moho::CScrLuaInitFormSet sSet("Sim");
    return sSet;
  }

  /**
   * Address: 0x00775630 (FUN_00775630, context unwrap)
   * Address: 0x00775910 (FUN_00775910, context unwrap)
   * Address: 0x00775A40 (FUN_00775A40, context unwrap)
   *
   * What it does:
   * Resolves LuaPlus wrapper state from native Lua callback context.
   */
  [[nodiscard]] LuaPlus::LuaState* ResolveBindingState(lua_State* const luaContext) noexcept
  {
    return luaContext ? luaContext->stateUserData : nullptr;
  }

  /**
   * Address: 0x006ADF70 (FUN_006ADF70)
   *
   * What it does:
   * Resolves and caches RTTI for one `CEconomyEvent` lane.
   */
  [[nodiscard]] gpg::RType* CachedCEconomyEventType()
  {
    if (!moho::CEconomyEvent::sType) {
      moho::CEconomyEvent::sType = gpg::LookupRType(typeid(moho::CEconomyEvent));
    }
    return moho::CEconomyEvent::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptEventType()
  {
    if (!moho::CScriptEvent::sType) {
      moho::CScriptEvent::sType = gpg::LookupRType(typeid(moho::CScriptEvent));
    }
    return moho::CScriptEvent::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CScriptObject*));
    }
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (!moho::SEconValue::sType) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
  }

  struct TypeInfoRTypePair
  {
    const std::type_info* typeInfo;
    gpg::RType* rType;
  };

  struct TypeInfoCache3
  {
    bool initialized;
    TypeInfoRTypePair entries[3];
  };

  thread_local TypeInfoCache3 gCEconRequestRRefCache{false, {}};

  template <typename TObject>
  [[nodiscard]] gpg::RRef* BuildTypedRefWithCache(
    gpg::RRef* const outRef,
    TObject* const value,
    const std::type_info& declaredType,
    gpg::RType*& declaredTypeCache,
    TypeInfoCache3& cache
  )
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RType* declaredRuntimeType = declaredTypeCache;
    if (declaredRuntimeType == nullptr) {
      declaredRuntimeType = gpg::LookupRType(declaredType);
      declaredTypeCache = declaredRuntimeType;
    }

    const std::type_info* runtimeTypeInfo = &declaredType;
    if constexpr (std::is_polymorphic_v<TObject>) {
      if (value != nullptr) {
        runtimeTypeInfo = &typeid(*value);
      }
    }

    if (value == nullptr || (*runtimeTypeInfo == declaredType)) {
      outRef->mObj = value;
      outRef->mType = declaredRuntimeType;
      return outRef;
    }

    if (!cache.initialized) {
      cache.initialized = true;
      for (TypeInfoRTypePair& entry : cache.entries) {
        entry.typeInfo = nullptr;
        entry.rType = nullptr;
      }
    }

    int cacheSlot = 0;
    while (cacheSlot < 3) {
      const TypeInfoRTypePair& entry = cache.entries[cacheSlot];
      if (entry.typeInfo == runtimeTypeInfo || (entry.typeInfo && (*entry.typeInfo == *runtimeTypeInfo))) {
        break;
      }
      ++cacheSlot;
    }

    gpg::RType* runtimeType = nullptr;
    if (cacheSlot >= 3) {
      runtimeType = gpg::LookupRType(*runtimeTypeInfo);
      cacheSlot = 2;
    } else {
      runtimeType = cache.entries[cacheSlot].rType;
    }

    for (int slot = cacheSlot; slot > 0; --slot) {
      cache.entries[slot] = cache.entries[slot - 1];
    }

    cache.entries[0].typeInfo = runtimeTypeInfo;
    cache.entries[0].rType = runtimeType;

    std::int32_t baseOffset = 0;
    const bool isDerived = runtimeType->IsDerivedFrom(declaredRuntimeType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      outRef->mObj = value;
      outRef->mType = runtimeType;
      return outRef;
    }

    outRef->mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(value) - static_cast<std::uintptr_t>(baseOffset));
    outRef->mType = runtimeType;
    return outRef;
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* object, gpg::RType* staticType)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = staticType;
    if (!object) {
      return out;
    }

    gpg::RType* dynamicType = staticType;
    try {
      dynamicType = gpg::LookupRType(typeid(*object));
    } catch (...) {
      dynamicType = staticType;
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(staticType, &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  void IntrusiveUnlink(moho::TDatListItem<void, void>& node)
  {
    node.ListUnlink();
  }

  void IntrusiveLinkBefore(moho::TDatListItem<void, void>& node, moho::TDatListItem<void, void>& listHead)
  {
    node.ListLinkBefore(&listHead);
  }

  /**
   * Address: 0x00775D50 (FUN_00775D50)
   *
   * What it does:
   * Registers `CScriptEvent` as one reflected base lane for `CEconomyEvent`
   * at offset `+0x00`.
   */
  void AddCScriptEventBaseToCEconomyEventType(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptEventType();
    gpg::RField baseField(baseType->GetName(), baseType, 0, 0, nullptr);
    typeInfo->AddBase(baseField);
  }

  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractUserDataSlotRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
  }

  [[nodiscard]] moho::CScriptObject** GetScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractUserDataSlotRef(payload);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<moho::CScriptObject**>(upcast.mObj);
  }

  [[noreturn]] void RaiseLuaError(LuaPlus::LuaState* state, const char* text)
  {
    lua_State* activeState = state ? state->GetActiveCState() : nullptr;
    if (!activeState && state) {
      activeState = state->GetCState();
    }
    luaL_error(activeState, "%s", text ? text : "<lua error>");
  }

  template <typename TObject>
  [[nodiscard]] TObject*
  ResolveTypedGameObject(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state, gpg::RType* expectedType)
  {
    moho::CScriptObject** const slot = GetScriptObjectSlotFromLuaObject(object);
    if (!slot) {
      RaiseLuaError(state, kExpectedGameObjectError);
    }

    moho::CScriptObject* const scriptObject = *slot;
    if (!scriptObject) {
      RaiseLuaError(state, kDestroyedGameObjectError);
    }

    const gpg::RRef sourceRef = moho::SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, expectedType);
    if (!upcast.mObj) {
      RaiseLuaError(state, kIncorrectGameObjectTypeError);
    }

    return static_cast<TObject*>(upcast.mObj);
  }

  [[nodiscard]] moho::Unit* ResolveUnitFromLuaObject(const LuaPlus::LuaObject& object, LuaPlus::LuaState* state)
  {
    (void)state;
    return moho::SCR_FromLua_Unit(object);
  }

  void RaiseLuaArgCountError(
    LuaPlus::LuaState* state, const char* helpName, const int expectedMin, const int expectedMax, const int actual
  )
  {
    luaL_error(
      state->GetActiveCState(),
      "%s\n  expected between %d and %d args, but got %d",
      helpName ? helpName : "<lua-func>",
      expectedMin,
      expectedMax,
      actual
    );
  }

  void RaiseLuaArgCountError(LuaPlus::LuaState* state, const char* helpName, const int expected, const int actual)
  {
    luaL_error(
      state->GetActiveCState(),
      "%s\n  expected %d args, but got %d",
      helpName ? helpName : "<lua-func>",
      expected,
      actual
    );
  }

  [[nodiscard]] float ReadLuaNumberOrError(LuaPlus::LuaState* state, const int index)
  {
    lua_State* const lstate = state->m_state;
    if (lua_type(lstate, index) != LUA_TNUMBER) {
      luaL_error(state->GetActiveCState(), "bad argument #%d (number expected)", index);
    }

    return static_cast<float>(lua_tonumber(lstate, index));
  }

  /**
   * Address: 0x00775DB0 (FUN_00775DB0)
   *
   * What it does:
   * Returns cached `CEconomyEvent` metatable object from Lua object-factory
   * storage.
   */
  [[nodiscard]] LuaPlus::LuaObject GetEconomyEventFactory(LuaPlus::LuaState* state)
  {
    if (!state) {
      return {};
    }
    return moho::CScrLuaMetatableFactory<moho::CEconomyEvent>::Instance().Get(state);
  }

  /**
   * Address: 0x00775BF0 (FUN_00775BF0, sub_775BF0)
   *
   * What it does:
   * Destroys and frees a heap-backed `LuaPlus::LuaObject` when the
   * CEconomyEvent tick callback cleanup lane owns one.
   */
  void DestroyHeapLuaObjectCleanupLane(LuaPlus::LuaObject*& cleanupLaneObject)
  {
    LuaPlus::LuaObject* const object = cleanupLaneObject;
    if (!object) {
      return;
    }

    object->~LuaObject();
    operator delete(object);
  }

  void ClearUnitRequestedRates(moho::Unit* unit)
  {
    unit->mUnitVarDat.mMaintainenceCost.ENERGY = 0.0f;
    unit->mUnitVarDat.mMaintainenceCost.MASS = 0.0f;
  }

  /**
   * Address: 0x00773740 (FUN_00773740, sub_773740)
   */
  [[nodiscard]] moho::SEconValue TakeGrantedResourcesAndReset(moho::CEconRequest* request)
  {
    moho::SEconValue out{};
    out.energy = request->mGranted.energy;
    out.mass = request->mGranted.mass;
    request->mGranted.energy = 0.0f;
    request->mGranted.mass = 0.0f;
    return out;
  }

  /**
   * Address: 0x005CFA20 (sub_5CFA20)
   */
  void DestroyEconomyRequestPointer(moho::CEconRequest*& request)
  {
    if (!request) {
      return;
    }

    IntrusiveUnlink(request->mNode);
    delete request;
    request = nullptr;
  }

} // namespace

/**
 * Address: 0x00774420 (FUN_00774420)
 *
 * What it does:
 * Materializes one temporary `RRef_CEconRequest` and copies `(mObj,mType)`
 * lanes into caller-owned output storage.
 */
namespace gpg
{
  [[maybe_unused]] gpg::RRef* AssignCEconRequestRef(gpg::RRef* const out, moho::CEconRequest* const value)
  {
    gpg::RRef tmp{};
    tmp = gpg::MakeRRef<moho::CEconRequest>(value);
    out->mObj = tmp.mObj;
    out->mType = tmp.mType;
    return out;
  }
} // namespace gpg

namespace moho
{
  gpg::RType* SEconValue::sType = nullptr;
  gpg::RType* CEconRequest::sType = nullptr;
  gpg::RType* CEconomyEvent::sType = nullptr;
  gpg::RType* CEconomyEvent::sPointerType = nullptr;
  CScrLuaMetatableFactory<CEconomyEvent> CScrLuaMetatableFactory<CEconomyEvent>::sInstance{};

  namespace
  {
    /**
     * Address: 0x006B2600 (FUN_006B2600)
     * Address: 0x00BFDCA0 (FUN_00BFDCA0, atexit destructor of the static `RPointerType<CEconomyEvent>` descriptor)
     *
     * What it does:
     * Constructs the static `RPointerType<CEconomyEvent>` descriptor that the
     * binary exposes as `Moho::CEconomyEvent::PointerType` and pre-registers
     * it under the `CEconomyEvent*` type-info key, so subsequent `LookupRType`
     * queries from the lazy `GetPointerType` lane resolve to this descriptor.
     * The binary holds the descriptor as a function-local static of
     * `GetPointerType`; it lives here because the preregister phase has to
     * construct it before any consumer looks up `CEconomyEvent*`.
     */
    gpg::RType* PreregisterCEconomyEventPointerType()
    {
      static gpg::RPointerType<moho::CEconomyEvent> sDescriptor;
      gpg::PreRegisterRType(typeid(moho::CEconomyEvent*), &sDescriptor);
      return &sDescriptor;
    }
  } // namespace

  /**
   * Address: 0x006B2450 (FUN_006B2450, Moho::CEconomyEvent::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<CEconomyEvent>`
   * descriptor. After that, lazily caches the
   * `LookupRType(typeid(CEconomyEvent*))` result in `sPointerType` and
   * returns it.
   */
  gpg::RType* CEconomyEvent::GetPointerType()
  {
    static const bool sOnceInit = (PreregisterCEconomyEventPointerType(), true);
    (void)sOnceInit;

    if (!sPointerType) {
      sPointerType = gpg::LookupRType(typeid(CEconomyEvent*));
    }
    return sPointerType;
  }

  /**
   * Address: 0x00774DA0 (FUN_00774DA0, preregister_CEconomyEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `moho::CEconomyEvent`.
   */
  [[nodiscard]] gpg::RType* preregister_CEconomyEventTypeInfo()
  {
    static CEconomyEventTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(CEconomyEvent), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00773630 (FUN_00773630, ??0CEconRequest@Moho@@QAE@ABUSEconValue@1@PAVCEconomy@1@@Z)
   *
   * What it does:
   * Initializes one economy-request node with requested-per-second values,
   * clears granted lanes, and links into the economy consumption list head.
   */
  CEconRequest::CEconRequest(const SEconValue& perSecond, CEconomy* const economy)
    : mNode()
    , mRequested(perSecond)
    , mGranted{}
  {
    mNode.ListLinkAfter(&economy->mConsumptionData);
  }

  /**
   * Address: 0x00773990 (FUN_00773990, Moho::CEconRequest::MemberConstruct)
   *
   * What it does:
   * Allocates one `CEconRequest`, resets intrusive links/economy values, and
   * publishes the object as an unowned construct result.
   */
  void CEconRequest::MemberConstruct(
    gpg::ReadArchive&,
    const int,
    const gpg::RRef&,
    gpg::SerConstructResult& result
  )
  {
    result.SetUnowned(gpg::MakeRRef(new CEconRequest()), 0u);
  }

  /**
   * Address: 0x00774A60 (FUN_00774A60, Moho::CEconRequest::MemberDeserialize)
   *
   * What it does:
   * Deserializes requested and granted economy-value lanes.
   */
  void CEconRequest::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);

    archive->Read(econValueType, &mRequested, nullOwner);
    archive->Read(econValueType, &mGranted, nullOwner);
  }

  /**
   * Address: 0x00774AE0 (FUN_00774AE0, Moho::CEconRequest::MemberSerialize)
   *
   * What it does:
   * Serializes requested and granted economy-value lanes.
   */
  void CEconRequest::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};
    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);

    archive->Write(econValueType, &mRequested, nullOwner);
    archive->Write(econValueType, &mGranted, nullOwner);
  }

  /**
   * Address: 0x00773770 (FUN_00773770, Moho::CEconRequest::LimitingRate)
   *
   * What it does:
   * Computes limiting fulfillment ratio for requested economy lanes by
   * selecting the smallest granted/requested ratio across energy and mass.
   */
  float CEconRequest::LimitingRate() const
  {
    float limitingRate = 1.0f;

    if (mRequested.energy > 0.0f) {
      const float energyRatio = mGranted.energy / mRequested.energy;
      if (energyRatio <= limitingRate) {
        limitingRate = energyRatio;
      }
    }

    if (mRequested.mass > 0.0f) {
      const float massRatio = mGranted.mass / mRequested.mass;
      if (massRatio <= limitingRate) {
        limitingRate = massRatio;
      }
    }

    return limitingRate;
  }
} // namespace moho

/**
 * Address: 0x00774EF0 (FUN_00774EF0, ??0CEconomyEvent@Moho@@QAE@@Z)
 */
moho::CEconomyEvent::CEconomyEvent(
  Unit* const unit,
  const float requestedEnergy,
  const float requestedMass,
  const float durationSeconds,
  const LuaPlus::LuaObject& progressCallback
)
  : CScriptEvent()
  , mUnit(unit)
  , mRequestedPerTick{}
  , mRequest(nullptr)
  , mProgressCallback(progressCallback)
  , mRemainingTicks(static_cast<std::int32_t>(durationSeconds * 10.0f))
  , mTotalTicks(mRemainingTicks)
{
  auto* const entity = static_cast<Entity*>(mUnit);
  auto* const sim = entity->SimulationRef;
  LuaPlus::LuaState* const luaState = sim ? sim->GetLuaState() : nullptr;

  LuaPlus::LuaObject metatable = GetEconomyEventFactory(luaState);
  LuaPlus::LuaObject arg1;
  LuaPlus::LuaObject arg2;
  LuaPlus::LuaObject arg3;
  CreateLuaObject(metatable, arg1, arg2, arg3);

  const std::int32_t clampedRemaining = mRemainingTicks > 1 ? mRemainingTicks : 1;
  mRemainingTicks = clampedRemaining;

  const float scale = 1.0f / static_cast<float>(clampedRemaining);
  mRequestedPerTick.energy = requestedEnergy * scale;
  mRequestedPerTick.mass = requestedMass * scale;

  auto* const army = entity->ArmyRef;
  CSimArmyEconomyInfo* const economyInfo = army->GetEconomy();

  mRequest = new CEconRequest{};
  mRequest->mRequested = mRequestedPerTick;
  mRequest->mGranted.energy = 0.0f;
  mRequest->mGranted.mass = 0.0f;
  IntrusiveLinkBefore(mRequest->mNode, economyInfo->registrationNode);
}

/**
 * Address: 0x00775140 (FUN_00775140, sub_775140)
 */
moho::CEconomyEvent::CEconomyEvent()
  : CScriptEvent()
  , mUnit(nullptr)
  , mRequestedPerTick{}
  , mRequest(nullptr)
  , mProgressCallback()
  , mRemainingTicks(0)
  , mTotalTicks(0)
{}

/**
 * Address: 0x00775120 (FUN_00775120, scalar deleting thunk)
 * Address: 0x007751C0 (FUN_007751C0, sub_7751C0)
 */
moho::CEconomyEvent::~CEconomyEvent()
{
  ClearUnitRequestedRates(mUnit);
  mProgressCallback = LuaPlus::LuaObject{};
  DestroyEconomyRequestPointer(mRequest);
}

/**
 * Address: 0x00775B20 (FUN_00775B20, ?GetClass@CEconomyEvent@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* moho::CEconomyEvent::GetClass() const
{
  return CachedCEconomyEventType();
}

/**
 * Address: 0x00775B40 (FUN_00775B40, ?GetDerivedObjectRef@CEconomyEvent@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef moho::CEconomyEvent::GetDerivedObjectRef()
{
  return MakeTypedRef(this, CachedCEconomyEventType());
}

/**
 * Address: 0x00775270 (FUN_00775270, sub_775270)
 */
void moho::CEconomyEvent::ProcessTick()
{
  if (mRemainingTicks != 0 && mRequest != nullptr && mUnit != nullptr) {
    mUnit->mUnitVarDat.mMaintainenceCost.ENERGY = mRequestedPerTick.energy;
    mUnit->mUnitVarDat.mMaintainenceCost.MASS = mRequestedPerTick.mass;

    if (mRequest->mGranted.energy >= mRequestedPerTick.energy && mRequest->mGranted.mass >= mRequestedPerTick.mass) {
      LuaPlus::LuaObject* callbackUnitLuaCleanupLane = nullptr;
      const SEconValue granted = TakeGrantedResourcesAndReset(mRequest);
      mUnit->mUnitVarDat.mResourcesSpent.ENERGY += granted.energy;
      mUnit->mUnitVarDat.mResourcesSpent.MASS += granted.mass;

      --mRemainingTicks;

      if (!mProgressCallback.IsNil()) {
        // A failing progress script is logged, not propagated (FuncInfo
        // 0x00ED65C8: runtime_error handler at 0x0077539B).
        const LuaPlus::LuaFunction<void> progressCallback(mProgressCallback);
        try {
          const float progress = 1.0f - static_cast<float>(mRemainingTicks) / static_cast<float>(mTotalTicks);
          progressCallback.Call_ObjectNum(mUnit->GetLuaObject(), progress);
        } catch (const msvc8::runtime_error& error) {
          gpg::Warnf("Error executing progress function: %s", error.what());
        }
      }

      if (mRemainingTicks == 0) {
        DestroyEconomyRequestPointer(mRequest);
        EventSetSignaled(true);
      }

      DestroyHeapLuaObjectCleanupLane(callbackUnitLuaCleanupLane);
    }
  } else {
    ClearUnitRequestedRates(mUnit);
  }
}

bool moho::CEconomyEvent::IsDone() const noexcept
{
  return mRemainingTicks == 0;
}

/**
  * Alias of FUN_1001FDE0 (non-canonical helper lane).
 */
moho::CScrLuaMetatableFactory<moho::CEconomyEvent>::CScrLuaMetatableFactory()
  : CScrLuaObjectFactory(CScrLuaObjectFactory::AllocateFactoryObjectIndex())
{}

moho::CScrLuaMetatableFactory<moho::CEconomyEvent>& moho::CScrLuaMetatableFactory<moho::CEconomyEvent>::Instance()
{
  return sInstance;
}

/**
 * Address: 0x00775B80 (FUN_00775B80)
 */
LuaPlus::LuaObject moho::CScrLuaMetatableFactory<moho::CEconomyEvent>::Create(LuaPlus::LuaState* const state)
{
  return SCR_CreateSimpleMetatable(state);
}

namespace
{
} // namespace

/**
 * Address: 0x00774E40 (FUN_00774E40, scalar deleting destructor thunk)
 */
moho::CEconomyEventTypeInfo::~CEconomyEventTypeInfo() = default;

/**
 * Address: 0x00774E30 (FUN_00774E30, ?GetName@CEconomyEventTypeInfo@Moho@@UBEPBDXZ)
 */
const char* moho::CEconomyEventTypeInfo::GetName() const
{
  return "CEconomyEvent";
}

/**
 * Address: 0x00774E00 (FUN_00774E00, ?Init@CEconomyEventTypeInfo@Moho@@UAEXXZ)
 */
void moho::CEconomyEventTypeInfo::Init()
{
  size_ = sizeof(CEconomyEvent);
  AddCScriptEventBaseToCEconomyEventType(this);
  gpg::RType::Init();
  Finish();
}

/**
  * Alias of FUN_00775630 (non-canonical helper lane).
 */
int moho::cfunc_CreateEconomyEvent(lua_State* const luaContext)
{
  auto* const state = ResolveBindingState(luaContext);
  return cfunc_CreateEconomyEventL(state);
}

/**
 * Address: 0x00775650 (FUN_00775650, func_CreateEconomyEvent_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateEconomyEvent`.
 */
moho::CScrLuaInitForm* moho::func_CreateEconomyEvent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "CreateEconomyEvent",
    &moho::cfunc_CreateEconomyEvent,
    nullptr,
    "<global>",
    kCreateEconomyEventLuaHelp
  );
  return &binder;
}

/**
 * Address: 0x007756B0 (FUN_007756B0, cfunc_CreateEconomyEventL)
 */
int moho::cfunc_CreateEconomyEventL(LuaPlus::LuaState* const state)
{
  const int argCount = lua_gettop(state->m_state);
  if (argCount < 4 || argCount > 5) {
    RaiseLuaArgCountError(state, kCreateEconomyEventHelp, 4, 5, argCount);
  }

  lua_settop(state->m_state, 5);

  const LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
  Unit* const unit = ResolveUnitFromLuaObject(unitObject, state);

  const float energy = ReadLuaNumberOrError(state, 2);
  const float mass = ReadLuaNumberOrError(state, 3);
  const float duration = ReadLuaNumberOrError(state, 4);

  const LuaPlus::LuaObject callbackObject(LuaPlus::LuaStackObject(state, 5));
  auto* const event = new CEconomyEvent(unit, energy, mass, duration, callbackObject);
  unit->mEconomyEventListHead.push_back(event);

  event->mLuaObj.PushStack(state);
  return 1;
}

/**
  * Alias of FUN_00775910 (non-canonical helper lane).
 */
int moho::cfunc_RemoveEconomyEvent(lua_State* const luaContext)
{
  auto* const state = ResolveBindingState(luaContext);
  return cfunc_RemoveEconomyEventL(state);
}

/**
 * Address: 0x00775930 (FUN_00775930, func_RemoveEconomyEvent_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveEconomyEvent`.
 */
moho::CScrLuaInitForm* moho::func_RemoveEconomyEvent_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "RemoveEconomyEvent",
    &moho::cfunc_RemoveEconomyEvent,
    nullptr,
    "<global>",
    kRemoveEconomyEventLuaHelp
  );
  return &binder;
}

/**
 * Address: 0x00775990 (FUN_00775990, cfunc_RemoveEconomyEventL)
 */
int moho::cfunc_RemoveEconomyEventL(LuaPlus::LuaState* const state)
{
  const int argCount = lua_gettop(state->m_state);
  if (argCount != 2) {
    RaiseLuaArgCountError(state, kRemoveEconomyEventHelp, 2, argCount);
  }

  const LuaPlus::LuaObject payload(LuaPlus::LuaStackObject(state, 2));
  CEconomyEvent* const event = func_GetCEconomyEvent(payload, state);
  delete event;
  return 0;
}

/**
  * Alias of FUN_00775A40 (non-canonical helper lane).
 */
int moho::cfunc_EconomyEventIsDone(lua_State* const luaContext)
{
  auto* const state = ResolveBindingState(luaContext);
  return cfunc_EconomyEventIsDoneL(state);
}

/**
 * Address: 0x00775A60 (FUN_00775A60, func_EconomyEventIsDone_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EconomyEventIsDone`.
 */
moho::CScrLuaInitForm* moho::func_EconomyEventIsDone_LuaFuncDef()
{
  static CScrLuaBinder binder(
    SimLuaInitSet(),
    "EconomyEventIsDone",
    &moho::cfunc_EconomyEventIsDone,
    nullptr,
    "<global>",
    kEconomyEventIsDoneLuaHelp
  );
  return &binder;
}

/**
 * Address: 0x00775AC0 (FUN_00775AC0, cfunc_EconomyEventIsDoneL)
 */
int moho::cfunc_EconomyEventIsDoneL(LuaPlus::LuaState* const state)
{
  const int argCount = lua_gettop(state->m_state);
  if (argCount != 1) {
    RaiseLuaArgCountError(state, kEconomyEventIsDoneHelp, 1, argCount);
  }

  const LuaPlus::LuaObject payload(LuaPlus::LuaStackObject(state, 1));
  const CEconomyEvent* const event = func_GetCEconomyEvent(payload, state);
  lua_pushboolean(state->m_state, event->mRemainingTicks == 0);
  return 1;
}

/**
 * Address: 0x00775EC0 (FUN_00775EC0, func_GetCEconomyEvent)
 */
moho::CEconomyEvent* moho::func_GetCEconomyEvent(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
{
  return ResolveTypedGameObject<CEconomyEvent>(object, state, CachedCEconomyEventType());
}

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterCEconomyEventPointerType_bf228f, moho::PreregisterCEconomyEventPointerType)
GPG_PREREGISTER_INIT(preregister_CEconomyEventTypeInfo_bf228f, moho::preregister_CEconomyEventTypeInfo)

namespace
{
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
  struct CEconomyEventLuaFuncDefBootstrap
  {
    CEconomyEventLuaFuncDefBootstrap()
    {
      (void)::moho::func_CreateEconomyEvent_LuaFuncDef();
      (void)::moho::func_RemoveEconomyEvent_LuaFuncDef();
      (void)::moho::func_EconomyEventIsDone_LuaFuncDef();
    }
  };

  const CEconomyEventLuaFuncDefBootstrap gCEconomyEventLuaFuncDefBootstrap{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007754E0 (FUN_007754E0)
   */
  void CEconomyEvent::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new CEconomyEvent()), 0u);
  }

  /**
   * Address: 0x00776010 (FUN_00776010)
   */
  void CEconomyEvent::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef owner{};
    archive->Read(gpg::RTypeOf<CScriptEvent>(), static_cast<CScriptEvent*>(this), owner);
    archive->ReadPointer(&mUnit, &owner);
    archive->Read(gpg::RTypeOf<SEconValue>(), &mRequestedPerTick, owner);

    CEconRequest* request = nullptr;
    archive->ReadPointerOwned(&request, &owner);
    CEconRequest* const replaced = mRequest;
    mRequest = request;
    delete replaced;

    archive->Read(gpg::RTypeOf<LuaPlus::LuaObject>(), &mProgressCallback, owner);
    archive->ReadInt(&mRemainingTicks);
    archive->ReadInt(&mTotalTicks);
  }

  /**
   * Address: 0x00776140 (FUN_00776140)
   */
  void CEconomyEvent::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef owner{};
    archive->Write(gpg::RTypeOf<CScriptEvent>(), static_cast<const CScriptEvent*>(this), owner);
    archive->WritePointer(mUnit, gpg::TrackedPointerState::Unowned, owner);
    archive->Write(gpg::RTypeOf<SEconValue>(), &mRequestedPerTick, owner);
    archive->WritePointer(mRequest, gpg::TrackedPointerState::Owned, owner);
    archive->Write(gpg::RTypeOf<LuaPlus::LuaObject>(), &mProgressCallback, owner);
    archive->WriteInt(mRemainingTicks);
    archive->WriteInt(mTotalTicks);
  }

  /**
   * `gpg::SerConstructHelper<CEconRequest>`, vtable 0x00E36E40.
   *
   * Address: 0x00BDD210 (FUN_00BDD210 -- constructs the global and registers its destructor.)
   * Address: 0x00C023D0 (FUN_00C023D0 -- the global's destructor.)
   * Address: 0x007738F0 (FUN_007738F0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00773EC0 (FUN_00773EC0 -- `Init`.)
   * Address: 0x00773980 (FUN_00773980 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x007743E0 (FUN_007743E0 -- `Delete`.)
   */
  struct CEconRequestConstruct : gpg::SerConstructHelper<CEconRequest>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CEconRequest>`, vtable 0x00E36E50.
   *
   * Address: 0x00BDD250 (FUN_00BDD250 -- constructs the global and registers its destructor.)
   * Address: 0x00C02400 (FUN_00C02400 -- the global's destructor.)
   * Address: 0x00773A20 (FUN_00773A20 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00773F40 (FUN_00773F40 -- `Init`.)
   * Address: 0x00773A00 (FUN_00773A00 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00773A10 (FUN_00773A10 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CEconRequestSerializer : gpg::SerSaveLoadHelper<CEconRequest>
  {};

  /**
   * `gpg::SerConstructHelper<CEconomyEvent>`, vtable 0x00E36FE4.
   *
   * Address: 0x00BDD360 (FUN_00BDD360 -- constructs the global and registers its destructor.)
   * Address: 0x00C024B0 (FUN_00C024B0 -- the global's destructor.)
   * Address: 0x00775C40 (FUN_00775C40 -- `Init`.)
   * Address: 0x007754D0 (FUN_007754D0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x00775E70 (FUN_00775E70 -- `Delete`.)
   */
  struct CEconomyEventConstruct : gpg::SerConstructHelper<CEconomyEvent>
  {};

  /**
   * `gpg::SerSaveLoadHelper<CEconomyEvent>`, vtable 0x00E36FF4.
   *
   * Address: 0x00BDD3A0 (FUN_00BDD3A0 -- constructs the global and registers its destructor.)
   * Address: 0x00C024E0 (FUN_00C024E0 -- the global's destructor.)
   * Address: 0x00775CC0 (FUN_00775CC0 -- `Init`.)
   * Address: 0x00775570 (FUN_00775570 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00775580 (FUN_00775580 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct CEconomyEventSerializer : gpg::SerSaveLoadHelper<CEconomyEvent>
  {};
} // namespace moho

namespace
{
  // Address: 0x010BB81C -- process-global `CEconRequestConstruct` singleton.
  moho::CEconRequestConstruct gCEconRequestConstruct;

  // Address: 0x010BB808 -- process-global `CEconRequestSerializer` singleton.
  moho::CEconRequestSerializer gCEconRequestSerializer;

  // Address: 0x010BB9A8 -- process-global `CEconomyEventConstruct` singleton.
  moho::CEconomyEventConstruct gCEconomyEventConstruct;

  // Address: 0x010BB994 -- process-global `CEconomyEventSerializer` singleton.
  moho::CEconomyEventSerializer gCEconomyEventSerializer;
} // namespace

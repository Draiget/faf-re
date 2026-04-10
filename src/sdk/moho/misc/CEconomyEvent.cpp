#include "moho/misc/CEconomyEvent.h"

#include <cstdint>
#include <new>
#include <stdexcept>
#include <typeinfo>
#include <type_traits>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/entity/Entity.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

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
    static moho::CScrLuaInitFormSet sSet("sim");
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

  [[nodiscard]] gpg::RType* CachedUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::Unit));
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

  [[nodiscard]] gpg::RType* CachedCEconRequestType()
  {
    if (!moho::CEconRequest::sType) {
      moho::CEconRequest::sType = gpg::LookupRType(typeid(moho::CEconRequest));
    }
    return moho::CEconRequest::sType;
  }

  [[nodiscard]] gpg::RType* CachedLuaObjectType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(LuaPlus::LuaObject));
    }
    return cached;
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

  void AddCScriptEventBase(gpg::RType* typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptEventType();
    gpg::RField baseField(baseType->GetName(), baseType, 0, 0, nullptr);
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RRef ExtractUserDataSlotRef(const LuaPlus::LuaObject& userDataObject)
  {
    gpg::RRef out{};
    if (!userDataObject.IsUserData()) {
      return out;
    }

    lua_State* const lstate = userDataObject.GetActiveCState();
    if (!lstate) {
      return out;
    }

    const int top = lua_gettop(lstate);
    const_cast<LuaPlus::LuaObject&>(userDataObject).PushStack(lstate);
    void* const rawUserData = lua_touserdata(lstate, -1);
    if (rawUserData) {
      out = *static_cast<gpg::RRef*>(rawUserData);
    }
    lua_settop(lstate, top);
    return out;
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

  [[nodiscard]] LuaPlus::LuaObject GetEconomyEventMetatable(LuaPlus::LuaState* state)
  {
    if (!state) {
      return {};
    }
    return moho::CScrLuaMetatableFactory<moho::CEconomyEvent>::Instance().Get(state);
  }

  void InvokeProgressCallback(const LuaPlus::LuaObject& callback, LuaPlus::LuaObject unitObject, const float progress)
  {
    lua_State* const activeState = callback.GetActiveCState();
    const int savedTop = lua_gettop(activeState);
    const_cast<LuaPlus::LuaObject&>(callback).PushStack(activeState);
    unitObject.PushStack(activeState);
    lua_pushnumber(activeState, progress);
    lua_call(activeState, 2, 1);
    lua_settop(activeState, savedTop);
  }

  void ClearUnitRequestedRates(moho::Unit* unit)
  {
    unit->SharedEconomyRateEnergy = 0.0f;
    unit->SharedEconomyRateMass = 0.0f;
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

  [[nodiscard]] moho::CEconRequest* ReadCEconRequestPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedCEconRequestType());
    if (upcast.mObj) {
      return static_cast<moho::CEconRequest*>(upcast.mObj);
    }

    const char* const expected = CachedCEconRequestType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "CEconRequest",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  void WriteCEconRequestPointer(gpg::WriteArchive* archive, moho::CEconRequest* request, const gpg::RRef& ownerRef)
  {
    const gpg::RRef objectRef = MakeTypedRef(request, CachedCEconRequestType());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Owned, ownerRef);
  }

  [[nodiscard]] moho::Unit* ReadUnitPointer(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedUnitType());
    if (upcast.mObj) {
      return static_cast<moho::Unit*>(upcast.mObj);
    }

    const char* const expected = CachedUnitType()->GetName();
    const char* const actual = source.GetTypeName();
    const msvc8::string msg = gpg::STR_Printf(
      "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
      "instead",
      expected ? expected : "Unit",
      actual ? actual : "null"
    );
    throw std::runtime_error(msg.c_str());
  }

  void WriteUnitPointer(gpg::WriteArchive* archive, moho::Unit* unit, const gpg::RRef& ownerRef)
  {
    const gpg::RRef objectRef = MakeTypedRef(unit, CachedUnitType());
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  /**
   * Address: 0x00776010 (FUN_00776010, sub_776010)
   */
  void DeserializeCEconomyEvent(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const event = reinterpret_cast<moho::CEconomyEvent*>(objectPtr);
    GPG_ASSERT(event != nullptr);

    gpg::RType* const baseType = CachedCScriptEventType();
    GPG_ASSERT(baseType && baseType->serLoadFunc_);
    gpg::RRef owner{};
    baseType->serLoadFunc_(archive, objectPtr, baseType->version_, &owner);

    event->mUnit = ReadUnitPointer(archive, owner);
    archive->Read(CachedSEconValueType(), &event->mRequestedPerTick, owner);

    moho::CEconRequest* const loadedRequest = ReadCEconRequestPointer(archive, owner);
    DestroyEconomyRequestPointer(event->mRequest);
    event->mRequest = loadedRequest;

    archive->Read(CachedLuaObjectType(), &event->mProgressCallback, owner);
    archive->ReadInt(&event->mRemainingTicks);
    archive->ReadInt(&event->mTotalTicks);
  }

  /**
   * Address: 0x00776140 (FUN_00776140, sub_776140)
   */
  void SerializeCEconomyEvent(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    auto* const event = reinterpret_cast<moho::CEconomyEvent*>(objectPtr);
    GPG_ASSERT(event != nullptr);

    gpg::RType* const baseType = CachedCScriptEventType();
    GPG_ASSERT(baseType && baseType->serSaveFunc_);
    gpg::RRef owner{};
    baseType->serSaveFunc_(archive, objectPtr, baseType->version_, &owner);

    WriteUnitPointer(archive, event->mUnit, owner);
    archive->Write(CachedSEconValueType(), &event->mRequestedPerTick, owner);
    WriteCEconRequestPointer(archive, event->mRequest, owner);
    archive->Write(CachedLuaObjectType(), &event->mProgressCallback, owner);
    archive->WriteInt(event->mRemainingTicks);
    archive->WriteInt(event->mTotalTicks);
  }
} // namespace

/**
 * Address: 0x005D1C70 (FUN_005D1C70, gpg::RRef_CEconRequest)
 *
 * What it does:
 * Builds a typed reflection reference for `CEconRequest*`, resolving derived
 * runtime type + base adjustment when required.
 */
gpg::RRef* gpg::RRef_CEconRequest(gpg::RRef* const outRef, moho::CEconRequest* const value)
{
  return BuildTypedRefWithCache(
    outRef,
    value,
    typeid(moho::CEconRequest),
    moho::CEconRequest::sType,
    gCEconRequestRRefCache
  );
}

namespace moho
{
  gpg::RType* SEconValue::sType = nullptr;
  gpg::RType* CEconRequest::sType = nullptr;
  gpg::RType* CEconomyEvent::sType = nullptr;
  CScrLuaMetatableFactory<CEconomyEvent> CScrLuaMetatableFactory<CEconomyEvent>::sInstance{};
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
  , mUnitEventNode()
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

  LuaPlus::LuaObject metatable = GetEconomyEventMetatable(luaState);
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
  , mUnitEventNode()
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
  IntrusiveUnlink(mUnitEventNode);
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
    mUnit->SharedEconomyRateEnergy = mRequestedPerTick.energy;
    mUnit->SharedEconomyRateMass = mRequestedPerTick.mass;

    if (mRequest->mGranted.energy >= mRequestedPerTick.energy && mRequest->mGranted.mass >= mRequestedPerTick.mass) {
      const SEconValue granted = TakeGrantedResourcesAndReset(mRequest);
      mUnit->mBeatResourceAccumulators.resourcesSpentEnergy += granted.energy;
      mUnit->mBeatResourceAccumulators.resourcesSpentMass += granted.mass;

      --mRemainingTicks;

      if (!mProgressCallback.IsNil()) {
        const float progress = 1.0f - static_cast<float>(mRemainingTicks) / static_cast<float>(mTotalTicks);
        LuaPlus::LuaObject unitLuaObject = mUnit->GetLuaObject();
        InvokeProgressCallback(mProgressCallback, unitLuaObject, progress);
      }

      if (mRemainingTicks == 0) {
        DestroyEconomyRequestPointer(mRequest);
        EventSetSignaled(true);
      }
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
 * Address: 0x1001FDE0 (MohoEngine.dll constructor shape)
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

/**
 * Address: 0x00775C40 (FUN_00775C40, sub_775C40)
 */
void moho::CEconomyEventConstruct::RegisterConstructFunction()
{
  gpg::RType* const type = CachedCEconomyEventType();
  GPG_ASSERT(type->serConstructFunc_ == nullptr);
  type->serConstructFunc_ = mSerConstructFunc;
  type->deleteFunc_ = mDeleteFunc;
}

/**
 * Address: 0x00775CC0 (FUN_00775CC0, sub_775CC0)
 */
void moho::CEconomyEventSerializer::RegisterSerializeFunctions()
{
  gpg::RType* const type = CachedCEconomyEventType();
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

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
  AddCScriptEventBase(this);
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00775630 (FUN_00775630, cfunc_CreateEconomyEvent)
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
  IntrusiveLinkBefore(event->mUnitEventNode, unit->mEconomyEventListHead);

  event->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x00775910 (FUN_00775910, cfunc_RemoveEconomyEvent)
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
 * Address: 0x00775A40 (FUN_00775A40, cfunc_EconomyEventIsDone)
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

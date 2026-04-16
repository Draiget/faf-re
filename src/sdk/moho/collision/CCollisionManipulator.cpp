#include "CCollisionManipulator.h"

#include <cstddef>
#include <cstdlib>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/animation/CAniActor.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/script/CScriptObject.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"
#include "Wm3Quaternion.h"

namespace moho
{
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  constexpr const char* kCollisionManipulatorLuaClassName = "CCollisionManipulator";
  constexpr const char* kCollisionManipulatorCreateCollisionDetectorHelpText =
    "CreateCollisionDetector(unit) -- create a collision detection manipulator";
  constexpr const char* kCollisionManipulatorEnableTerrainCheckHelpText =
    "Make manipulator check for terrain height intersection";
  constexpr const char* kCollisionManipulatorEnableHelpText =
    "Fixme: this should just use base manipulator enable/disable";
  constexpr const char* kCollisionManipulatorDisableHelpText =
    "Fixme: this should just use base manipulator enable/disable";
  constexpr const char* kCollisionManipulatorWatchBoneHelpText =
    "CollisionDetector:WatchBone(bone) -- add the given bone to those watched by this manipulator";
  constexpr std::uint32_t kWatchBoneActiveMask = 0x8000u;
  constexpr std::uint32_t kAnimCollisionNotifiedMask = 0x0001u;
  constexpr std::uint32_t kTerrainCollisionNotifiedMask = 0x0002u;
  constexpr float kOrientationCollisionThreshold = 0.1f;
  constexpr int kCollisionManipulatorPrecedence = 99;

  alignas(moho::CCollisionManipulatorTypeInfo)
    std::byte gCCollisionManipulatorTypeInfoStorage[sizeof(moho::CCollisionManipulatorTypeInfo)]{};
  bool gCCollisionManipulatorTypeInfoConstructed = false;
  moho::CCollisionManipulatorSerializer gCCollisionManipulatorSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mNext = self;
    helper.mPrev = self;
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("sim"); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("sim");
    return fallbackSet;
  }

  [[nodiscard]] moho::CCollisionManipulatorTypeInfo& AcquireCCollisionManipulatorTypeInfo()
  {
    if (!gCCollisionManipulatorTypeInfoConstructed) {
      new (gCCollisionManipulatorTypeInfoStorage) moho::CCollisionManipulatorTypeInfo();
      gCCollisionManipulatorTypeInfoConstructed = true;
    }

    return *reinterpret_cast<moho::CCollisionManipulatorTypeInfo*>(gCCollisionManipulatorTypeInfoStorage);
  }

  /**
   * Address: 0x00637840 (FUN_00637840)
   *
   * What it does:
   * Resolves and caches the reflected runtime type for
   * `CCollisionManipulator`.
   */
  [[nodiscard]] gpg::RType* ResolveCCollisionManipulatorTypeCachePrimary()
  {
    if (!moho::CCollisionManipulator::sType) {
      moho::CCollisionManipulator::sType = gpg::LookupRType(typeid(moho::CCollisionManipulator));
    }
    return moho::CCollisionManipulator::sType;
  }

  /**
   * Address: 0x00638670 (FUN_00638670)
   *
   * What it does:
   * Secondary duplicate lane that resolves/caches
   * `CCollisionManipulator` reflection type.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* ResolveCCollisionManipulatorTypeCacheSecondary()
  {
    if (!moho::CCollisionManipulator::sType) {
      moho::CCollisionManipulator::sType = gpg::LookupRType(typeid(moho::CCollisionManipulator));
    }
    return moho::CCollisionManipulator::sType;
  }

  [[nodiscard]] gpg::RType* CachedCCollisionManipulatorType()
  {
    return ResolveCCollisionManipulatorTypeCachePrimary();
  }

  /**
   * Address: 0x006377B0 (FUN_006377B0)
   *
   * What it does:
   * Translates one world-space point into a local origin lane and rotates it
   * by the inverse of one quaternion lane set.
   */
  [[maybe_unused]] Wm3::Vector3f* TransformWorldPointByInverseQuaternionLanes(
    const float* const transformLanes,
    Wm3::Vector3f* const outVector,
    const float* const worldPointLanes
  )
  {
    Wm3::Vector3f localPoint{};
    localPoint.x = worldPointLanes[0] - transformLanes[4];
    localPoint.y = worldPointLanes[1] - transformLanes[5];
    localPoint.z = worldPointLanes[2] - transformLanes[6];

    Wm3::Quaternionf inverseRotation{};
    inverseRotation.x = transformLanes[0];
    inverseRotation.y = -transformLanes[1];
    inverseRotation.z = -transformLanes[2];
    inverseRotation.w = -transformLanes[3];

    moho::MultQuadVec(outVector, &localPoint, &inverseRotation);
    return outVector;
  }

  /**
   * Address: 0x00638D10 (FUN_00638D10)
   *
   * What it does:
   * Upcasts one reflected reference lane to `moho::CCollisionManipulator*`.
   */
  [[maybe_unused]] [[nodiscard]] void* TryUpcastCCollisionManipulatorRefObject(gpg::RRef* const sourceRef)
  {
    if (!sourceRef) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedCCollisionManipulatorType());
    return upcast.mObj;
  }

  gpg::RType* CachedIAniManipulatorType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IAniManipulator));
    }
    return cached;
  }

  gpg::RType* CachedIUnitType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::IUnit));
    }
    return cached;
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

  void AddIAniManipulatorBase(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedIAniManipulatorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  [[nodiscard]] gpg::RRef MakeIUnitRef(const moho::Unit* unit)
  {
    gpg::RRef out{};
    out.mObj = nullptr;
    out.mType = CachedIUnitType();
    if (!unit) {
      return out;
    }

    auto* const iunit = const_cast<moho::IUnit*>(static_cast<const moho::IUnit*>(unit));
    gpg::RType* dynamicType = CachedIUnitType();
    try {
      dynamicType = gpg::LookupRType(typeid(*iunit));
    } catch (...) {
      dynamicType = CachedIUnitType();
    }

    std::int32_t baseOffset = 0;
    const bool derived = dynamicType->IsDerivedFrom(CachedIUnitType(), &baseOffset);
    GPG_ASSERT(derived);
    if (!derived) {
      out.mObj = iunit;
      out.mType = dynamicType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(iunit) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
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

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedIUnitType());
    if (!upcast.mObj) {
      const char* const expected = CachedIUnitType()->GetName();
      const char* const actual = source.GetTypeName();
      const msvc8::string message = gpg::STR_Printf(
        "Error detected in archive: expected a pointer to an object of type \"%s\" but got an object of type \"%s\" "
        "instead",
        expected ? expected : "IUnit",
        actual ? actual : "unknown"
      );
      throw std::runtime_error(message.c_str());
    }

    auto* const iunit = static_cast<moho::IUnit*>(upcast.mObj);
    return iunit ? iunit->IsUnit() : nullptr;
  }

  void WriteUnitPointer(gpg::WriteArchive* archive, moho::Unit* unit, const gpg::RRef& ownerRef)
  {
    const gpg::RRef objectRef = MakeIUnitRef(unit);
    gpg::WriteRawPointer(archive, objectRef, gpg::TrackedPointerState::Unowned, ownerRef);
  }

  [[nodiscard]] float GetOrientationAlignment(const moho::VTransform& owner, const moho::VTransform& bone)
  {
    return std::abs(Wm3::Quatf::Dot(owner.orient_, bone.orient_));
  }

  void DispatchOwnerScriptCallback(moho::Unit* ownerUnit, const char* callbackName)
  {
    if (!ownerUnit || !callbackName) {
      return;
    }

    auto* const ownerEntity = static_cast<moho::Entity*>(ownerUnit);
    auto* const scriptObject = static_cast<moho::CScriptObject*>(ownerEntity);
    scriptObject->CallbackStr(callbackName);
  }

  [[nodiscard]] float SampleTerrainSurfaceY(const moho::Sim* sim, const moho::VTransform& transform)
  {
    if (!sim || !sim->mMapData) {
      return transform.pos_.y;
    }
    return sim->mMapData->GetSurface(transform.pos_);
  }

  /**
   * Address: 0x00638F00 (FUN_00638F00)
   *
   * What it does:
   * Loads IAniManipulator base payload, then reads owner-unit pointer and two
   * collision mode booleans.
   */
  void DeserializeCCollisionManipulator(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const object = reinterpret_cast<moho::CCollisionManipulator*>(objectPtr);
    GPG_ASSERT(object != nullptr);

    if (gpg::RType* const baseType = CachedIAniManipulatorType();
        baseType != nullptr && baseType->serLoadFunc_ != nullptr) {
      baseType->serLoadFunc_(archive, objectPtr, baseType->version_, ownerRef);
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    object->mOwnerUnit = ReadUnitPointer(archive, owner);
    archive->ReadBool(&object->mCollisionCallbacksEnabled);
    archive->ReadBool(&object->mTerrainCollisionCheckEnabled);
  }

  /**
   * Address: 0x00638930 (FUN_00638930, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards one CCollisionManipulator deserialize thunk alias into the
   * shared deserialize callback body.
   */
  void DeserializeCCollisionManipulatorThunkVariantA(
    gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    DeserializeCCollisionManipulator(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00638C20 (FUN_00638C20, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards a second CCollisionManipulator deserialize thunk alias into
   * the shared deserialize callback body.
   */
  void DeserializeCCollisionManipulatorThunkVariantB(
    gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    DeserializeCCollisionManipulator(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00638F90 (FUN_00638F90)
   *
   * What it does:
   * Saves IAniManipulator base payload, then writes owner-unit pointer and two
   * collision mode booleans.
   */
  void SerializeCCollisionManipulator(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* ownerRef)
  {
    auto* const object = reinterpret_cast<moho::CCollisionManipulator*>(objectPtr);
    GPG_ASSERT(object != nullptr);

    if (gpg::RType* const baseType = CachedIAniManipulatorType();
        baseType != nullptr && baseType->serSaveFunc_ != nullptr) {
      baseType->serSaveFunc_(archive, objectPtr, baseType->version_, ownerRef);
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    WriteUnitPointer(archive, object->mOwnerUnit, owner);
    archive->WriteBool(object->mCollisionCallbacksEnabled);
    archive->WriteBool(object->mTerrainCollisionCheckEnabled);
  }

  /**
   * Address: 0x00638940 (FUN_00638940, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards one CCollisionManipulator serialize thunk alias into the
   * shared serialize callback body.
   */
  void SerializeCCollisionManipulatorThunkVariantA(
    gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    SerializeCCollisionManipulator(archive, objectPtr, version, ownerRef);
  }

  /**
   * Address: 0x00638C30 (FUN_00638C30, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards a second CCollisionManipulator serialize thunk alias into
   * the shared serialize callback body.
   */
  void SerializeCCollisionManipulatorThunkVariantB(
    gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef
  )
  {
    SerializeCCollisionManipulator(archive, objectPtr, version, ownerRef);
  }

  /**
    * Alias of FUN_00638770 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::RRef CreateCollisionManipulatorRefOwned()
  {
    return MakeTypedRef(new moho::CCollisionManipulator(), CachedCCollisionManipulatorType());
  }

  /**
   * Address: 0x00638810 (LAB_00638810, CCollisionManipulatorTypeInfo::deleteFunc_)
   */
  void DeleteCollisionManipulatorOwned(void* object)
  {
    delete static_cast<moho::CCollisionManipulator*>(object);
  }

  /**
    * Alias of FUN_00638830 (non-canonical helper lane).
   */
  [[nodiscard]] gpg::RRef ConstructCollisionManipulatorRefInPlace(void* objectStorage)
  {
    auto* const object = static_cast<moho::CCollisionManipulator*>(objectStorage);
    if (object) {
      new (object) moho::CCollisionManipulator();
    }
    return MakeTypedRef(object, CachedCCollisionManipulatorType());
  }

  /**
   * Address: 0x00637B10 (FUN_00637B10)
   *
   * What it does:
   * In-place constructor lane that initializes one `CCollisionManipulator`
   * object and returns that same storage pointer.
   */
  [[maybe_unused]] [[nodiscard]] moho::CCollisionManipulator* ConstructCollisionManipulatorInPlaceAlias(
    moho::CCollisionManipulator* const objectStorage
  )
  {
    return new (objectStorage) moho::CCollisionManipulator();
  }

  /**
   * Address: 0x006388C0 (LAB_006388C0, CCollisionManipulatorTypeInfo::dtrFunc_)
   */
  void DestroyCollisionManipulatorInPlace(void* object)
  {
    auto* const collisionManipulator = static_cast<moho::CCollisionManipulator*>(object);
    if (collisionManipulator) {
      collisionManipulator->~CCollisionManipulator();
    }
  }
} // namespace

namespace moho
{
  gpg::RType* CCollisionManipulator::sType = nullptr;

  /**
   * Address: 0x00638950 (FUN_00638950, func_CreateCollisionManipulatorObject)
   *
   * What it does:
   * Returns cached `CCollisionManipulator` metatable object from Lua
   * object-factory storage.
   */
  LuaPlus::LuaObject*
  func_CreateCollisionManipulatorObject(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<CCollisionManipulator>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00638770 (FUN_00638770, CCollisionManipulatorTypeInfo::newRefFunc_)
   * Address: 0x00638830 (FUN_00638830, CCollisionManipulatorTypeInfo::ctorRefFunc_)
   */
  CCollisionManipulator::CCollisionManipulator()
    : mOwnerUnit(nullptr)
    , mCollisionCallbacksEnabled(false)
    , mTerrainCollisionCheckEnabled(false)
  {}

  /**
   * Address: 0x00637B70 (FUN_00637B70)
   */
  CCollisionManipulator::CCollisionManipulator(Unit* const ownerUnit, Sim* const sim)
    : IAniManipulator(sim, ownerUnit ? ownerUnit->AniActor : nullptr, kCollisionManipulatorPrecedence)
    , mOwnerUnit(ownerUnit)
    , mCollisionCallbacksEnabled(false)
    , mTerrainCollisionCheckEnabled(false)
  {
    if (sim != nullptr && sim->mLuaState != nullptr) {
      LuaPlus::LuaObject arg3{};
      LuaPlus::LuaObject arg2{};
      LuaPlus::LuaObject arg1{};
      LuaPlus::LuaObject scriptFactory{};
      (void)func_CreateCollisionManipulatorObject(&scriptFactory, sim->mLuaState);
      CreateLuaObject(scriptFactory, arg1, arg2, arg3);
    }
  }

  /**
   * Address: 0x00637B40 (FUN_00637B40, scalar deleting body)
   * Address: 0x00639030 (FUN_00639030, deleting thunk from CScriptObject view)
   */
  CCollisionManipulator::~CCollisionManipulator() = default;

  /**
   * Address: 0x00637860 (FUN_00637860, ?GetClass@CCollisionManipulator@Moho@@UBEPAVRType@gpg@@XZ)
   */
  gpg::RType* CCollisionManipulator::GetClass() const
  {
    return CachedCCollisionManipulatorType();
  }

  /**
   * Address: 0x00637880 (FUN_00637880, ?GetDerivedObjectRef@CCollisionManipulator@Moho@@UAE?AVRRef@gpg@@XZ)
   */
  gpg::RRef CCollisionManipulator::GetDerivedObjectRef()
  {
    return MakeTypedRef(this, CachedCCollisionManipulatorType());
  }

  /**
   * Address: 0x00638020 (FUN_00638020, CreateCollisionDetector Lua path)
   */
  CCollisionManipulator* CCollisionManipulator::CreateCollisionDetector(Unit* const ownerUnit)
  {
    if (!ownerUnit) {
      return nullptr;
    }

    auto* const ownerEntity = static_cast<Entity*>(ownerUnit);
    Sim* const sim = ownerEntity ? ownerEntity->SimulationRef : nullptr;
    return new CCollisionManipulator(ownerUnit, sim);
  }

  /**
   * Address: 0x00637FA0 (FUN_00637FA0, cfunc_CreateCollisionDetector)
   *
   * What it does:
   * Reads one unit argument, allocates a collision manipulator, and pushes its
   * Lua userdata back to the stack.
   */
  int cfunc_CreateCollisionDetector(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCollisionManipulatorCreateCollisionDetectorHelpText,
        1,
        argumentCount
      );
    }

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    Unit* const ownerUnit = SCR_FromLua_Unit(unitObject);
    CCollisionManipulator* const manipulator = CCollisionManipulator::CreateCollisionDetector(ownerUnit);
    if (manipulator != nullptr) {
      manipulator->mLuaObj.PushStack(state);
      return 1;
    }

    return 0;
  }

  /**
   * Address: 0x00637FC0 (FUN_00637FC0, func_CreateCollisionDetector_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreateCollisionDetector(unit)` Lua binder.
   */
  CScrLuaInitForm* func_CreateCollisionDetector_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "CreateCollisionDetector",
      &moho::cfunc_CreateCollisionDetector,
      nullptr,
      "<global>",
      kCollisionManipulatorCreateCollisionDetectorHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00638190 (FUN_00638190, Lua wrapper path)
   */
  void CCollisionManipulator::SetTerrainCollisionCheckEnabled(const bool enabled) noexcept
  {
    mTerrainCollisionCheckEnabled = enabled;
  }

  /**
   * Address: 0x00638110 (FUN_00638110, cfunc_CCollisionManipulatorEnableTerrainCheck)
   *
   * What it does:
   * Reads `(manipulator, enabled)` and toggles terrain collision checks.
   */
  int cfunc_CCollisionManipulatorEnableTerrainCheck(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(
        state,
        "%s\n  expected %d args, but got %d",
        kCollisionManipulatorEnableTerrainCheckHelpText,
        2,
        argumentCount
      );
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CCollisionManipulator* const manipulator = SCR_FromLua_CCollisionManipulator(manipulatorObject, state);

    LuaPlus::LuaStackObject enabledArg(state, 2);
    manipulator->SetTerrainCollisionCheckEnabled(enabledArg.GetBoolean());
    return 0;
  }

  /**
   * Address: 0x00638130 (FUN_00638130, func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:EnableTerrainCheck(bool)` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorEnableTerrainCheck_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "EnableTerrainCheck",
      &moho::cfunc_CCollisionManipulatorEnableTerrainCheck,
      &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(),
      kCollisionManipulatorLuaClassName,
      kCollisionManipulatorEnableTerrainCheckHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00638250 (FUN_00638250, cfunc_CCollisionManipulatorEnable)
   *
   * What it does:
   * Reads one manipulator argument and enables collision callback checks.
   */
  int cfunc_CCollisionManipulatorEnable(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCollisionManipulatorEnableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CCollisionManipulator* const manipulator = SCR_FromLua_CCollisionManipulator(manipulatorObject, state);
    manipulator->EnableCollisionCallbacks();
    return 0;
  }

  /**
   * Address: 0x00638270 (FUN_00638270, func_CCollisionManipulatorEnable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:Enable()` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorEnable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Enable",
      &moho::cfunc_CCollisionManipulatorEnable,
      &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(),
      kCollisionManipulatorLuaClassName,
      kCollisionManipulatorEnableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x00638380 (FUN_00638380, cfunc_CCollisionManipulatorDisable)
   *
   * What it does:
   * Reads one manipulator argument and disables collision callback checks.
   */
  int cfunc_CCollisionManipulatorDisable(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCollisionManipulatorDisableHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CCollisionManipulator* const manipulator = SCR_FromLua_CCollisionManipulator(manipulatorObject, state);
    manipulator->DisableCollisionCallbacks();
    return 0;
  }

  /**
   * Address: 0x006383A0 (FUN_006383A0, func_CCollisionManipulatorDisable_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:Disable()` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorDisable_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "Disable",
      &moho::cfunc_CCollisionManipulatorDisable,
      &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(),
      kCollisionManipulatorLuaClassName,
      kCollisionManipulatorDisableHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006384C0 (FUN_006384C0, cfunc_CCollisionManipulatorWatchBone)
   *
   * What it does:
   * Reads `(manipulator, bone)` and adds the resolved bone to the watch list.
   */
  int cfunc_CCollisionManipulatorWatchBone(lua_State* const luaContext)
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    if (!state || !state->m_state) {
      return 0;
    }

    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, "%s\n  expected %d args, but got %d", kCollisionManipulatorWatchBoneHelpText, 2, argumentCount);
    }

    LuaPlus::LuaObject manipulatorObject(LuaPlus::LuaStackObject(state, 1));
    CCollisionManipulator* const manipulator = SCR_FromLua_CCollisionManipulator(manipulatorObject, state);

    LuaPlus::LuaStackObject boneArg(state, 2);
    CAniActor* const aniActor = static_cast<CAniActor*>(manipulator->mOwnerActor);
    const int boneIndex = aniActor ? aniActor->ResolveBoneIndex(boneArg) : -1;
    if (boneIndex < 0) {
      LuaPlus::LuaState::Error(boneArg.m_state, "A valid bone is required");
    }

    (void)manipulator->WatchBone(boneIndex);
    return 0;
  }

  /**
   * Address: 0x006384E0 (FUN_006384E0, func_CCollisionManipulatorWatchBone_LuaFuncDef)
   *
   * What it does:
   * Publishes the `CCollisionManipulator:WatchBone(bone)` Lua binder.
   */
  CScrLuaInitForm* func_CCollisionManipulatorWatchBone_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      "WatchBone",
      &moho::cfunc_CCollisionManipulatorWatchBone,
      &CScrLuaMetatableFactory<CCollisionManipulator>::Instance(),
      kCollisionManipulatorLuaClassName,
      kCollisionManipulatorWatchBoneHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006382D0 (FUN_006382D0, Lua wrapper path)
   */
  void CCollisionManipulator::EnableCollisionCallbacks() noexcept
  {
    mCollisionCallbacksEnabled = true;
  }

  /**
   * Address: 0x00638400 (FUN_00638400, Lua wrapper path)
   */
  void CCollisionManipulator::DisableCollisionCallbacks() noexcept
  {
    mCollisionCallbacksEnabled = false;
    for (auto* watchBone = mWatchBones.mBegin; watchBone != mWatchBones.mEnd; ++watchBone) {
      watchBone->mFlags &= ~static_cast<int>(kAnimCollisionNotifiedMask);
    }
  }

  /**
   * Address: 0x00638540 (FUN_00638540, Lua wrapper path)
   */
  int CCollisionManipulator::WatchBone(const int boneIndex)
  {
    if (boneIndex < 0) {
      return -1;
    }
    return AddWatchBone(boneIndex);
  }

  Unit* CCollisionManipulator::GetOwnerUnit() const noexcept
  {
    return mOwnerUnit;
  }

  /**
   * Address: 0x00637C90 (FUN_00637C90)
   */
  bool CCollisionManipulator::ManipulatorUpdate()
  {
    if (!mCollisionCallbacksEnabled || !mOwnerUnit) {
      return false;
    }

    auto* const ownerEntity = static_cast<Entity*>(mOwnerUnit);
    if (!ownerEntity) {
      return false;
    }

    const int boneCount = ownerEntity->GetBoneCount();
    const VTransform& ownerTransform = mOwnerUnit->GetTransform();
    bool raisedCallback = false;

    for (auto* watchBone = mWatchBones.mBegin; watchBone != mWatchBones.mEnd; ++watchBone) {
      std::uint32_t flags = static_cast<std::uint32_t>(watchBone->mFlags);
      if ((flags & kWatchBoneActiveMask) == 0u) {
        continue;
      }

      const int boneIndex = watchBone->mBoneIndex;
      if (boneIndex < 0 || boneIndex >= boneCount) {
        continue;
      }

      const VTransform boneTransform = ownerEntity->GetBoneWorldTransform(boneIndex);
      if (!mTerrainCollisionCheckEnabled) {
        const float alignment = GetOrientationAlignment(ownerTransform, boneTransform);
        if (alignment >= kOrientationCollisionThreshold) {
          flags &= ~kAnimCollisionNotifiedMask;
        } else if ((flags & kAnimCollisionNotifiedMask) == 0u) {
          DispatchOwnerScriptCallback(mOwnerUnit, "OnAnimCollision");
          flags |= kAnimCollisionNotifiedMask;
          raisedCallback = true;
        }

        watchBone->mFlags = static_cast<int>(flags);
        continue;
      }

      const float terrainSurfaceY = SampleTerrainSurfaceY(mOwnerSim, boneTransform);
      if ((flags & kTerrainCollisionNotifiedMask) == 0u) {
        if (boneTransform.pos_.y < terrainSurfaceY) {
          flags |= kTerrainCollisionNotifiedMask;
          DispatchOwnerScriptCallback(mOwnerUnit, "OnAnimTerrainCollision");
          raisedCallback = true;
        }
      } else if (terrainSurfaceY <= boneTransform.pos_.y) {
        flags &= ~kTerrainCollisionNotifiedMask;
        DispatchOwnerScriptCallback(mOwnerUnit, "OnNotAnimTerrainCollision");
        raisedCallback = true;
      }

      watchBone->mFlags = static_cast<int>(flags);
    }

    return raisedCallback;
  }

  /**
   * What it does:
   * Stores one factory-table slot index used by CScrLuaObjectFactory::Get.
   */
  CScrLuaMetatableFactory<CCollisionManipulator>& CScrLuaMetatableFactory<CCollisionManipulator>::Instance()
  {
    static CScrLuaMetatableFactory<CCollisionManipulator> instance(
      CScrLuaObjectFactory::AllocateFactoryObjectIndex()
    );
    return instance;
  }

  /**
   * Address: 0x00638BF0 (FUN_00638BF0)
   *
   * What it does:
   * Rebinds the startup metatable-factory index lane for
   * `CScrLuaMetatableFactory<CCollisionManipulator>` and returns that
   * singleton.
   */
  CScrLuaMetatableFactory<CCollisionManipulator>* startup_CScrLuaMetatableFactory_CCollisionManipulator_Index()
  {
    auto& instance = CScrLuaMetatableFactory<CCollisionManipulator>::Instance();
    instance.SetFactoryObjectIndexForRecovery(CScrLuaObjectFactory::AllocateFactoryObjectIndex());
    return &instance;
  }

  /**
   * What it does:
   * Stores one factory-table slot index used by CScrLuaObjectFactory::Get.
   */
  CScrLuaMetatableFactory<CCollisionManipulator>::CScrLuaMetatableFactory(const std::int32_t factoryObjectIndex)
    : CScrLuaObjectFactory(factoryObjectIndex)
  {}

  /**
   * Address: 0x00638640 (FUN_00638640)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<CCollisionManipulator>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x006386E0 (FUN_006386E0, sub_6386E0)
   */
  void CCollisionManipulatorSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveCCollisionManipulatorTypeCacheSecondary();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc ? mSerLoadFunc : &DeserializeCCollisionManipulator;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc ? mSerSaveFunc : &SerializeCCollisionManipulator;
  }

  /**
   * Address: 0x006379A0 (FUN_006379A0, scalar deleting destructor thunk)
   */
  /**
   * Address: 0x00637A00 (FUN_00637A00, CCollisionManipulatorTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Executes one non-deleting destruction lane for
   * `CCollisionManipulatorTypeInfo`.
   */
  [[maybe_unused]] void DestroyCCollisionManipulatorTypeInfoBody(
    CCollisionManipulatorTypeInfo* const typeInfo
  ) noexcept
  {
    typeInfo->~CCollisionManipulatorTypeInfo();
  }

  CCollisionManipulatorTypeInfo::~CCollisionManipulatorTypeInfo() = default;

  /**
   * Address: 0x00637990 (FUN_00637990, ?GetName@CCollisionManipulatorTypeInfo@Moho@@UBEPBDXZ)
   */
  const char* CCollisionManipulatorTypeInfo::GetName() const
  {
    return "CCollisionManipulator";
  }

  /**
   * Address: 0x00637950 (FUN_00637950, ?Init@CCollisionManipulatorTypeInfo@Moho@@UAEXXZ)
   */
  void CCollisionManipulatorTypeInfo::Init()
  {
    size_ = sizeof(CCollisionManipulator);
    (void)gpg::BindRTypeLifecycleCallbacks(
      this,
      &CreateCollisionManipulatorRefOwned,
      &ConstructCollisionManipulatorRefInPlace,
      &DeleteCollisionManipulatorOwned,
      &DestroyCollisionManipulatorInPlace
    );
    gpg::RType::Init();
    AddIAniManipulatorBase(this);
    Finish();
  }

  /**
   * Address: 0x006378F0 (FUN_006378F0, preregister_CCollisionManipulatorTypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup RTTI metadata for `CCollisionManipulator`.
   */
  gpg::RType* preregister_CCollisionManipulatorTypeInfo()
  {
    CCollisionManipulatorTypeInfo& typeInfo = AcquireCCollisionManipulatorTypeInfo();
    gpg::PreRegisterRType(typeid(CCollisionManipulator), &typeInfo);
    return &typeInfo;
  }

  /**
   * Address: 0x00BFAB10 (FUN_00BFAB10, cleanup_CCollisionManipulatorTypeInfo)
   *
   * What it does:
   * Tears down startup-owned RTTI metadata for `CCollisionManipulator`.
   */
  void cleanup_CCollisionManipulatorTypeInfo()
  {
    if (!gCCollisionManipulatorTypeInfoConstructed) {
      return;
    }

    AcquireCCollisionManipulatorTypeInfo().~CCollisionManipulatorTypeInfo();
    gCCollisionManipulatorTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00637A80 (FUN_00637A80)
   *
   * What it does:
   * Initializes callback lanes for global `CCollisionManipulatorSerializer`
   * helper storage and returns that helper object.
   */
  [[maybe_unused]] [[nodiscard]] moho::CCollisionManipulatorSerializer*
  InitializeCCollisionManipulatorSerializerStartupThunkPrimary()
  {
    InitializeHelperNode(gCCollisionManipulatorSerializer);
    gCCollisionManipulatorSerializer.mSerLoadFunc = &DeserializeCCollisionManipulator;
    gCCollisionManipulatorSerializer.mSerSaveFunc = &SerializeCCollisionManipulator;
    return &gCCollisionManipulatorSerializer;
  }

  /**
   * Address: 0x006386B0 (FUN_006386B0)
   *
   * What it does:
   * Secondary startup-init entry for global
   * `CCollisionManipulatorSerializer` helper storage that mirrors the primary
   * callback initialization.
   */
  [[maybe_unused]] [[nodiscard]] moho::CCollisionManipulatorSerializer*
  InitializeCCollisionManipulatorSerializerStartupThunkSecondary()
  {
    return InitializeCCollisionManipulatorSerializerStartupThunkPrimary();
  }

  /**
   * Address: 0x00BFAB70 (FUN_00BFAB70, cleanup_CCollisionManipulatorSerializer)
   *
   * What it does:
   * Unlinks the global serializer helper node from the intrusive serializer
   * helper list and rewires it as a self-linked singleton.
   */
  gpg::SerHelperBase* cleanup_CCollisionManipulatorSerializer()
  {
    gCCollisionManipulatorSerializer.mNext->mPrev = gCCollisionManipulatorSerializer.mPrev;
    gCCollisionManipulatorSerializer.mPrev->mNext = gCCollisionManipulatorSerializer.mNext;

    gpg::SerHelperBase* const self = HelperSelfNode(gCCollisionManipulatorSerializer);
    gCCollisionManipulatorSerializer.mPrev = self;
    gCCollisionManipulatorSerializer.mNext = self;
    return self;
  }

  /**
   * Address: 0x00637AB0 (FUN_00637AB0, cleanup_CCollisionManipulatorSerializerStartupThunkA)
   *
   * What it does:
   * Unlinks one startup helper lane for the global
   * `CCollisionManipulatorSerializer` node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CCollisionManipulatorSerializerStartupThunkA()
  {
    return cleanup_CCollisionManipulatorSerializer();
  }

  /**
   * Address: 0x00637AE0 (FUN_00637AE0, cleanup_CCollisionManipulatorSerializerStartupThunkB)
   *
   * What it does:
   * Unlinks the mirrored startup helper lane for the global
   * `CCollisionManipulatorSerializer` node and restores self-links.
   */
  [[maybe_unused]] gpg::SerHelperBase* cleanup_CCollisionManipulatorSerializerStartupThunkB()
  {
    return cleanup_CCollisionManipulatorSerializer();
  }

  /**
   * Address: 0x00BD2720 (FUN_00BD2720, register_CCollisionManipulatorSerializer)
   *
   * What it does:
   * Initializes global `CCollisionManipulatorSerializer` callback lanes,
   * binds load/save callbacks into RTTI, and installs process-exit cleanup.
   */
  void register_CCollisionManipulatorSerializer()
  {
    InitializeHelperNode(gCCollisionManipulatorSerializer);
    gCCollisionManipulatorSerializer.mSerLoadFunc = &DeserializeCCollisionManipulator;
    gCCollisionManipulatorSerializer.mSerSaveFunc = &SerializeCCollisionManipulator;
    (void)std::atexit(reinterpret_cast<void (*)()>(&cleanup_CCollisionManipulatorSerializer));
  }

  /**
   * Address: 0x00BD2700 (FUN_00BD2700, register_CCollisionManipulatorTypeInfoAtexit)
   *
   * What it does:
   * Preregisters `CCollisionManipulator` RTTI and installs process-exit cleanup.
   */
  int register_CCollisionManipulatorTypeInfoAtexit()
  {
    (void)preregister_CCollisionManipulatorTypeInfo();
    return std::atexit(&cleanup_CCollisionManipulatorTypeInfo);
  }
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x00638D50 (FUN_00638D50, gpg::RRef_CCollisionManipulator)
   *
   * What it does:
   * Builds one typed reflection reference for
   * `moho::CCollisionManipulator*`, preserving dynamic-derived ownership and
   * base-offset adjustment.
   */
  gpg::RRef* RRef_CCollisionManipulator(gpg::RRef* const outRef, moho::CCollisionManipulator* const value)
  {
    if (!outRef) {
      return nullptr;
    }

    *outRef = MakeTypedRef(value, CachedCCollisionManipulatorType());
    return outRef;
  }

  /**
   * Address: 0x00638BC0 (FUN_00638BC0)
   *
   * What it does:
   * Wrapper lane that materializes one temporary `RRef_CCollisionManipulator`
   * and copies object/type fields into the destination reference record.
   */
  [[maybe_unused]] gpg::RRef* AssignCCollisionManipulatorRef(
    gpg::RRef* const outRef, moho::CCollisionManipulator* const value
  )
  {
    if (!outRef) {
      return nullptr;
    }

    gpg::RRef tmp{};
    (void)RRef_CCollisionManipulator(&tmp, value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }
} // namespace gpg

namespace
{
  struct CCollisionManipulatorTypeInfoBootstrap
  {
    CCollisionManipulatorTypeInfoBootstrap()
    {
      (void)moho::register_CCollisionManipulatorTypeInfoAtexit();
      moho::register_CCollisionManipulatorSerializer();
    }
  };

  [[maybe_unused]] CCollisionManipulatorTypeInfoBootstrap gCCollisionManipulatorTypeInfoBootstrap;
} // namespace

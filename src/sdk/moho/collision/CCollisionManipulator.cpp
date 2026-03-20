#include "CCollisionManipulator.h"

#include <cmath>
#include <cstdint>
#include <new>
#include <stdexcept>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"
#include "wm3/Quaternion.h"

namespace gpg
{
  enum class TrackedPointerState : int
  {
    Unowned = 1,
    Owned = 2,
  };

  struct TrackedPointerInfo
  {
    void* object;
    gpg::RType* type;
  };

  TrackedPointerInfo ReadRawPointer(ReadArchive* archive, const gpg::RRef& ownerRef);
  void WriteRawPointer(
    WriteArchive* archive, const gpg::RRef& objectRef, TrackedPointerState state, const gpg::RRef& ownerRef
  );
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
} // namespace gpg

namespace
{
  constexpr std::uint32_t kWatchBoneActiveMask = 0x8000u;
  constexpr std::uint32_t kAnimCollisionNotifiedMask = 0x0001u;
  constexpr std::uint32_t kTerrainCollisionNotifiedMask = 0x0002u;
  constexpr float kOrientationCollisionThreshold = 0.1f;
  constexpr int kCollisionManipulatorPrecedence = 99;

  gpg::RType* CachedCCollisionManipulatorType()
  {
    if (!moho::CCollisionManipulator::sType) {
      moho::CCollisionManipulator::sType = gpg::LookupRType(typeid(moho::CCollisionManipulator));
    }
    return moho::CCollisionManipulator::sType;
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
   * Address: 0x00638770 (FUN_00638770, CCollisionManipulatorTypeInfo::newRefFunc_)
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
   * Address: 0x00638830 (FUN_00638830, CCollisionManipulatorTypeInfo::ctorRefFunc_)
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
  {}

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
   * Address: 0x00638190 (FUN_00638190, Lua wrapper path)
   */
  void CCollisionManipulator::SetTerrainCollisionCheckEnabled(const bool enabled) noexcept
  {
    mTerrainCollisionCheckEnabled = enabled;
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
    gpg::RType* const type = CachedCCollisionManipulatorType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc ? mSerLoadFunc : &DeserializeCCollisionManipulator;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc ? mSerSaveFunc : &SerializeCCollisionManipulator;
  }

  /**
   * Address: 0x006379A0 (FUN_006379A0, scalar deleting destructor thunk)
   */
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
    newRefFunc_ = &CreateCollisionManipulatorRefOwned;
    deleteFunc_ = &DeleteCollisionManipulatorOwned;
    ctorRefFunc_ = &ConstructCollisionManipulatorRefInPlace;
    dtrFunc_ = &DestroyCollisionManipulatorInPlace;
    gpg::RType::Init();
    AddIAniManipulatorBase(this);
    Finish();
  }
} // namespace moho

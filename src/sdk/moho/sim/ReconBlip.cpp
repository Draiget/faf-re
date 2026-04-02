#include "moho/sim/ReconBlip.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "moho/animation/CAniPose.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

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
  constexpr std::uint32_t kUnitCollisionBucketFlags = 0x100u;
  constexpr std::uint32_t kReconEntityFamilyPrefix = 0x300u;
  gpg::RType* gSimType = nullptr;
  gpg::RType* gRMeshBlueprintType = nullptr;
  gpg::RType* gRScmResourceType = nullptr;
  gpg::RType* gCAniPoseType = nullptr;

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] gpg::RType* ResolveRMeshBlueprintType()
  {
    return CachedType<RMeshBlueprint>(gRMeshBlueprintType);
  }

  [[nodiscard]] gpg::RType* ResolveSimType()
  {
    return CachedType<Sim>(gSimType);
  }

  [[nodiscard]] gpg::RType* ResolveRScmResourceType()
  {
    return CachedType<RScmResource>(gRScmResourceType);
  }

  [[nodiscard]] gpg::RType* ResolveCAniPoseType()
  {
    return CachedType<CAniPose>(gCAniPoseType);
  }

  struct ReflectedObjectDeleter
  {
    gpg::RType::delete_func_t deleteFunc = nullptr;

    void operator()(void* const object) const noexcept
    {
      if (deleteFunc) {
        deleteFunc(object);
      }
    }
  };

  [[nodiscard]] bool IsPointerCompatibleWithExpectedType(
    const gpg::TrackedPointerInfo& tracked, gpg::RType* const expectedType
  )
  {
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    return gpg::REF_UpcastPtr(source, expectedType).mObj != nullptr;
  }

  void EnsureTrackedPointerSharedOwnership(gpg::TrackedPointerInfo& tracked)
  {
    if (tracked.state == gpg::TrackedPointerState::Unowned) {
      if (!tracked.type || !tracked.type->deleteFunc_) {
        throw gpg::SerializationError("Ownership conflict while loading archive");
      }

      auto* const control = new boost::detail::sp_counted_impl_pd<void*, ReflectedObjectDeleter>(
        tracked.object, ReflectedObjectDeleter{tracked.type->deleteFunc_}
      );
      tracked.sharedObject = tracked.object;
      tracked.sharedControl = control;
      tracked.state = gpg::TrackedPointerState::Shared;
      return;
    }

    if (tracked.state != gpg::TrackedPointerState::Shared || !tracked.sharedObject || !tracked.sharedControl) {
      throw gpg::SerializationError("Can't mix boost::shared_ptr with other shared pointers.");
    }
  }

  template <typename TObject>
  [[nodiscard]] TObject* ReadPointerUnowned(
    gpg::ReadArchive* const archive, const gpg::RRef& ownerRef, gpg::RType* const expectedType, const char* const typeName
  )
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
      throw gpg::SerializationError(typeName ? typeName : "Archive pointer type mismatch");
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    return static_cast<TObject*>(gpg::REF_UpcastPtr(source, expectedType).mObj);
  }

  template <typename TObject>
  void ReadPointerShared(
    boost::SharedPtrRaw<TObject>& outPointer,
    gpg::ReadArchive* const archive,
    const gpg::RRef& ownerRef,
    gpg::RType* const expectedType,
    const char* const typeName
  )
  {
    gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      outPointer.release();
      return;
    }

    EnsureTrackedPointerSharedOwnership(tracked);
    if (!IsPointerCompatibleWithExpectedType(tracked, expectedType)) {
      throw gpg::SerializationError(typeName ? typeName : "Archive shared-pointer type mismatch");
    }

    boost::SharedPtrRaw<TObject> source{};
    source.px = static_cast<TObject*>(tracked.sharedObject);
    source.pi = tracked.sharedControl;
    outPointer.assign_retain(source);
  }

  template <typename TObject>
  [[nodiscard]] gpg::RRef MakeTypedRef(TObject* const object, gpg::RType* const staticType)
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
    const bool derived = dynamicType && staticType && dynamicType->IsDerivedFrom(staticType, &baseOffset);
    if (!derived) {
      out.mObj = object;
      out.mType = dynamicType ? dynamicType : staticType;
      return out;
    }

    out.mObj =
      reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(object) - static_cast<std::uintptr_t>(baseOffset));
    out.mType = dynamicType;
    return out;
  }

  template <typename TObject>
  void WritePointerWithType(
    gpg::WriteArchive* const archive,
    TObject* const object,
    gpg::RType* const staticType,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    const gpg::RRef objectRef = MakeTypedRef(object, staticType);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  [[nodiscard]] EntId ReserveReconBlipId(Sim* const sim, Unit* const sourceUnit)
  {
    if (!sim || !sim->mEntityDB) {
      return static_cast<EntId>(0);
    }

    const std::uint32_t sourceArmyId = (sourceUnit && sourceUnit->ArmyRef && sourceUnit->ArmyRef->ArmyId >= 0)
      ? static_cast<std::uint32_t>(sourceUnit->ArmyRef->ArmyId)
      : 0u;
    const std::uint32_t requestBits = (sourceArmyId | kReconEntityFamilyPrefix) << 20u;
    return static_cast<EntId>(sim->mEntityDB->DoReserveId(requestBits));
  }

  [[nodiscard]] Wm3::Vec3f ComputeJamOffset(Unit* const sourceUnit, Sim* const sim)
  {
    if (!sourceUnit || !sim || !sim->mRngState) {
      return {};
    }

    const auto* const blueprint = reinterpret_cast<const RUnitBlueprint*>(sourceUnit->BluePrint);
    if (!blueprint) {
      return {};
    }

    auto& rng = *sim->mRngState;
    const std::uint32_t minRadius = blueprint->Intel.JamRadius.min;
    const std::uint32_t maxRadius = blueprint->Intel.JamRadius.max;
    const std::uint32_t range = maxRadius > minRadius ? (maxRadius - minRadius) : 0u;
    const std::uint32_t radiusWord = rng.twister.NextUInt32();
    const std::uint32_t radiusStep = static_cast<std::uint32_t>((static_cast<std::uint64_t>(range) * radiusWord) >> 32u);
    const float radius = static_cast<float>(minRadius + radiusStep);

    Wm3::Vec3f direction{rng.FRandGaussian(), 0.0f, rng.FRandGaussian()};
    Wm3::Vec3f::Normalize(direction);

    const float randomScale = CMersenneTwister::ToUnitFloat(rng.twister.NextUInt32()) * radius;
    return {direction.x * randomScale, direction.y * randomScale, direction.z * randomScale};
  }

  [[nodiscard]] gpg::RRef MakeReconBlipRef(ReconBlip* const object) noexcept
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = object ? ReconBlip::StaticGetClass() : nullptr;
    return ref;
  }
} // namespace

gpg::RType* SPerArmyReconInfo::sType = nullptr;
gpg::RType* ReconBlip::sType = nullptr;

gpg::RType* ReconBlip::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(ReconBlip));
  }
  return sType;
}

/**
 * Address: 0x005BED70 (FUN_005BED70, Moho::ReconBlip::ReconBlip)
 *
 * Sim *
 *
 * IDA signature:
 * Moho::ReconBlip *__stdcall Moho::ReconBlip::ReconBlip(Moho::ReconBlip *this, Moho::Sim *sim);
 *
 * What it does:
 * Constructs serializer-load baseline state for `ReconBlip`.
 */
ReconBlip::ReconBlip(Sim* const sim) :
    Entity(
      nullptr,
      sim,
      static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid)),
      kUnitCollisionBucketFlags
    ),
    mCreator{},
    mDeleteWhenStale(0u),
    mPad279{0, 0, 0},
    mJamOffset{},
    mUnitConstDat{},
    mUnitVarDat{},
    mReconDat{}
{
}

/**
 * Address: 0x005C8DE0 (FUN_005C8DE0, Moho::SPerArmyReconInfo::MemberDeserialize)
 */
void SPerArmyReconInfo::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  archive->ReadUInt(&mReconFlags);
  archive->ReadBool(reinterpret_cast<bool*>(&mNeedsFlush));
  if (mNeedsFlush == 0u) {
    return;
  }

  const gpg::RRef ownerRef{};
  mStiMesh = ReadPointerUnowned<RMeshBlueprint>(archive, ownerRef, ResolveRMeshBlueprintType(), "RMeshBlueprint");
  ReadPointerShared<RScmResource>(mMesh, archive, ownerRef, ResolveRScmResourceType(), "RScmResource");
  ReadPointerShared<CAniPose>(mPriorPose, archive, ownerRef, ResolveCAniPoseType(), "CAniPose");
  ReadPointerShared<CAniPose>(mPose, archive, ownerRef, ResolveCAniPoseType(), "CAniPose");
  archive->ReadFloat(&mHealth);
  archive->ReadFloat(&mHealth);
  archive->ReadFloat(&mFractionComplete);
  archive->ReadBool(reinterpret_cast<bool*>(&mMaybeDead));
}

/**
 * Address: 0x005C8ED0 (FUN_005C8ED0, Moho::SPerArmyReconInfo::MemberSerialize)
 */
void SPerArmyReconInfo::MemberSerialize(gpg::WriteArchive* const archive, const int version)
{
  if (version < 1) {
    throw gpg::SerializationError("unsupported version.");
  }

  archive->WriteUInt(mReconFlags);
  archive->WriteBool(mNeedsFlush != 0u);
  if (mNeedsFlush == 0u) {
    return;
  }

  const gpg::RRef ownerRef{};
  WritePointerWithType(archive, mStiMesh, ResolveRMeshBlueprintType(), gpg::TrackedPointerState::Unowned, ownerRef);
  WritePointerWithType(archive, mMesh.px, ResolveRScmResourceType(), gpg::TrackedPointerState::Shared, ownerRef);
  WritePointerWithType(archive, mPriorPose.px, ResolveCAniPoseType(), gpg::TrackedPointerState::Shared, ownerRef);
  WritePointerWithType(archive, mPose.px, ResolveCAniPoseType(), gpg::TrackedPointerState::Shared, ownerRef);
  archive->WriteFloat(mHealth);
  archive->WriteFloat(mHealth);
  archive->WriteFloat(mFractionComplete);
  archive->WriteBool(mMaybeDead != 0u);
}

/**
 * Address: 0x005BE6E0 (FUN_005BE6E0)
 *
 * Unit *,Sim *,bool
 *
 * IDA signature:
 * Moho::ReconBlip *__userpurge Moho::ReconBlip::ReconBlip@<eax>(
 *   Moho::Unit *unit@<ebx>, Moho::ReconBlip *this, Moho::Sim *sim, char fake);
 *
 * What it does:
 * Constructs a recon blip from `unit`, allocates a 0x3xx-family entity id,
 * initializes per-army recon state storage, and performs an initial refresh.
 */
ReconBlip::ReconBlip(Unit* const sourceUnit, Sim* const sim, const bool fake) :
    Entity(
      sourceUnit ? reinterpret_cast<REntityBlueprint*>(sourceUnit->BluePrint) : nullptr,
      sim,
      ReserveReconBlipId(sim, sourceUnit),
      kUnitCollisionBucketFlags
    ),
    mCreator{},
    mDeleteWhenStale(static_cast<std::uint8_t>((sourceUnit && sourceUnit->IsMobile()) ? 1u : 0u)),
    mPad279{0, 0, 0},
    mJamOffset{},
    mUnitConstDat{},
    mUnitVarDat{},
    mReconDat{}
{
  mCreator.ResetFromObject(sourceUnit);
  mQueueRelinkBlocked = 1u;

  if (fake) {
    mJamOffset = ComputeJamOffset(sourceUnit, sim);
  } else {
    mJamOffset = {};
    if (sourceUnit) {
      mMeshRef = sourceUnit->mMeshRef;
      mMeshTypeClassId = sourceUnit->mMeshTypeClassId;
    }
  }

  if (sourceUnit) {
    BluePrint = const_cast<REntityBlueprint*>(reinterpret_cast<const REntityBlueprint*>(sourceUnit->GetBlueprint()));
    mCurrentLayer = sourceUnit->mCurrentLayer;
  }
  mUnitConstDat.mFake = static_cast<std::uint8_t>(fake ? 1u : 0u);

  const std::size_t armyCount = (sim && sim->mArmiesList.begin())
    ? static_cast<std::size_t>(sim->mArmiesList.end() - sim->mArmiesList.begin())
    : 0u;
  mReconDat.resize(armyCount, SPerArmyReconInfo{});
  Refresh();
}

/**
 * Address: 0x005BFBE0 (FUN_005BFBE0, Moho::ReconBlip::MemberConstruct)
 *
 * gpg::ReadArchive &,int,gpg::RRef const &,gpg::SerConstructResult &
 *
 * What it does:
 * Reads serializer construct args (`Sim*`), allocates one `ReconBlip`, and
 * returns it as an unowned construct result.
 */
void ReconBlip::MemberConstruct(
  gpg::ReadArchive& archive, const int, const gpg::RRef& ownerRef, gpg::SerConstructResult& result
)
{
  Sim* const sim = ReadPointerUnowned<Sim>(&archive, ownerRef, ResolveSimType(), "Sim");
  ReconBlip* const object = new (std::nothrow) ReconBlip(sim);
  result.SetUnowned(MakeReconBlipRef(object), 0u);
}

/**
 * Address: 0x005BDE90 (FUN_005BDE90)
 */
ReconBlip* ReconBlip::IsReconBlip()
{
  return this;
}

/**
 * Address: 0x005BEE80 (FUN_005BEE80)
 */
const RUnitBlueprint* ReconBlip::GetBlueprint() const
{
  return reinterpret_cast<const RUnitBlueprint*>(BluePrint);
}

/**
 * Address: 0x005BF810 (FUN_005BF810)
 *
 * What it does:
 * Refreshes cached transform/visual words from the linked source unit.
 */
void ReconBlip::Refresh()
{
  Unit* const sourceUnit = GetSourceUnit();
  if (!sourceUnit || sourceUnit->DestroyQueued()) {
    return;
  }

  EntityTransformPayload pending = ReadEntityTransformPayload(sourceUnit->PendingOrientation, sourceUnit->PendingPosition);
  pending.posX += mJamOffset.x;
  pending.posY += mJamOffset.y;
  pending.posZ += mJamOffset.z;
  WriteEntityTransformPayload(PendingOrientation, PendingPosition, pending);
  mPendingVelocityScale = sourceUnit->mPendingVelocityScale;

  if (SimulationRef && mCoordNode.ListIsSingleton()) {
    mCoordNode.ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  const EntityTransformPayload sourceTransform = ReadEntityTransformPayload(sourceUnit->GetTransform());
  Orientation = {sourceTransform.quatW, sourceTransform.quatX, sourceTransform.quatY, sourceTransform.quatZ};
  Position = {sourceTransform.posX + mJamOffset.x, sourceTransform.posY + mJamOffset.y, sourceTransform.posZ + mJamOffset.z};
  mVelocityScale = sourceUnit->mVelocityScale;
  SetCurrentLayer(sourceUnit->mCurrentLayer);

  mUnitVarDat.mHasLinkedSource = sourceUnit->mAttachInfo.HasAttachTarget() ? 1u : 0u;

  const UnitAttributes& sourceAttributes = sourceUnit->GetAttributes();
  mUnitVarDat.mBlueprintState0 = sourceAttributes.GetReconBlipBlueprintState0();
  mUnitVarDat.mBlueprintState1 = sourceAttributes.GetReconBlipBlueprintState1();
  BeingBuilt = sourceUnit->IsBeingBuilt() ? 1u : 0u;
}

/**
 * Address: 0x005BF6F0 (FUN_005BF6F0)
 *
 * What it does:
 * Destroys this blip once no army still tracks it and source retention rules
 * are no longer satisfied.
 */
void ReconBlip::DestroyIfUnused()
{
  Unit* const sourceUnit = GetSourceUnit();
  if (sourceUnit && !sourceUnit->DestroyQueued() && !IsFake()) {
    return;
  }

  for (const SPerArmyReconInfo& perArmy : mReconDat) {
    if (perArmy.mNeedsFlush != 0u) {
      return;
    }
  }

  if (sourceUnit) {
    for (ReconBlip** it = sourceUnit->mReconBlips.begin(); it != sourceUnit->mReconBlips.end();) {
      if (*it == this) {
        it = sourceUnit->mReconBlips.erase(it);
      } else {
        ++it;
      }
    }
  }

  Destroy();
}

Unit* ReconBlip::GetSourceUnit() const noexcept
{
  return mCreator.GetObjectPtr();
}

bool ReconBlip::IsFake() const noexcept
{
  return mUnitConstDat.mFake != 0u;
}

SPerArmyReconInfo* ReconBlip::GetPerArmyReconInfo(const std::int32_t armyIndex) noexcept
{
  if (armyIndex < 0 || mReconDat.begin() == nullptr || mReconDat.end() == nullptr) {
    return nullptr;
  }

  const std::ptrdiff_t count = mReconDat.end() - mReconDat.begin();
  if (armyIndex >= count) {
    return nullptr;
  }

  return mReconDat.begin() + armyIndex;
}

const SPerArmyReconInfo* ReconBlip::GetPerArmyReconInfo(const std::int32_t armyIndex) const noexcept
{
  if (armyIndex < 0 || mReconDat.begin() == nullptr || mReconDat.end() == nullptr) {
    return nullptr;
  }

  const std::ptrdiff_t count = mReconDat.end() - mReconDat.begin();
  if (armyIndex >= count) {
    return nullptr;
  }

  return mReconDat.begin() + armyIndex;
}

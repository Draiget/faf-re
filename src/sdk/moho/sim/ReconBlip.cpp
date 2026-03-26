#include "moho/sim/ReconBlip.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  constexpr std::uint32_t kUnitCollisionBucketFlags = 0x100u;
  constexpr std::uint32_t kReconEntityFamilyPrefix = 0x300u;

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
} // namespace

gpg::RType* ReconBlip::sType = nullptr;

gpg::RType* ReconBlip::StaticGetClass()
{
  if (!sType) {
    sType = gpg::LookupRType(typeid(ReconBlip));
  }
  return sType;
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

#include "moho/ai/CAiTransportImpl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>

#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniSkel.h"
#include "moho/containers/SCoordsVec2.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/SEntAttachInfo.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CMersenneTwister.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"

using namespace moho;

bool STransportPickUpInfo::HasUnit(const Unit* const unit) const noexcept
{
  return mUnits.ContainsUnit(unit);
}

void STransportPickUpInfo::RemoveUnit(Unit* const unit) noexcept
{
  (void)mUnits.RemoveUnit(unit);
  if (mUnits.Empty()) {
    mHasSpace = 0;
  }
}

namespace
{
  [[nodiscard]] float DistSq(const Wm3::Vec3f& lhs, const Wm3::Vec3f& rhs) noexcept
  {
    const float dx = lhs.x - rhs.x;
    const float dy = lhs.y - rhs.y;
    const float dz = lhs.z - rhs.z;
    return (dx * dx) + (dy * dy) + (dz * dz);
  }

  [[nodiscard]] Wm3::Vec3f ForwardFromOrientation(const Wm3::Quatf& orient) noexcept
  {
    return Wm3::Vec3f(
      ((orient.x * orient.z) + (orient.w * orient.y)) * 2.0f,
      ((orient.w * orient.z) - (orient.x * orient.y)) * 2.0f,
      1.0f - (((orient.z * orient.z) + (orient.y * orient.y)) * 2.0f)
    );
  }

  [[nodiscard]] Wm3::Vec3f NormalizeXZ(Wm3::Vec3f vec) noexcept
  {
    vec.y = 0.0f;
    const float lenSq = (vec.x * vec.x) + (vec.z * vec.z);
    if (lenSq <= 1.0e-6f) {
      return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    }
    const float invLen = 1.0f / std::sqrt(lenSq);
    vec.x *= invLen;
    vec.z *= invLen;
    return vec;
  }

  [[nodiscard]] Wm3::Quatf OrientationFromForward(const Wm3::Vec3f& forward) noexcept
  {
    const float lenSq = (forward.x * forward.x) + (forward.y * forward.y) + (forward.z * forward.z);
    if (lenSq <= 1.0e-6f) {
      return Wm3::Quatf(0.0f, 0.0f, 0.0f, 0.0f);
    }

    const float yaw = std::atan2(forward.x, forward.z);
    const float halfYaw = yaw * 0.5f;
    return Wm3::Quatf(std::cos(halfYaw), 0.0f, std::sin(halfYaw), 0.0f);
  }

  [[nodiscard]] SOCellPos InvalidCellPos() noexcept
  {
    SOCellPos out{};
    out.x = static_cast<std::int16_t>(0x8000);
    out.z = static_cast<std::int16_t>(0x8000);
    return out;
  }

  [[nodiscard]] SOCellPos CellPosFromWorldForUnit(const Wm3::Vec3f& worldPos, const Unit* const unit) noexcept
  {
    if (!unit) {
      return InvalidCellPos();
    }

    const SFootprint& footprint = unit->GetFootprint();
    const int x = static_cast<int>(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f));
    const int z = static_cast<int>(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f));

    SOCellPos out{};
    out.x = static_cast<std::int16_t>(x);
    out.z = static_cast<std::int16_t>(z);
    return out;
  }

  [[nodiscard]] const CAniSkel* ResolveUnitSkeleton(const Unit* const unit, boost::shared_ptr<const CAniSkel>& holdSkel)
  {
    holdSkel = {};
    if (!unit || !unit->AniActor) {
      return nullptr;
    }

    holdSkel = unit->AniActor->GetSkeleton();
    return holdSkel.get();
  }

  [[nodiscard]] const SAniSkelBone* ResolveUnitBoneByIndex(const Unit* const unit, const unsigned int boneIndex)
  {
    boost::shared_ptr<const CAniSkel> holdSkel{};
    const CAniSkel* const skeleton = ResolveUnitSkeleton(unit, holdSkel);
    if (!skeleton) {
      return nullptr;
    }

    return skeleton->GetBone(boneIndex);
  }

  /**
   * Address: 0x005E8A30 (sub_5E8A30)
   *
   * What it does:
   * Broadcasts one transport event to intrusive listeners while preserving
   * safe iteration semantics when listeners mutate registration.
   */
  void BroadcastTransportEvent(IAiTransport& transport, const EAiTransportEvent event)
  {
    Broadcaster* const head = static_cast<Broadcaster*>(&transport);
    if (!head || head->ListIsSingleton()) {
      return;
    }

    Broadcaster pending{};
    head->move_nodes_to(pending);

    while (auto* pendingNode = pending.pop_front()) {
      auto* const node = static_cast<Broadcaster*>(pendingNode);
      head->push_back(node);
      if (auto* const listener = IAiTransportEventListener::FromListenerLink(node)) {
        listener->OnTransportEvent(event);
      }
    }
  }

  /**
   * Address: 0x005EBD60 (sub_5EBD60)
   * Address: 0x005ED7D0 (func_LuaCallObjOObj_0 helper chain)
   *
   * What it does:
   * Invokes a transport script callback (`OnTransportAttach` / `OnTransportDetach`)
   * with bone-name string and optional payload unit Lua object.
   */
  void InvokeTransportBoneScriptCallback(
    Unit* const transportUnit,
    const char* const callbackName,
    const SAniSkelBone* const bone,
    Unit* const payloadUnit
  )
  {
    if (!transportUnit || !callbackName || !bone || !bone->mBoneName) {
      return;
    }

    const char* const boneName = bone->mBoneName;
    LuaPlus::LuaObject* const payloadObj = payloadUnit ? &payloadUnit->mLuaObj : nullptr;
    transportUnit->LuaPCall(callbackName, &boneName, payloadObj);
  }

} // namespace

gpg::RType* CAiTransportImpl::sType = nullptr;

/**
 * Address: 0x005E60F0 (FUN_005E60F0)
 */
bool CAiTransportImpl::TransportIsAirStagingPlatform() const
{
  return mStagingPlatform != 0;
}

/**
 * Address: 0x005E6100 (FUN_005E6100)
 */
bool CAiTransportImpl::TransportIsTeleporter() const
{
  return mTeleportation != 0;
}

/**
 * Address: 0x005E6110 (FUN_005E6110)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetLoadedUnits(const bool includeFutureLoad) const
{
  EntitySetTemplate<Unit> out{};
  if (!mUnit) {
    return out;
  }

  const msvc8::vector<Entity*>& attached = mUnit->GetAttachedEntities();
  for (Entity* const* it = attached.begin(); it != attached.end(); ++it) {
    Unit* const attachedUnit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!attachedUnit) {
      continue;
    }

    if (attachedUnit->IsInCategory("UPGRADE")) {
      continue;
    }
    if (attachedUnit->IsUnitState(UNITSTATE_Refueling)) {
      continue;
    }
    if (includeFutureLoad && TransportIsStoredUnit(attachedUnit)) {
      continue;
    }

    (void)out.Add(static_cast<Entity*>(attachedUnit));
  }

  return out;
}

/**
 * Address: 0x005E6260 (FUN_005E6260)
 */
void CAiTransportImpl::TransportAddPickupUnits(const EntitySetTemplate<Unit>& units, const SCoordsVec2 fallbackPos)
{
  for (Entity* const* it = units.begin(); it != units.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (unit) {
      TransportRemovePickupUnit(unit, false);
    }
  }

  if (!mUnit) {
    return;
  }

  Wm3::Vec3f pickupFacing{};
  if (mAttachpoints == 1 && units.Size() == 1u) {
    Unit* const onlyUnit = SEntitySetTemplateUnit::UnitFromEntry(*units.begin());
    if (onlyUnit) {
      pickupFacing = ForwardFromOrientation(onlyUnit->GetTransform().orient_);
    }
  } else {
    const Wm3::Vec3f& transportPos = mUnit->GetPosition();
    pickupFacing = NormalizeXZ(Wm3::Vec3f(fallbackPos.x - transportPos.x, 0.0f, fallbackPos.z - transportPos.z));
  }

  mPickupFacing = pickupFacing;
  mPickupInfo.mFallbackPos = fallbackPos;
  mPickupInfo.mPos = Wm3::Vec3f(fallbackPos.x, mUnit->GetPosition().y, fallbackPos.z);
  mPickupInfo.mOri = OrientationFromForward(pickupFacing);
  mPickupInfo.mUnits.AddUnits(units);
  mPickupInfo.mHasSpace = 0;
}

/**
 * Address: 0x005E64A0 (FUN_005E64A0)
 */
void CAiTransportImpl::TransportRemovePickupUnit(Unit* const unit, const bool clearReservation)
{
  mPickupInfo.RemoveUnit(unit);
  if (clearReservation) {
    TransportRemoveUnitReservation(unit);
  }
}

/**
 * Address: 0x005E64D0 (FUN_005E64D0)
 */
void CAiTransportImpl::TransportRemoveUnitReservation(Unit* const unit)
{
  for (SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end();) {
    Unit* const reserved = it->reservedUnit.GetObjectPtr();
    if (!reserved || reserved == unit) {
      it = mReservedBones.erase(it);
    } else {
      ++it;
    }
  }
}

/**
 * Address: 0x005E6530 (FUN_005E6530)
 */
void CAiTransportImpl::TransportUnreserveUnattachedSpots()
{
  for (SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end();) {
    Unit* const reserved = it->reservedUnit.GetObjectPtr();
    if (!reserved) {
      it = mReservedBones.erase(it);
      continue;
    }

    Unit* const transportedBy = reserved->TransportedByRef.ResolveObjectPtr<Unit>();
    if (transportedBy != mUnit) {
      it = mReservedBones.erase(it);
      continue;
    }

    ++it;
  }
}

/**
 * Address: 0x005E65A0 (FUN_005E65A0)
 */
unsigned int CAiTransportImpl::TransportGetPickupUnitCount() const
{
  return mPickupInfo.mUnits.CountLiveUnits();
}

/**
 * Address: 0x005E65F0 (FUN_005E65F0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetPickupUnits()
{
  EntitySetTemplate<Unit> out{};
  mPickupInfo.mUnits.CopyTo(out);

  if (mWaitingFormation) {
    mUnitSet30.CopyLiveUnitsTo(out);
  }

  return out;
}

/**
 * Address: 0x005E6690 (FUN_005E6690)
 */
bool CAiTransportImpl::TransportIsUnitAssignedForPickup(Unit* const unit) const
{
  return mPickupInfo.HasUnit(unit);
}

/**
 * Address: 0x005E66B0 (FUN_005E66B0)
 */
SOCellPos CAiTransportImpl::TransportGetPickupUnitPos(Unit* const unit) const
{
  const SAiReservedTransportBone* const reservedBone = GetReservedBone(unit);
  if (!reservedBone || !mUnit) {
    return InvalidCellPos();
  }

  Wm3::Vec3f worldPos = mPickupInfo.mPos;
  if (mAttachpoints != 1) {
    const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reservedBone->transportBoneIndex));
    const Wm3::Vec3f rotated = mPickupInfo.mOri.Rotate(localTransform.pos_);
    worldPos.x += rotated.x * 2.0f;
    worldPos.z += rotated.z * 2.0f;
  }

  return CellPosFromWorldForUnit(worldPos, unit);
}

/**
 * Address: 0x005E6870 (FUN_005E6870)
 */
bool CAiTransportImpl::TransportCanCarryUnit(Unit* const unit) const
{
  if (!unit || !unit->IsMobile()) {
    return false;
  }

  if (mStagingPlatform != 0) {
    if (!unit->mIsAir) {
      return false;
    }
  } else if (unit->mIsAir) {
    return false;
  }

  if (unit->IsInCategory("COMMAND") && (!mUnit || !mUnit->IsInCategory("CANTRANSPORTCOMMANDER"))) {
    return false;
  }

  if (!mUnit) {
    return false;
  }

  const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
  const RUnitBlueprint* const transportBlueprint = mUnit->GetBlueprint();
  if (!unitBlueprint || !transportBlueprint) {
    return false;
  }

  const int transportClass = unitBlueprint->Transport.TransportClass;
  if (transportBlueprint->Transport.ClassGenericUpTo >= transportClass && !mGenericAttachPoints.empty()) {
    return true;
  }

  const int attachCount = static_cast<int>(
    (transportBlueprint->Transport.ClassGenericUpTo != 0) ? mGenericAttachPoints.size() : mClass1AttachPoints.size()
  );

  switch (transportClass) {
    case 1:
      return attachCount > 0;
    case 2:
      return transportBlueprint->Transport.Class2AttachSize != 0 && attachCount >= transportBlueprint->Transport.Class2AttachSize;
    case 3:
      return transportBlueprint->Transport.Class3AttachSize != 0 && attachCount >= transportBlueprint->Transport.Class3AttachSize;
    case 4:
      return transportBlueprint->Transport.Class4AttachSize != 0 && attachCount > transportBlueprint->Transport.Class4AttachSize;
    default:
      return false;
  }
}

/**
 * Address: 0x005E5F10 (FUN_005E5F10)
 */
void CAiTransportImpl::TransportRemoveFromWaitingList(Unit* const unit)
{
  (void)mUnitSet30.RemoveUnit(unit);
}

/**
 * Address: 0x005E5EF0 (FUN_005E5EF0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetUnitsWaitingForPickup() const
{
  EntitySetTemplate<Unit> out{};
  mUnitSet30.CopyTo(out);
  return out;
}

/**
 * Address: 0x005E5F30 (FUN_005E5F30)
 */
IFormationInstance* CAiTransportImpl::TransportGetWaitingFormation() const
{
  return mWaitingFormation;
}

/**
 * Address: 0x005E5F40 (FUN_005E5F40)
 */
void CAiTransportImpl::TransportGenerateWaitingFormationForUnits(const EntitySetTemplate<Unit>& units)
{
  mUnitSet30.AddUnits(units);
  if (!mUnit || !mUnit->SimulationRef || !mUnit->SimulationRef->mFormationDB) {
    return;
  }

  const RUnitBlueprint* const blueprint = mUnit->GetBlueprint();
  const char* const formationName = blueprint ? blueprint->AI.GuardFormationName.c_str() : nullptr;
  if (!formationName) {
    return;
  }

  SFormationUnitWeakRefSet weakSet{};
  for (Entity* const* it = mUnitSet30.mVec.begin(); it != mUnitSet30.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit) {
      continue;
    }

    const SFormationUnitWeakRef ref = SFormationUnitWeakRef::FromUnit(unit);
    weakSet.push_back(ref);
  }

  SCoordsVec2 center{};
  const Wm3::Vec3f& unitPos = mUnit->GetPosition();
  center.x = unitPos.x;
  center.z = unitPos.z;

  Wm3::Quatf orientation(0.0f, 0.0f, 0.0f, 0.0f);
  if (mUnit->IsMobile()) {
    orientation = mUnit->GetTransform().orient_;
  }

  CAiFormationDBImpl* const formationDB = mUnit->SimulationRef->mFormationDB;
  auto* const formation = formationDB->NewFormation(
    &weakSet,
    formationName,
    &center,
    orientation.x,
    orientation.y,
    orientation.z,
    orientation.w,
    2
  );
  mWaitingFormation = formation;
}

/**
 * Address: 0x005E60A0 (FUN_005E60A0)
 */
void CAiTransportImpl::TransportClearWaitingFormation()
{
  if (mWaitingFormation) {
    mWaitingFormation->operator_delete(1);
    mWaitingFormation = nullptr;
  }

  mUnitSet30.Clear();
}

/**
 * Address: 0x005E5120 (FUN_005E5120)
 */
const SAiReservedTransportBone* CAiTransportImpl::GetReservedBone(Unit* const unit) const
{
  for (const SAiReservedTransportBone* it = mReservedBones.begin(); it != mReservedBones.end(); ++it) {
    if (it->reservedUnit.GetObjectPtr() == unit) {
      return it;
    }
  }
  return nullptr;
}

/**
 * Address: 0x005E50A0 (FUN_005E50A0)
 */
unsigned int CAiTransportImpl::GetBestAttachPoint(Unit* const unit) const
{
  if (!unit) {
    return 0u;
  }

  boost::shared_ptr<const CAniSkel> holdSkel{};
  const CAniSkel* const skeleton = ResolveUnitSkeleton(mUnit, holdSkel);
  const int attachPointIndex = skeleton ? skeleton->FindBoneIndex("AttachPoint") : -1;
  if (attachPointIndex >= 0) {
    return static_cast<unsigned int>(attachPointIndex);
  }

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  if (blueprint && blueprint->Transport.AirClass != 0) {
    return 0u;
  }
  return static_cast<unsigned int>(attachPointIndex);
}

/**
 * Address: 0x005E6AC0 (FUN_005E6AC0)
 */
bool CAiTransportImpl::TransportValidateType(const RUnitBlueprint* const unitBlueprint) const
{
  if (!unitBlueprint || !mUnit) {
    return false;
  }

  const bool isAirClass = unitBlueprint->Transport.AirClass != 0;
  if (mStagingPlatform != 0 && !isAirClass) {
    return false;
  }
  if (mStagingPlatform != 0 || !isAirClass) {
    return true;
  }

  const Sim* const sim = mUnit->SimulationRef;
  if (!sim || !sim->mRules) {
    return false;
  }

  const CategoryWordRangeView* const category = sim->mRules->GetEntityCategory("TRANSPORTATION");
  if (!category) {
    return false;
  }

  const std::uint32_t ordinal = static_cast<std::uint32_t>(unitBlueprint->mCategoryBitIndex);
  const auto it = category->FindWord(ordinal >> 5u);
  if (it == category->cend()) {
    return false;
  }

  return (((*it) >> (ordinal & 0x1Fu)) & 1u) != 0u;
}

/**
 * Address: 0x005E6B30 (FUN_005E6B30)
 */
void CAiTransportImpl::TransportFindAttachList(
  const int unitClass,
  msvc8::vector<SAttachPoint>& attachPoints,
  msvc8::vector<SAttachPoint>& outAttachPoints,
  int& outAttachSize
)
{
  const RUnitBlueprint* const blueprint = (mUnit != nullptr) ? mUnit->GetBlueprint() : nullptr;
  if (!blueprint) {
    attachPoints.clear();
    outAttachPoints.clear();
    outAttachSize = 0;
    return;
  }

  if (unitClass > blueprint->Transport.ClassGenericUpTo) {
    switch (unitClass) {
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_1):
        attachPoints = mClass1AttachPoints;
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_2):
        attachPoints = mClass2AttachPoints;
        outAttachSize = blueprint->Transport.Class2AttachSize;
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_3):
        attachPoints = mClass3AttachPoints;
        outAttachSize = blueprint->Transport.Class3AttachSize;
        break;
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_4):
        attachPoints = mClass4AttachPoints;
        outAttachSize = blueprint->Transport.Class4AttachSize;
        [[fallthrough]];
      case static_cast<int>(ETransportClass::TRANSPORTCLASS_SPECIAL):
        attachPoints = mClassSAttachPoints;
        outAttachSize = blueprint->Transport.ClassSAttachSize;
        break;
      default:
        break;
    }
  } else {
    attachPoints = mGenericAttachPoints;
  }

  if (outAttachSize == 0) {
    attachPoints = !mClass1AttachPoints.empty() ? mClass1AttachPoints : mGenericAttachPoints;
  }

  outAttachPoints = attachPoints;
}

/**
 * Address: 0x005E4D40 (FUN_005E4D40)
 */
msvc8::vector<int> CAiTransportImpl::GetClosestAttachPointsTo(
  msvc8::vector<SAttachPoint> attachPoints,
  const int hookIndex,
  int attachSize
)
{
  msvc8::vector<int> result{};
  if (attachSize <= 0) {
    return result;
  }

  if (attachSize == 1) {
    result.push_back(hookIndex);
    return result;
  }

  if (!mUnit || attachPoints.size() < static_cast<std::size_t>(attachSize)) {
    return result;
  }

  const VTransform hookTransform = mUnit->GetBoneLocalTransform(hookIndex);
  for (SAttachPoint* it = attachPoints.begin(); it != attachPoints.end(); ++it) {
    const VTransform attachTransform = mUnit->GetBoneLocalTransform(static_cast<int>(it->index));
    it->distSq = DistSq(attachTransform.pos_, hookTransform.pos_);
  }

  std::sort(attachPoints.begin(), attachPoints.end(), [](const SAttachPoint& lhs, const SAttachPoint& rhs) {
    return lhs.distSq < rhs.distSq;
  });

  for (const SAttachPoint* it = attachPoints.begin();
       it != attachPoints.end() && attachSize > 0;
       ++it, --attachSize) {
    result.push_back(static_cast<int>(it->index));
  }

  return result;
}

/**
 * Address: 0x005E4F00 (FUN_005E4F00)
 */
bool CAiTransportImpl::IsBoneReserved(msvc8::vector<int> boneIndices)
{
  for (const SAiReservedTransportBone* reserved = mReservedBones.begin(); reserved != mReservedBones.end(); ++reserved) {
    for (const int* candidate = boneIndices.begin(); candidate != boneIndices.end(); ++candidate) {
      for (const int* reservedBone = reserved->reservedBones.begin(); reservedBone != reserved->reservedBones.end(); ++reservedBone) {
        if (*candidate == *reservedBone) {
          return true;
        }
      }
    }
  }

  return false;
}

/**
 * Address: 0x005E4FA0 (FUN_005E4FA0)
 */
void CAiTransportImpl::ReserveBone(
  const unsigned int bestAttachBoneIndex,
  Unit* const unit,
  const unsigned int transportBoneIndex,
  msvc8::vector<int> boneIndices
)
{
  if (boneIndices.empty()) {
    return;
  }

  SAiReservedTransportBone reservation{};
  reservation.transportBoneIndex = transportBoneIndex;
  reservation.attachBoneIndex = bestAttachBoneIndex;
  reservation.reservedUnit.ResetFromObject(unit);
  reservation.reservedBones = boneIndices;
  mReservedBones.push_back(reservation);
}

/**
 * Address: 0x005E6C70 (FUN_005E6C70)
 */
bool CAiTransportImpl::TransportHasSpaceFor(const RUnitBlueprint* const unitBlueprint)
{
  if (!TransportValidateType(unitBlueprint)) {
    return false;
  }

  msvc8::vector<SAttachPoint> attachVec{};
  msvc8::vector<SAttachPoint> hookVec{};
  int attachSize = 1;
  TransportFindAttachList(unitBlueprint->Transport.TransportClass, attachVec, hookVec, attachSize);
  if (attachVec.empty()) {
    return false;
  }

  attachSize = std::max(1, attachSize);
  for (const SAttachPoint* it = attachVec.begin(); it != attachVec.end(); ++it) {
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, static_cast<int>(it->index), attachSize);
    if (!candidate.empty() && !IsBoneReserved(candidate)) {
      return true;
    }
  }

  return false;
}

/**
 * Address: 0x005E6E30 (FUN_005E6E30)
 */
bool CAiTransportImpl::TransportAssignSlot(Unit* const unit, const int hookIndex)
{
  if (!unit || !TransportValidateType(unit->GetBlueprint())) {
    return false;
  }

  const unsigned int bestAttachBoneIndex = GetBestAttachPoint(unit);
  msvc8::vector<SAttachPoint> attachVec{};
  msvc8::vector<SAttachPoint> hookVec{};
  int attachSize = 1;
  TransportFindAttachList(unit->GetBlueprint()->Transport.TransportClass, attachVec, hookVec, attachSize);

  if (hookIndex >= 0) {
    const int normalizedAttachSize = std::max(1, attachSize);
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, hookIndex, normalizedAttachSize);
    if (candidate.empty() || IsBoneReserved(candidate)) {
      return false;
    }
    ReserveBone(bestAttachBoneIndex, unit, static_cast<unsigned int>(hookIndex), candidate);
    return true;
  }

  if (attachVec.empty()) {
    return false;
  }

  attachSize = std::max(1, attachSize);
  for (const SAttachPoint* it = attachVec.begin(); it != attachVec.end(); ++it) {
    msvc8::vector<int> candidate = GetClosestAttachPointsTo(hookVec, static_cast<int>(it->index), attachSize);
    if (candidate.empty() || IsBoneReserved(candidate)) {
      continue;
    }

    ReserveBone(bestAttachBoneIndex, unit, it->index, candidate);
    return true;
  }

  return false;
}

/**
 * Address: 0x005E5150 (FUN_005E5150)
 */
void CAiTransportImpl::AttachUnitToBone(
  Unit* const unit,
  const unsigned int transportBoneIndex,
  const unsigned int attachBoneIndex
)
{
  if (!unit) {
    return;
  }

  SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
  attachInfo.mParentBoneIndex = static_cast<std::int32_t>(transportBoneIndex);
  attachInfo.mChildBoneIndex = static_cast<std::int32_t>(attachBoneIndex);
  attachInfo.TargetWeakLink().ResetFromObject(static_cast<Entity*>(mUnit));

  (void)unit->AttachTo(attachInfo);
  TransportRemovePickupUnit(unit, false);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  const SAniSkelBone* const transportBone = ResolveUnitBoneByIndex(mUnit, transportBoneIndex);
  InvokeTransportBoneScriptCallback(mUnit, "OnTransportAttach", transportBone, unit);
  BroadcastTransportEvent(*this, AITRANSPORTEVENT_Load);
}

/**
 * Address: 0x005E7100 (FUN_005E7100)
 */
bool CAiTransportImpl::TransportAttachUnit(Unit* const unit)
{
  if (!unit) {
    return false;
  }

  if (mTeleportation != 0) {
    TransportRemovePickupUnit(unit, true);
    return true;
  }

  const SAiReservedTransportBone* const reservedBone = GetReservedBone(unit);
  if (!reservedBone) {
    return false;
  }

  AttachUnitToBone(unit, reservedBone->transportBoneIndex, reservedBone->attachBoneIndex);
  unit->TransportedByRef.ResetObjectPtr<Unit>(mUnit);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  return true;
}

/**
 * Address: 0x005E7170 (FUN_005E7170)
 */
bool CAiTransportImpl::TransportDetachUnit(Unit* const unit)
{
  if (!unit || !mUnit) {
    return false;
  }

  Entity* const expectedParent = static_cast<Entity*>(mUnit);
  Entity* const actualParent = unit->mAttachInfo.GetAttachTargetEntity();
  if (actualParent != expectedParent) {
    gpg::Logf("Transport attemping to detach unit that is not attached");

    const RUnitBlueprint* const unitBlueprint = unit->GetBlueprint();
    const RUnitBlueprint* const transportBlueprint = mUnit->GetBlueprint();
    const char* const unitName = unitBlueprint ? unitBlueprint->mBlueprintId.c_str() : "<unknown-unit>";
    const char* const transportName =
      transportBlueprint ? transportBlueprint->mBlueprintId.c_str() : "<unknown-transport>";
    gpg::Logf("Transport = %s, unit = %s", transportName, unitName);

    if (unit->IsDead()) {
      gpg::Logf("Attempted to detach a dead unit");
    }
  }

  if (mUnit->mCurrentLayer == LAYER_Air) {
    const Sim* const sim = mUnit->SimulationRef;
    if (!sim || !sim->mOGrid) {
      return false;
    }

    const SFootprint& footprint = unit->GetFootprint();
    const Wm3::Vec3f& worldPos = unit->GetPosition();
    const SCoordsVec2 worldPos2D{worldPos.x, worldPos.z};
    if (footprint.FitsAt(worldPos2D, *sim->mOGrid) == static_cast<EOccupancyCaps>(0u)) {
      return false;
    }
  }

  const int detachedBoneIndex = unit->mAttachInfo.mParentBoneIndex;
  (void)unit->DetachFrom(expectedParent, false);
  TransportRemovePickupUnit(unit, true);
  unit->TransportedByRef.ResetObjectPtr<Unit>(nullptr);

  const SAniSkelBone* detachedBone = nullptr;
  if (detachedBoneIndex >= 0) {
    detachedBone = ResolveUnitBoneByIndex(mUnit, static_cast<unsigned int>(detachedBoneIndex));
  }
  InvokeTransportBoneScriptCallback(mUnit, "OnTransportDetach", detachedBone, unit);
  BroadcastTransportEvent(*this, AITRANSPORTEVENT_Unload);

  if (unit->AiNavigator) {
    unit->AiNavigator->AbortMove();
  }

  return true;
}

/**
 * Address: 0x005E73E0 (FUN_005E73E0)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportDetachAllUnits(const bool clearReservations)
{
  EntitySetTemplate<Unit> detached{};
  EntitySetTemplate<Unit> storedToDestroy{};
  if (!mUnit) {
    return detached;
  }

  const bool requiresAirFitCheck = !clearReservations && (mUnit->mCurrentLayer == LAYER_Air);
  Sim* const sim = mUnit->SimulationRef;
  COGrid* const oGrid = sim ? sim->mOGrid : nullptr;

  const msvc8::vector<Entity*>& attachedCopy = mUnit->GetAttachedEntities();
  for (Entity* const* it = attachedCopy.begin(); it != attachedCopy.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit || unit->IsDead()) {
      continue;
    }

    if (requiresAirFitCheck) {
      if (!oGrid) {
        continue;
      }

      const Wm3::Vec3f& worldPos = unit->GetPosition();
      const SCoordsVec2 worldPos2D{worldPos.x, worldPos.z};
      const SFootprint& footprint = unit->GetFootprint();
      if (footprint.FitsAt(worldPos2D, *oGrid) == static_cast<EOccupancyCaps>(0u)) {
        continue;
      }
    }

    if (TransportIsStoredUnit(unit)) {
      (void)storedToDestroy.Add(static_cast<Entity*>(unit));
    } else {
      (void)detached.Add(static_cast<Entity*>(unit));
    }
  }

  CRandomStream* const random = sim ? sim->mRngState : nullptr;
  for (Entity* const* it = detached.mVec.begin(); it != detached.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit) {
      continue;
    }

    if (clearReservations) {
      const float roll = random ? CMersenneTwister::ToUnitFloat(random->twister.NextUInt32()) : 1.0f;
      if (roll < 0.99f) {
        if (unit->RunScriptUnitBool("CheckCanBeKilled", mUnit)) {
          unit->Kill(static_cast<Entity*>(mUnit), "Damage", 0.0f);
          continue;
        }

        if (unit->IsInCategory("COMMAND") && unit->RunScriptUnitBool("CheckCanTakeDamage", mUnit)) {
          unit->RunScriptUnitOnDamage(mUnit, 10000, false);
          continue;
        }
      }
    }

    (void)TransportDetachUnit(unit);
  }

  for (Entity* const* it = storedToDestroy.mVec.begin(); it != storedToDestroy.mVec.end(); ++it) {
    Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*it);
    if (!unit) {
      continue;
    }

    unit->RunScript("DestroyedOnTransport");
    unit->Destroy();
  }

  return detached;
}

/**
 * Address: 0x005E77B0 (FUN_005E77B0)
 */
void CAiTransportImpl::TransportAtPickupPosition()
{
  mPickupInfo.mHasSpace = 1;
}

/**
 * Address: 0x005E77C0 (FUN_005E77C0)
 */
bool CAiTransportImpl::TransportIsReadyForUnit(Unit* const unit) const
{
  return mPickupInfo.mHasSpace != 0 && mPickupInfo.HasUnit(unit);
}

/**
 * Address: 0x005E7930 (FUN_005E7930)
 */
int CAiTransportImpl::TransportGetAttachBone(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  return reserved ? static_cast<int>(reserved->transportBoneIndex) : -1;
}

/**
 * Address: 0x005E77F0 (FUN_005E77F0)
 */
SOCellPos CAiTransportImpl::TransportGetAttachPosition(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return InvalidCellPos();
  }

  const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  const Wm3::Vec3f rotated = mUnit->GetTransform().orient_.Rotate(localTransform.pos_);
  Wm3::Vec3f world = mUnit->GetPosition();
  world.x += rotated.x;
  world.z += rotated.z;
  return CellPosFromWorldForUnit(world, unit);
}

/**
 * Address: 0x005E7950 (FUN_005E7950)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetAttachBonePosition(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  const VTransform localTransform = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  const Wm3::Vec3f rotated = mUnit->GetTransform().orient_.Rotate(localTransform.pos_);
  const Wm3::Vec3f base = mUnit->GetPosition();
  return Wm3::Vec3f(base.x + rotated.x, base.y + rotated.y, base.z + rotated.z);
}

/**
 * Address: 0x005E7A60 (FUN_005E7A60)
 */
VTransform CAiTransportImpl::TransportGetAttachBoneTransform(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (reserved && mUnit) {
    return mUnit->GetBoneWorldTransform(static_cast<int>(reserved->transportBoneIndex));
  }
  return mUnit ? mUnit->GetTransform() : VTransform{};
}

/**
 * Address: 0x005E7AD0 (FUN_005E7AD0)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetAttachFacing(Unit* const unit) const
{
  const SAiReservedTransportBone* const reserved = GetReservedBone(unit);
  if (!reserved || !mUnit) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  const VTransform localBone = mUnit->GetBoneLocalTransform(static_cast<int>(reserved->transportBoneIndex));
  Wm3::Vec3f localForward = localBone.orient_.Rotate(Wm3::Vec3f(0.0f, 0.0f, 1.0f));
  localForward.y = 0.0f;
  const Wm3::Vec3f worldForward = mUnit->GetTransform().orient_.Rotate(localForward);
  return Wm3::Vec3f::NormalizeOrZero(worldForward);
}

/**
 * Address: 0x005E7BB0 (FUN_005E7BB0)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetPickupFacing() const
{
  return mPickupFacing;
}

/**
 * Address: 0x005E7BE0 (FUN_005E7BE0)
 */
void CAiTransportImpl::TransportAddToStorage(Unit* const unit)
{
  if (!unit || !mUnit) {
    return;
  }

  unit->RunScript("OnAddToStorage", mUnit);
  TransportClearReservation(unit);

  SEntAttachInfo attachInfo = SEntAttachInfo::MakeDetached();
  attachInfo.mParentBoneIndex = -1;
  attachInfo.mChildBoneIndex = -1;
  attachInfo.TargetWeakLink().ResetFromObject(static_cast<Entity*>(mUnit));
  (void)unit->AttachTo(attachInfo);
  unit->TransportedByRef.ResetObjectPtr<Unit>(mUnit);
  (void)mStoredUnits.AddUnit(unit);
}

/**
 * Address: 0x005E7CF0 (FUN_005E7CF0)
 */
void CAiTransportImpl::TransportRemoveFromStorage(Unit* const unit, VTransform& outTransform)
{
  if (!mUnit) {
    outTransform = VTransform{};
    return;
  }

  outTransform = mUnit->GetTransform();
  if (!unit) {
    return;
  }

  unit->RunScript("OnRemoveFromStorage", mUnit);
  unit->TransportedByRef.ResetObjectPtr<Unit>(nullptr);
  (void)unit->DetachFrom(static_cast<Entity*>(mUnit), false);
  (void)mStoredUnits.RemoveUnit(unit);

  const msvc8::vector<SAttachPoint>* launchPoints = &mLaunchAttachPoints;
  if (launchPoints->empty()) {
    launchPoints = &mGenericAttachPoints;
  }
  if (launchPoints->empty()) {
    return;
  }

  const int count = static_cast<int>(launchPoints->size());
  if (count <= 0) {
    return;
  }

  mLaunchAttachIndex = (mLaunchAttachIndex + 1) % count;
  const SAttachPoint& point = (*launchPoints)[static_cast<std::size_t>(mLaunchAttachIndex)];
  outTransform = mUnit->GetBoneWorldTransform(static_cast<int>(point.index));
}

/**
 * Address: 0x005E7E60 (FUN_005E7E60)
 */
EntitySetTemplate<Unit> CAiTransportImpl::TransportGetStoredUnits() const
{
  EntitySetTemplate<Unit> out{};
  mStoredUnits.CopyTo(out);
  return out;
}

/**
 * Address: 0x005E8050 (FUN_005E8050)
 */
bool CAiTransportImpl::TransportIsStoredUnit(Unit* const unit) const
{
  return mStoredUnits.ContainsUnit(unit);
}

/**
 * Address: 0x005E7E80 (FUN_005E7E80)
 */
bool CAiTransportImpl::TransportHasAvailableStorage() const
{
  if (!mUnit || !mUnit->GetBlueprint()) {
    return false;
  }

  const int reservedCount = static_cast<int>(mUnitSet80.Size());
  const int currentStoredCount = static_cast<int>(mStoredUnits.Size());
  return (currentStoredCount + reservedCount) < mUnit->GetBlueprint()->Transport.StorageSlots;
}

/**
 * Address: 0x005E7EC0 (FUN_005E7EC0)
 */
int CAiTransportImpl::TransportReserveStorage(
  Unit* const unit,
  Wm3::Vec3f& outPos,
  Wm3::Vec3f& outFacing,
  float& outDropDist
)
{
  const int previousOverflow = mGenericOverflow;
  if (!unit || !mUnit || mGenericAttachPoints.empty()) {
    outPos = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    outFacing = Wm3::Vec3f(0.0f, 0.0f, 0.0f);
    outDropDist = 0.0f;
    return previousOverflow;
  }

  (void)mUnitSet80.AddUnit(unit);
  const std::size_t index = static_cast<std::size_t>(mNextGeneric) % mGenericAttachPoints.size();
  const SAttachPoint& point = mGenericAttachPoints[index];
  const VTransform world = mUnit->GetBoneWorldTransform(static_cast<int>(point.index));
  outPos = world.pos_;
  outFacing = ForwardFromOrientation(world.orient_);
  outDropDist = world.pos_.y - mUnit->GetPosition().y;

  const int count = static_cast<int>(mGenericAttachPoints.size());
  if (count > 0) {
    mNextGeneric = (mNextGeneric + 1) % count;
    if (mNextGeneric == 0) {
      mGenericOverflow = (previousOverflow + 3) % 50;
    }
  }

  return previousOverflow;
}

/**
 * Address: 0x005E8020 (FUN_005E8020)
 */
void CAiTransportImpl::TransportClearReservation(Unit* const unit)
{
  (void)mUnitSet80.RemoveUnit(unit);
}

/**
 * Address: 0x005E8040 (FUN_005E8040)
 */
void CAiTransportImpl::TransportResetReservation()
{
  mNextGeneric = 0;
  mLaunchAttachIndex = 0;
  mGenericOverflow = 0;
}

/**
 * Address: 0x005E8080 (FUN_005E8080)
 */
void CAiTransportImpl::TranspotSetTeleportDest(Unit* const beaconUnit)
{
  if (beaconUnit && mUnit) {
    LuaPlus::LuaState* const state = mUnit->mLuaObj.GetActiveState();
    if (state) {
      const LuaPlus::LuaObject destination = moho::SCR_ToLua<Wm3::Vector3<float>>(state, beaconUnit->GetPosition());
      (void)mUnit->RunScript("OnSetTeleportDest", destination);
    }
  }

  mTeleportBeacon.ResetFromObject(beaconUnit);
}

/**
 * Address: 0x005E8120 (FUN_005E8120)
 */
Wm3::Vec3f CAiTransportImpl::TransportGetTeleportDest() const
{
  Unit* const beacon = mTeleportBeacon.GetObjectPtr();
  if (!beacon || beacon->IsDead() || beacon->DestroyQueued()) {
    return Wm3::Vec3f(0.0f, 0.0f, 0.0f);
  }

  return beacon->GetPosition();
}

/**
 * Address: 0x005E81C0 (FUN_005E81C0)
 */
Unit* CAiTransportImpl::TransportGetTeleportBeacon() const
{
  return mTeleportBeacon.GetObjectPtr();
}

/**
 * Address: 0x005E81D0 (FUN_005E81D0)
 */
bool CAiTransportImpl::TransportIsTeleportBeaconReady() const
{
  Unit* const beacon = mTeleportBeacon.GetObjectPtr();
  if (!beacon) {
    return false;
  }
  if (beacon->IsDead() || beacon->DestroyQueued()) {
    return false;
  }
  return beacon->IsNavigatorIdle();
}

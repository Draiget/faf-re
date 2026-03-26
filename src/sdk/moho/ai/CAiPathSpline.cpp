#include "moho/ai/CAiPathSpline.h"

#include <algorithm>
#include <cmath>

#include "moho/misc/WeakPtr.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{
  using CollisionLinkWeakUnit = WeakPtr<IUnit>;

  static_assert(sizeof(CollisionLinkWeakUnit) == sizeof(SCollisionLink), "SCollisionLink/WeakPtr<IUnit> layout mismatch");
  static_assert(
    offsetof(CollisionLinkWeakUnit, ownerLinkSlot) == offsetof(SCollisionLink, mUnitIntrusiveSlot),
    "SCollisionLink::mUnitIntrusiveSlot owner slot mismatch"
  );
  static_assert(
    offsetof(CollisionLinkWeakUnit, nextInOwner) == offsetof(SCollisionLink, mNextInUnitChain),
    "SCollisionLink::mNextInUnitChain next slot mismatch"
  );

  [[nodiscard]] CollisionLinkWeakUnit& AsCollisionWeakLink(SCollisionLink& link) noexcept
  {
    return *reinterpret_cast<CollisionLinkWeakUnit*>(&link);
  }

  [[nodiscard]] const CollisionLinkWeakUnit& AsCollisionWeakLink(const SCollisionLink& link) noexcept
  {
    return *reinterpret_cast<const CollisionLinkWeakUnit*>(&link);
  }
} // namespace

Unit* SCollisionLink::ResolveUnitFromIntrusiveSlot() const noexcept
{
  if (IUnit* const iunit = AsCollisionWeakLink(*this).GetObjectPtr()) {
    return iunit->IsUnit();
  }
  return nullptr;
}

void** SCollisionLink::GetIntrusiveSlotAddress() const noexcept
{
  return reinterpret_cast<void**>(AsCollisionWeakLink(*this).ownerLinkSlot);
}

bool SCollisionLink::HasLinkedUnit() const noexcept
{
  return AsCollisionWeakLink(*this).HasValue();
}

void SCollisionLink::AssignUnit(Unit* const unit) noexcept
{
  AsCollisionWeakLink(*this).ResetFromObject(static_cast<IUnit*>(unit));
}

void SCollisionLink::ClearLink() noexcept
{
  AsCollisionWeakLink(*this).ResetFromOwnerLinkSlot(nullptr);
}

namespace
{
  void RemoveFromIntrusiveCollisionChain(SCollisionInfo& info)
  {
    auto& weakLink = AsCollisionWeakLink(info.mUnit);
    weakLink.UnlinkFromOwnerChain();
    weakLink.ClearLinkState();
  }

  [[nodiscard]] Wm3::Vector3f UnitForwardXZ(const Unit* unit) noexcept
  {
    if (!unit) {
      return {0.0f, 0.0f, 1.0f};
    }

    const Wm3::Vector3f forward = unit->GetTransform().orient_.Rotate(Wm3::Vector3f{0.0f, 0.0f, 1.0f});
    Wm3::Vector3f flat{forward.x, 0.0f, forward.z};
    const Wm3::Vector3f normalized = Wm3::Vector3f::NormalizeOrZero(flat);
    if (Wm3::Vector3f::LengthSq(normalized) <= 1.0e-6f) {
      return {0.0f, 0.0f, 1.0f};
    }
    return normalized;
  }

  void PushPathPoint(
    gpg::core::FastVectorN<CPathPoint, 20>& nodes,
    const Wm3::Vector3f& pos,
    const Wm3::Vector3f& forward,
    const EPathPointState state
  )
  {
    CPathPoint point{};
    point.mPosition = pos;
    point.mDirection = forward;
    point.mState = state;
    nodes.PushBack(point);
  }

} // namespace

gpg::RType* CAiPathSpline::sType = nullptr;

/**
 * Address: 0x00596560 (FUN_00596560, sub_596560)
 */
void moho::ResetCollisionInfo(SCollisionInfo& info)
{
  RemoveFromIntrusiveCollisionChain(info);
  info.mPos = Wm3::Vector3f::Zero();
  info.mCollisionType = COLLISIONTYPE_None;
  info.mTickGate = -1;
}

/**
 * Address: 0x005B2550 (FUN_005B2550, ??0CAiPathSpline@Moho@@QAE@@Z)
 */
CAiPathSpline::CAiPathSpline()
  : mCurrentNodeIndex(0)
  , mNodeCount(0)
  , mPathType(PT_0)
  , mContinuation{Wm3::Vector3f::Zero(), Wm3::Vector3f::Zero(), Wm3::Vector3f::Zero(), PPS_8}
  , mTailWord(0)
{
  ResetNodesToInline();
}

/**
 * Address: 0x005D45D0 (FUN_005D45D0, ??1CAiPathSpline@Moho@@QAE@@Z)
 */
CAiPathSpline::~CAiPathSpline()
{
  ResetNodesToInline();
}

/**
 * Address: 0x005B2550 (FUN_005B2550)
 */
void CAiPathSpline::ResetNodesToInline()
{
  nodes.ResetStorageToInline();
}

/**
 * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
 */
CPathPoint* CAiPathSpline::TryGetNode(const std::uint32_t index)
{
  if (index >= mNodeCount) {
    return nullptr;
  }
  return &nodes[index];
}

/**
 * Address: 0x005965E0 (FUN_005965E0, sub_5965E0)
 */
const CPathPoint* CAiPathSpline::TryGetNode(const std::uint32_t index) const
{
  if (index >= mNodeCount) {
    return nullptr;
  }
  return &nodes[index];
}

/**
 * Address: 0x005B26C0 (FUN_005B26C0, Moho::CAiPathSpline::Update)
 */
int CAiPathSpline::Update(Unit* const unit, const int updateMode)
{
  // TODO(binary-fidelity): current body is a provisional typed lift. Exact FA behavior
  // depends on sub_6990E0/sub_6992C0/sub_699760 math and additional physics helpers.
  ResetNodesToInline();
  mCurrentNodeIndex = 0;
  mNodeCount = 0;
  mPathType = static_cast<EPathSplineType>(updateMode);

  if (!unit) {
    return 0;
  }

  const Wm3::Vector3f start = unit->GetPosition();
  const Wm3::Vector3f forward = UnitForwardXZ(unit);

  const RUnitBlueprint* const blueprint = unit->GetBlueprint();
  const float maxSpeed = blueprint ? blueprint->Physics.MaxSpeed : 0.0f;
  const float stepLen = std::max(0.1f, maxSpeed * 0.1f);
  const int nodeCount = (updateMode == 3 || updateMode == 4) ? 6 : 4;

  Wm3::Vector3f cursor = start;
  for (int i = 0; i < nodeCount; ++i) {
    cursor = cursor + forward * stepLen;
    PushPathPoint(nodes, cursor, forward, i + 1 == nodeCount ? PPS_8 : PPS_1);
  }

  mContinuation.mPreviousPosition = start;
  mContinuation.mPreviousDirection = forward;
  mContinuation.mPreviousVelocity = forward * stepLen;
  mContinuation.mContinuationState = PPS_0;

  mNodeCount = static_cast<std::uint32_t>(nodes.size());
  return static_cast<int>(mNodeCount);
}

/**
 * Address: 0x005B2FF0 (FUN_005B2FF0, Moho::CAiPathSpline::Generate)
 */
void CAiPathSpline::Generate(
  Unit* const unit,
  const Wm3::Vector3f& destination,
  const int pathType,
  const bool allowContinuation
)
{
  // TODO(binary-fidelity): current body is a provisional typed lift. Exact FA behavior
  // depends on full PPS state-machine reconstruction from 0x005B2FF0.
  ResetNodesToInline();
  mCurrentNodeIndex = 0;
  mNodeCount = 0;
  mPathType = static_cast<EPathSplineType>(pathType);

  if (!unit || unit->IsDead()) {
    return;
  }

  Wm3::Vector3f start = unit->GetPosition();
  if (!allowContinuation && mContinuation.mContinuationState != PPS_0 && mContinuation.mContinuationState != PPS_8) {
    start = mContinuation.mPreviousPosition;
  }

  Wm3::Vector3f delta = destination - start;
  const float distSq2D = delta.x * delta.x + delta.z * delta.z;
  if (distSq2D < 1.0e-6f) {
    return;
  }

  const float distance2D = std::sqrt(distSq2D);
  const int steps = std::clamp(static_cast<int>(distance2D / 1.5f) + 1, 2, 20);

  for (int i = 1; i <= steps; ++i) {
    const float t = static_cast<float>(i) / static_cast<float>(steps);
    const Wm3::Vector3f pos = start + delta * t;
    Wm3::Vector3f dir = destination - pos;
    dir.y = 0.0f;
    dir = Wm3::Vector3f::NormalizeOrZero(dir);
    if (Wm3::Vector3f::LengthSq(dir) <= 1.0e-6f) {
      dir = UnitForwardXZ(unit);
    }

    PushPathPoint(nodes, pos, dir, i == steps ? PPS_8 : PPS_1);
  }

  if (!nodes.empty()) {
    const CPathPoint& tail = nodes.back();
    mContinuation.mPreviousPosition = tail.mPosition;
    mContinuation.mPreviousDirection = tail.mDirection;
    mContinuation.mPreviousVelocity = tail.mDirection;
    mContinuation.mContinuationState = tail.mState;
  }

  mNodeCount = static_cast<std::uint32_t>(nodes.size());
}

SCollisionInfoTypeInfo::~SCollisionInfoTypeInfo() = default;

const char* SCollisionInfoTypeInfo::GetName() const
{
  return "SCollisionInfo";
}

/**
 * Address: 0x00596790 (FUN_00596790, SCollisionInfoTypeInfo::Init)
 */
void SCollisionInfoTypeInfo::Init()
{
  size_ = sizeof(SCollisionInfo);
  gpg::RType::Init();
  Finish();
}

CPathPointTypeInfo::~CPathPointTypeInfo() = default;

const char* CPathPointTypeInfo::GetName() const
{
  return "CPathPoint";
}

/**
 * Address: 0x0062F6B0 (FUN_0062F6B0, CPathPointTypeInfo::Init)
 */
void CPathPointTypeInfo::Init()
{
  size_ = sizeof(CPathPoint);
  gpg::RType::Init();
  Finish();
}

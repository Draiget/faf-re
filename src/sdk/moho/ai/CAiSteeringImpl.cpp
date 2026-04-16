#include "moho/ai/CAiSteeringImpl.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/containers/FastVector.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/console/CVarAccess.h"
#include "moho/entity/EntityDb.h"
#include "moho/math/Vector2f.h"
#include "moho/misc/Stats.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitMotion.h"

using namespace moho;

namespace
{
  using UnitVector = gpg::core::FastVectorN<Unit*, 10>;

  [[nodiscard]] std::string BuildInstanceCounterStatPath(const char* const rawTypeName)
  {
    std::string path("Instance Counts_");
    if (!rawTypeName) {
      return path;
    }

    for (const char* it = rawTypeName; *it != '\0'; ++it) {
      if (*it != '_') {
        path.push_back(*it);
      }
    }
    return path;
  }

  [[nodiscard]] gpg::RType* ResolveTaskType()
  {
    if (!CTask::sType) {
      CTask::sType = gpg::LookupRType(typeid(CTask));
    }
    return CTask::sType;
  }

  [[nodiscard]] gpg::RType* ResolveVector3fType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RType* ResolveELayerType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeid(ELayer));
    }
    return cachedType;
  }

  [[nodiscard]] gpg::RType* ResolveSCollisionInfoType()
  {
    static gpg::RType* cachedType = nullptr;
    if (!cachedType) {
      cachedType = gpg::LookupRType(typeid(SCollisionInfo));
    }
    return cachedType;
  }

  [[nodiscard]] bool IsAtPosition(const Unit* unit, const Wm3::Vector3f& target, const float tolerance) noexcept
  {
    if (!unit) {
      return false;
    }
    const float tolSq = tolerance * tolerance;
    return Wm3::Vector3f::DistanceSqXZ(unit->GetPosition(), target) <= tolSq;
  }

  [[nodiscard]] bool IsUnitState(const Unit* unit, const EUnitState state) noexcept
  {
    if (!unit) {
      return false;
    }
    return unit->IsUnitState(state);
  }

  [[nodiscard]] bool HasFootprintFlag(const EFootprintFlags value, const EFootprintFlags flag) noexcept
  {
    return (static_cast<std::uint8_t>(value) & static_cast<std::uint8_t>(flag)) != 0u;
  }

  [[nodiscard]] Wm3::Vector3f FlattenedForward(const Unit& unit) noexcept
  {
    Wm3::Vector3f forward = unit.GetTransform().orient_.Rotate({0.0f, 0.0f, 1.0f});
    forward.y = 0.0f;
    return Wm3::Vector3f::NormalizeOrZero(forward);
  }

  /**
    * Alias of FUN_00409A40 (non-canonical helper lane).
   *
   * What it does:
   * Allocates one CTaskThread and links `dispatch` as task-top while preserving
   * prior top in `dispatch->mSubtask`.
   */
  [[nodiscard]] CTaskThread*
  CreateTaskThreadForDispatch(CTask* const dispatch, CTaskStage* const stage, const bool autoDelete)
  {
    if (!dispatch || !stage) {
      return nullptr;
    }

    auto* const taskThread = new CTaskThread(stage);
    dispatch->mAutoDelete = autoDelete;
    dispatch->mOwnerThread = taskThread;
    dispatch->mSubtask = taskThread->mTaskTop;
    taskThread->mTaskTop = dispatch;
    return taskThread;
  }

  [[nodiscard]] float ReadSimConVarFloat(Sim* const sim, CSimConVarBase* const conVar, const float fallback) noexcept
  {
    if (!sim || !conVar) {
      return fallback;
    }

    CSimConVarInstanceBase* const instance = sim->GetSimVar(conVar);
    void* const storage = instance ? instance->GetValueStorage() : nullptr;
    if (!storage) {
      return fallback;
    }

    const float value = *static_cast<const float*>(storage);
    if (!std::isfinite(value) || value <= 0.0f) {
      return fallback;
    }

    return value;
  }

  [[nodiscard]] float ReadSteeringAirTolerance(Sim* const sim) noexcept
  {
    constexpr float kFallbackTolerance = 1.0f;
    return ReadSimConVarFloat(sim, moho::console::SimSteeringAirToleranceConVar(), kFallbackTolerance);
  }

  void UpdateMotionPathPointers(CAiSteeringImpl& steering)
  {
    if (!steering.mUnitMotion) {
      return;
    }

    CPathPoint* current = nullptr;
    CPathPoint* next = nullptr;

    if (steering.mPath && steering.mPath->mCurrentNodeIndex < steering.mPath->mNodeCount) {
      current = steering.mPath->TryGetNode(steering.mPath->mCurrentNodeIndex);
      next = steering.mPath->TryGetNode(steering.mPath->mCurrentNodeIndex + 1U);
    }

    steering.mUnitMotion->mNextWaypoint = current;
    steering.mUnitMotion->mFollowingWaypoint = next;

    if (current && steering.mPath) {
      ++steering.mPath->mCurrentNodeIndex;
    }
  }

  void MotionSetTarget(CUnitMotion* const motion, const Wm3::Vector3f& target)
  {
    if (!motion) {
      return;
    }
    motion->SetTarget(target);
  }

  void
  MotionSetTarget(CUnitMotion* const motion, const Wm3::Vector3f& target, const Wm3::Vector3f& vec, const ELayer layer)
  {
    if (!motion) {
      return;
    }
    motion->SetTarget(target, vec, layer);
  }

  void MotionStop(CUnitMotion* const motion)
  {
    if (!motion) {
      return;
    }
    motion->Stop(nullptr);
  }

  void ApplyTopSpeedPolicy(CAiSteeringImpl& steering)
  {
    if (!steering.mUnitMotion) {
      return;
    }

    const bool calc1 = steering.mTopSpeedFromCalc1 != 0;
    const bool calc2 = steering.mTopSpeedFromCalc2 != 0;
    const bool useCalc1Selector = steering.mForceTopSpeed != 0;
    steering.mUnitMotion->mAlwaysUseTopSpeed = static_cast<std::uint8_t>(useCalc1Selector ? calc1 : calc2);
  }

  void NotifyNavigatorPathRefresh(Unit* unit)
  {
    if (!unit || !unit->AiNavigator) {
      return;
    }
    unit->AiNavigator->Func1();
  }

  [[nodiscard]] float ComputeBrakingLeadDistance(
    const Wm3::Vector3f& velocity, const RUnitBlueprintPhysics& physics, const bool ignoreBraking
  ) noexcept
  {
    if (ignoreBraking) {
      return 0.0f;
    }

    const float speed = velocity.Length() * 10.0f;
    if (physics.MaxAcceleration <= 0.0f) {
      return 0.0f;
    }

    return (speed * speed) / (physics.MaxAcceleration * 2.0f);
  }

  struct CollisionObb2D
  {
    Wm3::Vector2f center;
    Wm3::Vector2f axis0;
    Wm3::Vector2f axis1;
    float extent0;
    float extent1;
  };

  [[nodiscard]] CollisionObb2D BuildCollisionObb2D(
    const Unit& unit, const Wm3::Vector3f& position, const float leadDistance, const float inflatedLength
  ) noexcept
  {
    const RUnitBlueprint* const blueprint = unit.GetBlueprint();
    const float sizeX = blueprint ? blueprint->mSizeX : 0.0f;
    const float sizeZ = blueprint ? blueprint->mSizeZ : 0.0f;
    const float lateralExtent = (sizeX + sizeZ) * 0.25f;
    const float forwardExtent = inflatedLength * 0.5f;

    const Vector4f& q = unit.Orientation;
    const float qx = q.x;
    const float qy = q.y;
    const float qz = q.z;
    const float qw = q.w;

    const Wm3::Vector2f forward = Wm3::Vector2f::NormalizeOrZero({
      ((qx * qz) + (qw * qy)) * 2.0f,
      1.0f - ((qz * qz + qy * qy) * 2.0f),
    });
    const Wm3::Vector2f right = Wm3::Vector2f::NormalizeOrZero({
      1.0f - ((qw * qw + qz * qz) * 2.0f),
      ((qw * qy) - (qx * qz)) * 2.0f,
    });

    CollisionObb2D out{};
    out.center = {position.x + (forward.x * leadDistance), position.z + (forward.y * leadDistance)};
    out.axis0 = right;
    out.axis1 = forward;
    out.extent0 = lateralExtent;
    out.extent1 = forwardExtent;
    return out;
  }

  [[nodiscard]] bool
  OverlapsOnAxis(const CollisionObb2D& lhs, const CollisionObb2D& rhs, const Wm3::Vector2f& axis) noexcept
  {
    const float axisLenSq = Wm3::Vector2f::Dot(axis, axis);
    if (axisLenSq <= 1.0e-8f) {
      return true;
    }

    const Wm3::Vector2f n = Wm3::Vector2f::NormalizeOrZero(axis);
    const Wm3::Vector2f delta = {rhs.center.x - lhs.center.x, rhs.center.y - lhs.center.y};
    const float distance = std::fabs(Wm3::Vector2f::Dot(delta, n));
    const float lhsProjection =
      std::fabs(Wm3::Vector2f::Dot(lhs.axis0, n)) * lhs.extent0 + std::fabs(Wm3::Vector2f::Dot(lhs.axis1, n)) *
      lhs.extent1;
    const float rhsProjection =
      std::fabs(Wm3::Vector2f::Dot(rhs.axis0, n)) * rhs.extent0 + std::fabs(Wm3::Vector2f::Dot(rhs.axis1, n)) *
      rhs.extent1;
    return distance <= (lhsProjection + rhsProjection);
  }

  [[nodiscard]] bool OBB2DIntersects(const CollisionObb2D& lhs, const CollisionObb2D& rhs) noexcept
  {
    return OverlapsOnAxis(lhs, rhs, lhs.axis0) && OverlapsOnAxis(lhs, rhs, lhs.axis1) &&
      OverlapsOnAxis(lhs, rhs, rhs.axis0) && OverlapsOnAxis(lhs, rhs, rhs.axis1);
  }

  /**
   * Address: 0x00596930 (FUN_00596930, func_UnitsWillCollide)
   */
  [[nodiscard]] bool UnitsWillCollide(
    const Wm3::Vector3f& primaryVelocity,
    const Unit& secondaryUnit,
    const Unit& primaryUnit,
    const Wm3::Vector3f& primaryPos,
    const Wm3::Vector3f& secondaryPos,
    const Wm3::Vector3f& secondaryVelocity,
    const bool ignoreBraking
  ) noexcept
  {
    const RUnitBlueprint* const primaryBlueprint = primaryUnit.GetBlueprint();
    const RUnitBlueprint* const secondaryBlueprint = secondaryUnit.GetBlueprint();
    if (!primaryBlueprint || !secondaryBlueprint) {
      return false;
    }

    const float primaryLead = ComputeBrakingLeadDistance(primaryVelocity, primaryBlueprint->Physics, ignoreBraking);
    const float secondaryLead =
      ComputeBrakingLeadDistance(secondaryVelocity, secondaryBlueprint->Physics, ignoreBraking);
    const float primaryInflatedLength = primaryBlueprint->mSizeZ + primaryLead;
    const float secondaryInflatedLength = secondaryBlueprint->mSizeZ + secondaryLead;

    const float precheckRadius = primaryInflatedLength + secondaryInflatedLength;
    if (Wm3::Vector3f::DistanceSq3D(primaryPos, secondaryPos) > (precheckRadius * precheckRadius)) {
      return false;
    }

    const CollisionObb2D primaryObb = BuildCollisionObb2D(primaryUnit, primaryPos, primaryLead, primaryInflatedLength);
    const CollisionObb2D secondaryObb =
      BuildCollisionObb2D(secondaryUnit, secondaryPos, secondaryLead, secondaryInflatedLength);
    return OBB2DIntersects(primaryObb, secondaryObb);
  }

  /**
   * Address: 0x0062EEA0 (FUN_0062EEA0, func_IsSourceUnit mode=2 subset)
   */
  [[nodiscard]] bool IsSourceUnitMode2Filtered(const Unit& owner, Unit* candidate) noexcept
  {
    if (!candidate || candidate->IsDead() || candidate->DestroyQueued() || candidate == &owner ||
        !candidate->IsMobile()) {
      return true;
    }

    if (candidate->IsUnitState(UNITSTATE_Attached)) {
      return true;
    }

    if (owner.mCurrentLayer != candidate->mCurrentLayer || (owner.mIsNaval && !candidate->mIsNaval)) {
      return true;
    }

    if (candidate->mIsAir && (candidate->mCurrentLayer == LAYER_Air || candidate->AiTransport != nullptr)) {
      return true;
    }

    if (HasFootprintFlag(owner.GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures) &&
        candidate->GetFootprint().mFlags == EFootprintFlags::FPFLAG_None) {
      return true;
    }

    if (owner.IsUnitState(UNITSTATE_WaitingForTransport) && candidate->IsUnitState(UNITSTATE_WaitingForTransport)) {
      if (owner.FocusEntityRef.ResolveObjectPtr<Entity>() == candidate->FocusEntityRef.ResolveObjectPtr<Entity>()) {
        return true;
      }
    }

    if (owner.IsUnitState(UNITSTATE_Upgrading) && candidate->CreatorRef.ResolveObjectPtr<Unit>() == &owner) {
      return true;
    }

    return false;
  }

  [[nodiscard]] float ComputeCollisionQueryRadius(const Unit& owner, const CAiPathSpline* path) noexcept
  {
    const RUnitBlueprint* const blueprint = owner.GetBlueprint();
    if (!blueprint) {
      return 0.0f;
    }

    const float unitRadius = std::max(blueprint->mSizeX, blueprint->mSizeZ);
    const std::size_t pathNodeCount = path ? path->nodes.size() : 0u;
    const float pathTravelDistance = static_cast<float>(pathNodeCount) * blueprint->Physics.MaxSpeed * 0.1f;
    const float brakingDistance = (blueprint->Physics.MaxAcceleration > 0.0f)
      ? (blueprint->Physics.MaxSpeed * blueprint->Physics.MaxSpeed) / (blueprint->Physics.MaxAcceleration * 2.0f)
      : 0.0f;
    return unitRadius + pathTravelDistance + brakingDistance;
  }

  [[nodiscard]] bool ShouldIgnoreBrakingForCollisionPair(const Unit& first, const Unit& second) noexcept
  {
    if (first.IsUnitState(UNITSTATE_Attacking) || second.IsUnitState(UNITSTATE_Attacking)) {
      return false;
    }

    const CFormationInstance* const firstFormation = first.mInfoCache.mFormationLayer;
    if (!firstFormation) {
      return false;
    }

    return firstFormation == second.mInfoCache.mFormationLayer;
  }

  [[nodiscard]] Wm3::Vector3f ResolvePathProbePosition(
    IAiSteering* const steering, const Wm3::Vector3f& fallbackPosition
  ) noexcept
  {
    if (!steering) {
      return fallbackPosition;
    }

    const CAiPathSpline* const path = steering->GetPath();
    if (!path) {
      return fallbackPosition;
    }

    const CPathPoint* const node = path->TryGetNode(path->mCurrentNodeIndex);
    return node ? node->mPosition : fallbackPosition;
  }

  [[nodiscard]] bool InSameFormationLayer(const Unit& first, const Unit& second) noexcept
  {
    return first.mInfoCache.mFormationLayer != nullptr && first.mInfoCache.mFormationLayer == second.mInfoCache.mFormationLayer;
  }

  [[nodiscard]] float ComputeCollisionSeparationDistance(const Unit& first, const Unit& second) noexcept
  {
    const RUnitBlueprint* const firstBlueprint = first.GetBlueprint();
    const RUnitBlueprint* const secondBlueprint = second.GetBlueprint();

    const float firstExtent = firstBlueprint ? std::max(firstBlueprint->mSizeX, firstBlueprint->mSizeZ) : 0.0f;
    const float secondExtent = secondBlueprint ? std::max(secondBlueprint->mSizeX, secondBlueprint->mSizeZ) : 0.0f;
    return firstExtent + secondExtent + 0.5f;
  }

  /**
   * Address: 0x00596E00 (FUN_00596E00, sub_596E00)
   *
   * What it does:
   * Evaluates whether two units are on an immediate collision course and moving
   * toward one another.
   */
  [[nodiscard]] bool IsCollisionApproachThreat(
    const Unit& owner,
    const Unit& collisionUnit,
    const Wm3::Vector3f& ownerPosition,
    const Wm3::Vector3f& collisionPosition,
    const Wm3::Vector3f& ownerVelocity,
    const Wm3::Vector3f& collisionVelocity
  ) noexcept
  {
    const bool ignoreBraking = ShouldIgnoreBrakingForCollisionPair(owner, collisionUnit);
    if (!UnitsWillCollide(
          ownerVelocity, collisionUnit, owner, ownerPosition, collisionPosition, collisionVelocity, ignoreBraking
        )) {
      return false;
    }

    const Wm3::Vector3f velocityDelta = ownerVelocity - collisionVelocity;
    if (Wm3::Vector3f::LengthSq(velocityDelta) <= 1.0e-6f) {
      return false;
    }

    const Wm3::Vector3f relativePosition = owner.GetPosition() - collisionUnit.GetPosition();
    return Wm3::Vector3f::Dot(relativePosition, velocityDelta) < 0.0f;
  }

  void MarkSecondarySteeringForRepath(const Unit& owner, Unit& collisionUnit, const bool sameFormation)
  {
    IAiSteering* const collisionSteering = collisionUnit.AiSteering;
    if (!collisionSteering || sameFormation) {
      return;
    }

    if (collisionUnit.mIsNaval) {
      if (!owner.mIsNaval) {
        return;
      }
      collisionSteering->SetCol(COLLISIONTYPE_5, collisionUnit.GetPosition());
      return;
    }

    const bool ownerIgnoresStructures =
      HasFootprintFlag(owner.GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
    const bool collisionIgnoresStructures =
      HasFootprintFlag(collisionUnit.GetFootprint().mFlags, EFootprintFlags::FPFLAG_IgnoreStructures);
    if (!collisionIgnoresStructures || ownerIgnoresStructures) {
      collisionSteering->SetCol(COLLISIONTYPE_5, collisionUnit.GetPosition());
    }
  }

  [[nodiscard]] Wm3::Vector3f ComputeAvoidanceDirection(
    const Unit& owner,
    const Wm3::Vector3f& ownerToCollision,
    const Wm3::Vector3f& collisionHeading,
    const bool ownerHasVelocity,
    const bool sameFormation
  ) noexcept
  {
    Wm3::Vector3f ownerHeading = ownerHasVelocity ? Wm3::Vector3f::NormalizeOrZero(owner.GetVelocity()) : FlattenedForward(owner);
    if (Wm3::Vector3f::LengthSq(ownerHeading) <= 1.0e-6f) {
      ownerHeading = FlattenedForward(owner);
    }

    constexpr float kForwardAlign = 0.70700002f;
    Wm3::Vector3f avoidBase = collisionHeading;
    if (ownerHasVelocity && Wm3::Vector3f::Dot(ownerHeading, collisionHeading) > kForwardAlign) {
      avoidBase = Wm3::Vector3f::NormalizeOrZero(collisionHeading + ownerHeading);
    }

    if (Wm3::Vector3f::LengthSq(avoidBase) <= 1.0e-6f) {
      avoidBase = collisionHeading;
    }

    Wm3::Vector3f lateral = Wm3::Vector3f::NormalizeOrZero({-avoidBase.z, 0.0f, avoidBase.x});
    if (Wm3::Vector3f::LengthSq(lateral) <= 1.0e-6f) {
      lateral = Wm3::Vector3f::NormalizeOrZero({-ownerToCollision.z, 0.0f, ownerToCollision.x});
    }

    const float crossY = (ownerToCollision.x * avoidBase.z) - (ownerToCollision.z * avoidBase.x);
    if (crossY > 0.0f) {
      lateral = lateral * -1.0f;
    }
    if (sameFormation) {
      lateral = lateral * -1.0f;
    }

    Wm3::Vector3f avoidDirection = Wm3::Vector3f::NormalizeOrZero(avoidBase + lateral);
    if (Wm3::Vector3f::LengthSq(avoidDirection) <= 1.0e-6f) {
      avoidDirection = Wm3::Vector3f::NormalizeOrZero(ownerToCollision * -1.0f);
    }
    return avoidDirection;
  }

  /**
   * Address: 0x00597800 (FUN_00597800, sub_597800)
   */
  void PredictCollisionForSteerings(
    IAiSteering* primarySteering, Unit* primaryUnit, Unit* secondaryUnit, IAiSteering* secondarySteering
  )
  {
    if (!primaryUnit || !secondaryUnit || !secondarySteering) {
      return;
    }

    CAiPathSpline* const secondaryPath = secondarySteering->GetPath();
    CAiPathSpline* const primaryPath = primarySteering ? primarySteering->GetPath() : nullptr;
    std::uint32_t secondaryStartNode = secondaryPath ? secondaryPath->mCurrentNodeIndex : 0u;
    std::uint32_t primaryStartNode = primaryPath ? primaryPath->mCurrentNodeIndex : 0u;
    if (!secondaryPath && !primaryPath) {
      return;
    }

    SCollisionInfo* const collisionInfo = secondarySteering->GetColInfo();
    if (!collisionInfo) {
      return;
    }

    if (collisionInfo->mUnit.ResolveUnitFromIntrusiveSlot() == secondaryUnit) {
      ResetCollisionInfo(*collisionInfo);
    }

    const bool ignoreBraking = ShouldIgnoreBrakingForCollisionPair(*primaryUnit, *secondaryUnit);
    const std::int32_t tickBase =
      (primaryUnit->SimulationRef != nullptr) ? static_cast<std::int32_t>(primaryUnit->SimulationRef->mCurTick) : 0;

    Wm3::Vector3f primaryPos = primaryUnit->GetPosition();
    Wm3::Vector3f secondaryPos = secondaryUnit->GetPosition();
    Wm3::Vector3f prevPrimaryPos = primaryPos;
    Wm3::Vector3f prevSecondaryPos = secondaryPos;
    Wm3::Vector3f primaryVelocity = Wm3::Vector3f::Zero();
    Wm3::Vector3f secondaryVelocity = Wm3::Vector3f::Zero();

    std::int32_t pathStep = 0;
    while (true) {
      if (collisionInfo->mCollisionType == COLLISIONTYPE_1 && collisionInfo->mTickGate < (pathStep + tickBase)) {
        break;
      }

      if (secondaryPath) {
        const std::uint32_t index = secondaryStartNode + static_cast<std::uint32_t>(pathStep);
        if (index >= secondaryPath->mNodeCount) {
          return;
        }

        const CPathPoint* const node = secondaryPath->TryGetNode(index);
        if (!node) {
          return;
        }

        secondaryPos = node->mPosition;
        secondaryVelocity = (pathStep == 0) ? primaryUnit->GetVelocity() : (secondaryPos - prevSecondaryPos);
        prevSecondaryPos = secondaryPos;
      }

      if (primaryPath) {
        const std::uint32_t index = primaryStartNode + static_cast<std::uint32_t>(pathStep);
        if (index >= primaryPath->mNodeCount) {
          return;
        }

        const CPathPoint* const node = primaryPath->TryGetNode(index);
        if (!node) {
          return;
        }

        primaryPos = node->mPosition;
        primaryVelocity = (pathStep == 0) ? secondaryUnit->GetVelocity() : (primaryPos - prevPrimaryPos);
        prevPrimaryPos = primaryPos;
      }

      if (UnitsWillCollide(
            secondaryVelocity, *secondaryUnit, *primaryUnit, secondaryPos, primaryPos, primaryVelocity, ignoreBraking
          )) {
        const float existingCollisionDistSq = collisionInfo->mUnit.HasLinkedUnit()
          ? Wm3::Vector3f::DistanceSq3D(secondaryPos, collisionInfo->mPos)
          : 9999.0f;
        const float newCollisionDistSq = Wm3::Vector3f::DistanceSq3D(secondaryPos, primaryPos);
        if (existingCollisionDistSq > newCollisionDistSq) {
          collisionInfo->mCollisionType = COLLISIONTYPE_1;
          collisionInfo->mPos = primaryPos;
          collisionInfo->mUnit.AssignUnit(secondaryUnit);
          collisionInfo->mTickGate = pathStep + tickBase;
          return;
        }
      }

      pathStep += 3;
    }
  }

  void CollectCollisionCandidates(CAiSteeringImpl& steering, UnitVector& preferred, UnitVector& deferred)
  {
    Unit* const owner = steering.mOwnerUnit;
    if (!owner || !owner->SimulationRef || !owner->SimulationRef->mEntityDB) {
      return;
    }

    const float radius = ComputeCollisionQueryRadius(*owner, steering.mPath);
    const float radiusSq = radius * radius;
    const Wm3::Vector3f& ownerPosition = owner->GetPosition();

    for (Entity* entity : owner->SimulationRef->mEntityDB->Entities()) {
      Unit* const candidate = entity ? entity->IsUnit() : nullptr;
      if (!candidate) {
        continue;
      }

      if (Wm3::Vector3f::DistanceSq3D(ownerPosition, candidate->GetPosition()) > radiusSq) {
        continue;
      }

      if (IsSourceUnitMode2Filtered(*owner, candidate)) {
        continue;
      }

      IAiSteering* const candidateSteering = candidate->AiSteering;
      if (!candidateSteering) {
        continue;
      }

      CAiPathSpline* const candidatePath = candidateSteering->GetPath();
      if (candidatePath && candidatePath->mPathType == PT_2) {
        continue;
      }

      if (candidate->mCurrentLayer == owner->mCurrentLayer && !owner->IsHigherPriorityThan(candidate)) {
        deferred.PushBack(candidate);
        continue;
      }

      const RUnitBlueprint* const candidateBlueprint = candidate->GetBlueprint();
      if (!candidatePath && (!candidateBlueprint || !candidateBlueprint->Air.CanFly)) {
        continue;
      }

      preferred.PushBack(candidate);
    }
  }

  /**
   * Address: 0x00596F30 (FUN_00596F30, func_ResolvePossibleCollision)
   *
   * What it does:
   * Resolves a predicted collision window (`COLLISIONTYPE_1`) into a concrete
   * steering action (`None`, `2`, or `4`) and optional peer repath signal.
   */
  void ResolvePossibleCollisionState(CAiSteeringImpl& steering)
  {
    Unit* const owner = steering.mOwnerUnit;
    Unit* const collisionUnit = steering.mCollisionInfo.mUnit.ResolveUnitFromIntrusiveSlot();
    if (!owner || !collisionUnit || !owner->AiSteering) {
      return;
    }

    const Wm3::Vector3f ownerPosition = owner->GetPosition();
    Wm3::Vector3f ownerProbePosition = ResolvePathProbePosition(owner->AiSteering, ownerPosition);
    Wm3::Vector3f collisionProbePosition = ResolvePathProbePosition(collisionUnit->AiSteering, collisionUnit->GetPosition());

    const Wm3::Vector3f ownerVelocity = owner->GetVelocity();
    const Wm3::Vector3f collisionVelocity = collisionUnit->GetVelocity();
    const bool ownerHasVelocity = Wm3::Vector3f::LengthSq(ownerVelocity) > 0.0f;

    const RUnitBlueprint* const collisionBlueprint = collisionUnit->GetBlueprint();
    if (collisionBlueprint && collisionBlueprint->Air.CanFly && collisionUnit->UnitMotion) {
      if (!collisionUnit->AiTransport &&
          IsCollisionApproachThreat(
            *owner, *collisionUnit, ownerProbePosition, collisionProbePosition, ownerVelocity, collisionVelocity
          )) {
        MotionSetTarget(collisionUnit->UnitMotion, collisionUnit->GetPosition(), Wm3::Vector3f::Zero(), LAYER_Air);
      }

      steering.SetCol(COLLISIONTYPE_None, ownerPosition);
      return;
    }

    Sim* const sim = owner->SimulationRef;
    if (sim) {
      sim->Logf(
        "  ResolvePossibleCollision(0x%08x @ <%.2f,%.2f,%2.f>, 0x%08x @ <%.2f,%.2f,%2.f>)\n",
        static_cast<std::uint32_t>(owner->GetEntityId()),
        ownerProbePosition.x,
        ownerProbePosition.y,
        ownerProbePosition.z,
        static_cast<std::uint32_t>(collisionUnit->GetEntityId()),
        collisionProbePosition.x,
        collisionProbePosition.y,
        collisionProbePosition.z
      );
    }

    if (Wm3::Vector3f::LengthSq(collisionVelocity) <= 0.0f ||
        !IsCollisionApproachThreat(
          *owner, *collisionUnit, ownerProbePosition, collisionProbePosition, ownerVelocity, collisionVelocity
        )) {
      steering.SetCol(COLLISIONTYPE_None, ownerPosition);
      return;
    }

    if (sim) {
      sim->Logf("    collide.\n");
    }

    const Wm3::Vector3f ownerToCollision = Wm3::Vector3f::NormalizeOrZero(collisionProbePosition - ownerProbePosition);
    Wm3::Vector3f collisionHeading = Wm3::Vector3f::NormalizeOrZero(collisionVelocity);
    if (Wm3::Vector3f::LengthSq(collisionHeading) <= 1.0e-6f) {
      collisionHeading = FlattenedForward(*collisionUnit);
    }

    constexpr float kCollisionConeCos = 0.70700002f;
    if (Wm3::Vector3f::Dot(ownerToCollision, collisionHeading) <= kCollisionConeCos) {
      if (sim) {
        sim->Logf("    not within cone.\n");
      }
      steering.SetCol(COLLISIONTYPE_4, ownerPosition);
      return;
    }

    if (sim) {
      sim->Logf("    within cone.\n");
    }

    const bool sameFormation = InSameFormationLayer(*owner, *collisionUnit);
    MarkSecondarySteeringForRepath(*owner, *collisionUnit, sameFormation);

    const float separationDistance = ComputeCollisionSeparationDistance(*owner, *collisionUnit);
    const Wm3::Vector3f avoidDirection =
      ComputeAvoidanceDirection(*owner, ownerToCollision, collisionHeading, ownerHasVelocity, sameFormation);
    if (Wm3::Vector3f::LengthSq(avoidDirection) <= 1.0e-6f) {
      steering.SetCol(COLLISIONTYPE_None, ownerPosition);
      return;
    }

    steering.mCollisionAvoidTarget = ownerProbePosition + (avoidDirection * separationDistance);
    steering.SetCol(COLLISIONTYPE_2, steering.mCollisionAvoidTarget);
  }

  [[nodiscard]] Wm3::Vector3f DebugUpAxis() noexcept
  {
    return {0.0f, 1.0f, 0.0f};
  }

  constexpr std::uint32_t kDebugDepthBlockedNode = 0xFF00FF00u;
  constexpr std::uint32_t kDebugDepthTransitionNode = 0xFFFF0000u;
  constexpr std::uint32_t kDebugDepthPathType2Node = 0xFFFF00FFu;
  constexpr std::uint32_t kDebugDepthDefaultNode = 0xFFC0C000u;
  constexpr std::uint32_t kDebugDepthCurrentNode = 0xFFFFFFFFu;
  constexpr std::uint32_t kDebugDepthCollision = 0xFFFF00FFu;
  constexpr float kDebugPathNodeRadius = 0.1f;
  constexpr float kDebugCurrentNodeRadius = 0.3f;
  constexpr std::uint32_t kDebugPathNodePrecision = 6u;
  constexpr std::uint32_t kDebugCurrentNodePrecision = 8u;

  [[nodiscard]] std::uint32_t ResolvePathNodeDebugDepth(const CAiPathSpline& path, const CPathPoint& node) noexcept
  {
    if (node.mState == PPS_5 || node.mState == PPS_6 || node.mState == PPS_2) {
      return kDebugDepthBlockedNode;
    }

    if (node.mState == PPS_1 || node.mState == PPS_3 || node.mState == PPS_4 || node.mState == PPS_6) {
      return kDebugDepthTransitionNode;
    }

    if (path.mPathType == PT_2) {
      return kDebugDepthPathType2Node;
    }

    return kDebugDepthDefaultNode;
  }

  void DrawPathDebugOverlay(const CAiSteeringImpl& steering, CDebugCanvas& debugCanvas)
  {
    const CAiPathSpline* const path = steering.mPath;
    if (!path) {
      return;
    }

    const CPathPoint* const nodesBegin = path->nodes.begin();
    const CPathPoint* const nodesEnd = path->nodes.end();
    const std::uint32_t drawNodeCount =
      (nodesBegin && nodesEnd && nodesEnd > nodesBegin) ? static_cast<std::uint32_t>(nodesEnd - nodesBegin) : 0u;

    for (std::uint32_t i = 0; i < drawNodeCount; i += 3u) {
      if (i >= path->mNodeCount || !nodesBegin) {
        continue;
      }

      const CPathPoint& node = nodesBegin[i];
      debugCanvas.AddWireCircle(
        DebugUpAxis(),
        node.mPosition,
        kDebugPathNodeRadius,
        ResolvePathNodeDebugDepth(*path, node),
        kDebugPathNodePrecision
      );
    }

    if (path->mCurrentNodeIndex < path->mNodeCount) {
      if (const CPathPoint* const currentNode = path->TryGetNode(path->mCurrentNodeIndex)) {
        debugCanvas.AddWireCircle(
          DebugUpAxis(),
          currentNode->mPosition,
          kDebugCurrentNodeRadius,
          kDebugDepthCurrentNode,
          kDebugCurrentNodePrecision
        );
      }
    }
  }

  void DrawCollisionDebugOverlay(const CAiSteeringImpl& steering, CDebugCanvas& debugCanvas)
  {
    Unit* const collisionUnit = steering.mCollisionInfo.mUnit.ResolveUnitFromIntrusiveSlot();
    if (!collisionUnit || !steering.mOwnerUnit) {
      return;
    }

    const Wm3::Vector3f& ownerPos = steering.mOwnerUnit->GetPosition();
    const Wm3::Vector3f& collisionPos = collisionUnit->GetPosition();

    SDebugLine collisionLine{};
    collisionLine.p0 = collisionPos;
    collisionLine.p1 = ownerPos;
    collisionLine.depth0 = static_cast<std::int32_t>(kDebugDepthCollision);
    collisionLine.depth1 = static_cast<std::int32_t>(kDebugDepthCollision);
    debugCanvas.DebugDrawLine(collisionLine);

    float collisionRadius = 0.0f;
    if (const RUnitBlueprint* const collisionBlueprint = collisionUnit->GetBlueprint()) {
      collisionRadius = std::max(collisionBlueprint->mSizeX, collisionBlueprint->mSizeZ);
    }

    debugCanvas.AddWireCircle(
      DebugUpAxis(), collisionPos, collisionRadius, kDebugDepthCollision, kDebugCurrentNodePrecision
    );
  }
} // namespace

gpg::RType* CAiSteeringImpl::sType = nullptr;

/**
 * Address: 0x005D3F20 (FUN_005D3F20, Moho::InstanceCounter<Moho::CAiSteeringImpl>::GetStatItem)
 *
 * What it does:
 * Lazily resolves and caches the engine stat slot used for CAiSteeringImpl
 * instance counting (`Instance Counts_<type-name-without-underscores>`).
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::CAiSteeringImpl>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  const std::string statPath = BuildInstanceCounterStatPath(typeid(moho::CAiSteeringImpl).name());
  moho::EngineStats* const engineStats = moho::GetEngineStats();
  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

/**
 * Address: 0x005D2670 (FUN_005D2670, reflection default-construct path)
 */
CAiSteeringImpl::CAiSteeringImpl()
  : CTask(nullptr, false)
  , mOwnerUnit(nullptr)
  , mWaypoints{}
  , mWaypointCount(0)
  , mCurrentWaypointIndex(0)
  , mMovementLayer(LAYER_None)
  , mUnitMotion(nullptr)
  , mCollisionInfo{}
  , mPath(nullptr)
  , mCollisionAvoidTarget(Wm3::Vector3f::Zero())
  , mDestination(Wm3::Vector3f::Zero())
  , mNeedsWaypointRefresh(0)
  , mTopSpeedFromCalc1(0)
  , mTopSpeedFromCalc2(0)
  , mForceTopSpeed(0)
  , mPausedForStateTransition(0)
  , mPadA1{0, 0, 0}
{
  ResetCollisionInfo(mCollisionInfo);
}

/**
 * Address: 0x005D2790 (FUN_005D2790, ??0CAiSteeringImpl@Moho@@QAE@@Z)
 */
CAiSteeringImpl::CAiSteeringImpl(Unit* const unit, CUnitMotion* const motion, const ELayer layer)
  : CAiSteeringImpl()
{
  mOwnerUnit = unit;
  mMovementLayer = layer;
  mUnitMotion = motion;
  mDestination = Wm3::Vector3f::NaN();
  mCollisionAvoidTarget = Wm3::Vector3f::Zero();

  CAiBrain* brain = nullptr;
  if (mOwnerUnit && mOwnerUnit->ArmyRef) {
    brain = mOwnerUnit->ArmyRef->GetArmyBrain();
  }

  if (brain && brain->mAttackerThreadStage) {
    CreateTaskThreadForDispatch(static_cast<CTask*>(this), brain->mAttackerThreadStage, false);
  }
}

/**
 * Address: 0x005D2920 (FUN_005D2920, ??1CAiSteeringImpl@Moho@@QAE@@Z)
 */
CAiSteeringImpl::~CAiSteeringImpl()
{
  Stop();
  if (mPath) {
    delete mPath;
    mPath = nullptr;
  }
  ResetCollisionInfo(mCollisionInfo);
}

/**
 * Address: 0x005D48E0 (FUN_005D48E0, Moho::CAiSteeringImpl::MemberDeserialize)
 *
 * What it does:
 * Loads steering runtime fields from one archive lane in serializer order.
 */
void CAiSteeringImpl::MemberDeserialize(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  gpg::RType* const taskType = ResolveTaskType();
  GPG_ASSERT(taskType != nullptr);
  if (!taskType) {
    return;
  }
  archive->Read(taskType, static_cast<CTask*>(this), ownerRef);

  CAiPathSpline* loadedPath = nullptr;
  archive->ReadPointerOwned_CAiPathSpline(&loadedPath, &ownerRef);
  CAiPathSpline* const previousPath = mPath;
  mPath = loadedPath;
  if (previousPath) {
    previousPath->~CAiPathSpline();
  }

  archive->ReadPointer_Unit(&mOwnerUnit, &ownerRef);
  archive->ReadUInt(reinterpret_cast<unsigned int*>(&mWaypointCount));

  gpg::RType* const vector3Type = ResolveVector3fType();
  GPG_ASSERT(vector3Type != nullptr);
  if (!vector3Type) {
    return;
  }

  Wm3::Vector3f overflowWaypointSink = Wm3::Vector3f::Zero();
  const std::uint32_t waypointCount = static_cast<std::uint32_t>(mWaypointCount);
  for (std::uint32_t index = 0; index < waypointCount; ++index) {
    void* const waypointTarget =
      (index < 4u) ? static_cast<void*>(&mWaypoints[index]) : static_cast<void*>(&overflowWaypointSink);
    archive->Read(vector3Type, waypointTarget, ownerRef);
  }

  archive->ReadUInt(reinterpret_cast<unsigned int*>(&mCurrentWaypointIndex));

  gpg::RType* const layerType = ResolveELayerType();
  GPG_ASSERT(layerType != nullptr);
  if (!layerType) {
    return;
  }
  archive->Read(layerType, &mMovementLayer, ownerRef);

  archive->ReadPointer_CUnitMotion(&mUnitMotion, &ownerRef);

  gpg::RType* const collisionInfoType = ResolveSCollisionInfoType();
  GPG_ASSERT(collisionInfoType != nullptr);
  if (!collisionInfoType) {
    return;
  }
  archive->Read(collisionInfoType, &mCollisionInfo, ownerRef);

  archive->Read(vector3Type, &mCollisionAvoidTarget, ownerRef);
  archive->Read(vector3Type, &mDestination, ownerRef);

  bool flag = false;
  archive->ReadBool(&flag);
  mNeedsWaypointRefresh = static_cast<std::uint8_t>(flag ? 1u : 0u);
  archive->ReadBool(&flag);
  mTopSpeedFromCalc1 = static_cast<std::uint8_t>(flag ? 1u : 0u);
  archive->ReadBool(&flag);
  mTopSpeedFromCalc2 = static_cast<std::uint8_t>(flag ? 1u : 0u);
  archive->ReadBool(&flag);
  mForceTopSpeed = static_cast<std::uint8_t>(flag ? 1u : 0u);
  archive->ReadBool(&flag);
  mPausedForStateTransition = static_cast<std::uint8_t>(flag ? 1u : 0u);
}

/**
 * Address: 0x005D4B50 (FUN_005D4B50, Moho::CAiSteeringImpl::MemberSerialize)
 *
 * What it does:
 * Writes steering runtime fields into one write-archive lane in the same order
 * as `MemberDeserialize`.
 */
void CAiSteeringImpl::MemberSerialize(gpg::WriteArchive* const archive) const
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};

  gpg::RType* const taskType = ResolveTaskType();
  GPG_ASSERT(taskType != nullptr);
  if (!taskType) {
    return;
  }
  archive->Write(taskType, static_cast<const CTask*>(this), ownerRef);

  gpg::RRef pathRef{};
  gpg::RRef_CAiPathSpline(&pathRef, mPath);
  gpg::WriteRawPointer(archive, pathRef, gpg::TrackedPointerState::Owned, ownerRef);

  gpg::RRef unitRef{};
  gpg::RRef_Unit(&unitRef, mOwnerUnit);
  gpg::WriteRawPointer(archive, unitRef, gpg::TrackedPointerState::Unowned, ownerRef);

  archive->WriteUInt(static_cast<unsigned int>(mWaypointCount));

  gpg::RType* const vector3Type = ResolveVector3fType();
  GPG_ASSERT(vector3Type != nullptr);
  if (!vector3Type) {
    return;
  }

  const std::uint32_t waypointCount = static_cast<std::uint32_t>(mWaypointCount);
  for (std::uint32_t index = 0; index < waypointCount; ++index) {
    archive->Write(vector3Type, &mWaypoints[index], ownerRef);
  }

  archive->WriteUInt(static_cast<unsigned int>(mCurrentWaypointIndex));

  gpg::RType* const layerType = ResolveELayerType();
  GPG_ASSERT(layerType != nullptr);
  if (!layerType) {
    return;
  }
  archive->Write(layerType, &mMovementLayer, ownerRef);

  gpg::RRef motionRef{};
  gpg::RRef_CUnitMotion(&motionRef, mUnitMotion);
  gpg::WriteRawPointer(archive, motionRef, gpg::TrackedPointerState::Unowned, ownerRef);

  gpg::RType* const collisionInfoType = ResolveSCollisionInfoType();
  GPG_ASSERT(collisionInfoType != nullptr);
  if (!collisionInfoType) {
    return;
  }
  archive->Write(collisionInfoType, &mCollisionInfo, ownerRef);
  archive->Write(vector3Type, &mCollisionAvoidTarget, ownerRef);
  archive->Write(vector3Type, &mDestination, ownerRef);

  archive->WriteBool(mNeedsWaypointRefresh != 0u);
  archive->WriteBool(mTopSpeedFromCalc1 != 0u);
  archive->WriteBool(mTopSpeedFromCalc2 != 0u);
  archive->WriteBool(mForceTopSpeed != 0u);
  archive->WriteBool(mPausedForStateTransition != 0u);
}

/**
 * Address: 0x005D29C0 (FUN_005D29C0)
 */
CUnitMotion* CAiSteeringImpl::SetWaypoints(const Wm3::Vector3f* const waypoints, const int waypointCount)
{
  const int clampedCount = (waypoints != nullptr) ? std::clamp(waypointCount, 0, 4) : 0;
  mWaypointCount = clampedCount;
  mCurrentWaypointIndex = 0;

  for (int i = 0; i < clampedCount; ++i) {
    mWaypoints[i] = waypoints[i];
  }

  if (clampedCount > 0) {
    mNeedsWaypointRefresh = 1;
    return mUnitMotion;
  }

  mDestination = Wm3::Vector3f::NaN();

  if (mPath) {
    ResetCollisionInfo(mCollisionInfo);

    if (mOwnerUnit && !mOwnerUnit->IsDead() && !mOwnerUnit->IsBeingBuilt() && !mOwnerUnit->DestroyQueued()) {
      mPath->Update(mOwnerUnit, 3);
    }

    CheckCollisions();
    UpdateMotionPathPointers(*this);
  }

  mNeedsWaypointRefresh = 0;
  return mUnitMotion;
}

/**
 * Address: 0x005D2110 (FUN_005D2110)
 */
int CAiSteeringImpl::GetWaypoints(Wm3::Vector3f* const outWaypoints) const
{
  if (!outWaypoints) {
    return mWaypointCount;
  }

  for (int i = 0; i < 4; ++i) {
    outWaypoints[i] = mWaypoints[i];
  }

  return mWaypointCount;
}

/**
 * Address: 0x005D2170 (FUN_005D2170)
 */
Wm3::Vector3f CAiSteeringImpl::GetWaypoint() const
{
  if (mWaypointCount <= 0) {
    return Wm3::Vector3f::Zero();
  }

  return mWaypoints[mWaypointCount - 1];
}

/**
 * Address: 0x005D21B0 (FUN_005D21B0)
 */
bool CAiSteeringImpl::IsDone() const
{
  return mCurrentWaypointIndex >= mWaypointCount;
}

/**
 * Address: 0x005D21C0 (FUN_005D21C0)
 */
SCollisionInfo* CAiSteeringImpl::GetColInfo()
{
  return &mCollisionInfo;
}

/**
 * Address: 0x005D3B40 (FUN_005D3B40)
 */
void CAiSteeringImpl::SetCol(const ECollisionType type, const Wm3::Vector3f& position)
{
  mCollisionInfo.mCollisionType = type;
  mCollisionInfo.mPos = position;
}

/**
 * Address: 0x005D21D0 (FUN_005D21D0)
 */
CAiPathSpline* CAiSteeringImpl::GetPath()
{
  return mPath;
}

/**
 * Address: 0x005D2390 (FUN_005D2390)
 */
void CAiSteeringImpl::CalcAtTopSpeed1(const bool enabled)
{
  mTopSpeedFromCalc1 = static_cast<std::uint8_t>(enabled);
  ApplyTopSpeedPolicy(*this);
}

/**
 * Address: 0x005D23E0 (FUN_005D23E0)
 */
void CAiSteeringImpl::CalcAtTopSpeed2(const bool enabled)
{
  mTopSpeedFromCalc2 = static_cast<std::uint8_t>(enabled);
  ApplyTopSpeedPolicy(*this);
}

/**
 * Address: 0x005D2430 (FUN_005D2430)
 */
void CAiSteeringImpl::UseTopSpeed(const bool enabled)
{
  mForceTopSpeed = static_cast<std::uint8_t>(enabled);
}

/**
 * Address: 0x005D2440 (FUN_005D2440, Moho::CAiSteeringImpl::GetVal)
 */
int CAiSteeringImpl::GetVal() const
{
  if (mForceTopSpeed != 0) {
    return mTopSpeedFromCalc1 != 0;
  }
  return mTopSpeedFromCalc2 != 0;
}

/**
 * Address: 0x005D2480 (FUN_005D2480, func_TrySnapPosToWaypoint)
 */
Wm3::Vector3f CAiSteeringImpl::TrySnapPosToWaypoint(
  const CAiSteeringImpl& steering, const int index, const Wm3::Vector3f& currentPos, const float tolerance
)
{
  if (index < 0 || index >= steering.mWaypointCount) {
    return Wm3::Vector3f::Zero();
  }

  const Wm3::Vector3f waypoint = steering.mWaypoints[index];
  if (!Wm3::Vector3f::IsntNaN(&waypoint)) {
    gpg::Logf(
      "INVALID POINT!!!! index=%d, pathSize=%d, x=%f, y=%f, z=%f",
      index,
      steering.mWaypointCount,
      waypoint.x,
      waypoint.y,
      waypoint.z
    );
  }

  const bool hasNext = (index + 1) < steering.mWaypointCount;
  const float dist = std::sqrt(Wm3::Vector3f::DistanceSqXZ(currentPos, waypoint));
  if (!hasNext || dist >= tolerance) {
    return waypoint;
  }

  Wm3::Vector3f delta = steering.mWaypoints[index + 1] - waypoint;
  delta.LimitLengthTo(tolerance - dist);
  return waypoint + delta;
}

/**
 * Address: 0x005D35E0 (FUN_005D35E0)
 */
void CAiSteeringImpl::Stop()
{
  if (mPath) {
    const bool hadRemaining = mPath->mCurrentNodeIndex < mPath->mNodeCount;
    delete mPath;
    mPath = nullptr;

    mCollisionAvoidTarget = Wm3::Vector3f::Zero();
    ResetCollisionInfo(mCollisionInfo);

    if (hadRemaining) {
      CheckCollisions();
    }
  }

  CUnitMotion* const motion = mUnitMotion;
  if (motion) {
    motion->mNextWaypoint = nullptr;
    motion->mFollowingWaypoint = nullptr;
  }

  MotionStop(mUnitMotion);
}

/**
 * Address: 0x005D3680 (FUN_005D3680, Moho::CAiSteeringImpl::UpdatePath)
 */
void CAiSteeringImpl::UpdatePath(const int pathMode, const Wm3::Vector3f& destination, const bool allowContinuation)
{
  ResetCollisionInfo(mCollisionInfo);

  if (!mPath) {
    mPath = new CAiPathSpline();
  }

  if (!mOwnerUnit || mOwnerUnit->IsDead() || mOwnerUnit->IsBeingBuilt() || mOwnerUnit->DestroyQueued()) {
    return;
  }

  if (pathMode == 4 || pathMode == 3) {
    mPath->Update(mOwnerUnit, pathMode);
    return;
  }

  if (!Wm3::Vector3f::IsInvalid(destination)) {
    mPath->Generate(mOwnerUnit, destination, pathMode, allowContinuation);
  }
}

/**
 * Address: 0x005D3740 (FUN_005D3740, Moho::CAiSteeringImpl::CheckCollisions)
 */
void CAiSteeringImpl::CheckCollisions()
{
  if (!mOwnerUnit) {
    return;
  }

  if (mOwnerUnit->IsDead() || mOwnerUnit->DestroyQueued() || mOwnerUnit->IsBeingBuilt() ||
      mOwnerUnit->mCurrentLayer == LAYER_Sub) {
    return;
  }

  // FUN_005D3740 always clears collision state before candidate scan.
  ResetCollisionInfo(mCollisionInfo);
  UnitVector preferred;
  UnitVector deferred;
  CollectCollisionCandidates(*this, preferred, deferred);

  for (Unit* candidate : preferred) {
    if (!candidate || !candidate->AiSteering) {
      continue;
    }
    PredictCollisionForSteerings(candidate->AiSteering, mOwnerUnit, candidate, this);
  }

  for (Unit* candidate : deferred) {
    if (!candidate || !candidate->AiSteering) {
      continue;
    }
    PredictCollisionForSteerings(this, candidate, mOwnerUnit, candidate->AiSteering);
  }
}

/**
 * Address: 0x005D2C00 (FUN_005D2C00, Moho::CAiSteeringImpl::ProcessSplineMovement)
 */
bool CAiSteeringImpl::ProcessSplineMovement()
{
  if (!mOwnerUnit) {
    return false;
  }

  Sim* const sim = mOwnerUnit->SimulationRef;
  CUnitMotion* const motion = mUnitMotion;
  bool doPathRefresh = false;
  bool allowContinuation = false;

  if (motion && motion->mIsBeingPushed != 0) {
    if (mPath) {
      Stop();
    }

    const RUnitBlueprint* const blueprint = mOwnerUnit->GetBlueprint();
    const float maxSpeed = blueprint ? blueprint->Physics.MaxSpeed : 0.0f;
    const float velocityLen = mOwnerUnit->GetVelocity().Length();

    if ((maxSpeed * 0.01f) > velocityLen) {
      motion->mIsBeingPushed = 0;
      if (motion->mInStateTransition != 0) {
        motion->mInStateTransition = 0;
        NotifyNavigatorPathRefresh(mOwnerUnit);
      }

      if (!Wm3::Vector3f::IsInvalid(mDestination)) {
        doPathRefresh = true;
        allowContinuation = true;
      }
    }
  } else {
    if (mPath && (mPath->mCurrentNodeIndex + 1U) >= mPath->mNodeCount) {
      if (Wm3::Vector3f::IsInvalid(mDestination) || IsAtPosition(mOwnerUnit, mDestination, 1.0f)) {
        Stop();
        return true;
      }

      doPathRefresh = true;
      allowContinuation = false;
    }
  }

  if (doPathRefresh) {
    UpdatePath(GetVal(), mDestination, allowContinuation);
    CheckCollisions();
  }

  if (mPausedForStateTransition == 0) {
    if (IsUnitState(mOwnerUnit, UNITSTATE_Immobile) || mOwnerUnit->StunnedState != 0) {
      mPausedForStateTransition = 1;
      Stop();
      return false;
    }
  } else if (!IsUnitState(mOwnerUnit, UNITSTATE_Immobile) && mOwnerUnit->StunnedState == 0) {
    if (IsUnitState(mOwnerUnit, UNITSTATE_Moving) || IsUnitState(mOwnerUnit, UNITSTATE_Patrolling) ||
        IsUnitState(mOwnerUnit, UNITSTATE_Attacking)) {
      UpdatePath(GetVal(), mDestination, true);
      CheckCollisions();
    }
    mPausedForStateTransition = 0;
  }

  if (mPausedForStateTransition == 0) {
    if (mCollisionInfo.mCollisionType == COLLISIONTYPE_5) {
      UpdatePath(4, mDestination, true);
    } else if (mCollisionInfo.mCollisionType == COLLISIONTYPE_1 && sim &&
               static_cast<std::int32_t>(sim->mCurTick) >= mCollisionInfo.mTickGate) {
      ResolvePossibleCollisionState(*this);

      switch (mCollisionInfo.mCollisionType) {
      case COLLISIONTYPE_None:
        if (!Wm3::Vector3f::IsInvalid(mDestination)) {
          if (!mPath || mPath->mCurrentNodeIndex >= mPath->mNodeCount) {
            UpdatePath(GetVal(), mDestination, true);
            MotionSetTarget(mUnitMotion, mDestination);
          }
          CheckCollisions();
        }
        break;
      case COLLISIONTYPE_2:
        MotionSetTarget(mUnitMotion, mCollisionAvoidTarget);
        UpdatePath(2, mCollisionAvoidTarget, true);
        mCollisionAvoidTarget = Wm3::Vector3f::Zero();
        break;
      case COLLISIONTYPE_3:
        NotifyNavigatorPathRefresh(mOwnerUnit);
        break;
      case COLLISIONTYPE_4:
      case COLLISIONTYPE_5:
        UpdatePath(4, mDestination, true);
        break;
      default:
        break;
      }
    }

    UpdateMotionPathPointers(*this);
  }

  return false;
}

/**
 * Address: 0x005D3000 (FUN_005D3000, Moho::CAiSteeringImpl::DriveToNextWaypoint)
 */
bool CAiSteeringImpl::DriveToNextWaypoint()
{
  const bool processResult = ProcessSplineMovement();
  const bool refreshPending = mNeedsWaypointRefresh != 0;

  if (!refreshPending) {
    if (processResult) {
      return true;
    }
    if (mPath) {
      return false;
    }
  }

  if (mCurrentWaypointIndex == mWaypointCount) {
    return true;
  }

  if (!refreshPending) {
    return processResult;
  }

  const Wm3::Vector3f currentPos = mOwnerUnit ? mOwnerUnit->GetPosition() : Wm3::Vector3f::Zero();
  mDestination = TrySnapPosToWaypoint(*this, mCurrentWaypointIndex, currentPos, 8.0f);
  mNeedsWaypointRefresh = 0;

  const Wm3::Vector3f waypoint = mWaypoints[mCurrentWaypointIndex];
  if (!IsAtPosition(mOwnerUnit, waypoint, 0.5f)) {
    MotionSetTarget(mUnitMotion, mDestination);
    UpdatePath(GetVal(), mDestination, true);
    CheckCollisions();
    return ProcessSplineMovement();
  }

  return true;
}

/**
 * Address: 0x005D3140 (FUN_005D3140, Moho::CAiSteeringImpl::FlyToNextWaypoint)
 */
bool CAiSteeringImpl::FlyToNextWaypoint()
{
  if (!mOwnerUnit) {
    return true;
  }

  const Wm3::Vector3f currentPos = mOwnerUnit->GetPosition();

  Wm3::Vector3f snapped = Wm3::Vector3f::Zero();
  if (mCurrentWaypointIndex < mWaypointCount) {
    snapped = TrySnapPosToWaypoint(*this, mCurrentWaypointIndex, currentPos, 10.0f);
  } else if (mWaypointCount > 0) {
    snapped = TrySnapPosToWaypoint(*this, mWaypointCount - 1, currentPos, 10.0f);
  } else {
    return true;
  }

  mDestination = snapped;
  MotionSetTarget(mUnitMotion, snapped, Wm3::Vector3f::Zero(), LAYER_None);

  const float airTolerance = ReadSteeringAirTolerance(mOwnerUnit->SimulationRef);
  const Wm3::Vector3f delta = snapped - currentPos;
  return Wm3::Vector3f::LengthSq(delta) <= (airTolerance * airTolerance);
}

/**
 * Address: 0x005D32B0 (FUN_005D32B0, Moho::CAiSteeringImpl::OnTick)
 */
int CAiSteeringImpl::Execute()
{
  Sim* const sim = (mOwnerUnit != nullptr) ? mOwnerUnit->SimulationRef : nullptr;
  if (sim && mOwnerUnit) {
    sim->Logf("0x%08x's steering tick.\n", static_cast<std::uint32_t>(mOwnerUnit->GetEntityId()));
  }

  const bool reached =
    (mMovementLayer == LAYER_Air || mMovementLayer == LAYER_Orbit) ? FlyToNextWaypoint() : DriveToNextWaypoint();

  if (reached && mCurrentWaypointIndex < mWaypointCount) {
    ++mCurrentWaypointIndex;
    mNeedsWaypointRefresh = 1;
  }

  if (ren_Steering != 0 && sim) {
    CDebugCanvas* const debugCanvas = sim->GetDebugCanvas();
    if (debugCanvas) {
      if (mOwnerUnit) {
        // Binary calls owner vslot +0x1C here (`Unit::GetBlueprint`) before draw passes.
        (void)mOwnerUnit->GetBlueprint();
      }
      DrawPathDebugOverlay(*this, *debugCanvas);
      DrawCollisionDebugOverlay(*this, *debugCanvas);
    }
  }

  return 1;
}

/**
 * Address: 0x005D3C30 (FUN_005D3C30,
 * ?AI_CreateSteering@Moho@@YAPAVIAiSteering@1@PAVUnit@1@PAVCUnitMotion@1@W4ELayer@1@@Z)
 */
IAiSteering* moho::AI_CreateSteering(Unit* const unit, CUnitMotion* const motion, const ELayer layer)
{
  return new CAiSteeringImpl(unit, motion, layer);
}

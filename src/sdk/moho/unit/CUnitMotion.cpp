#include "moho/unit/CUnitMotion.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>

#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  namespace
  {
    constexpr float kStopLookAheadDistance = 100.0f;
    constexpr float kAtTargetBaseTolerance = 0.25f;
    constexpr float kNonWingedSpeedScale = 0.25f;
    constexpr std::uint64_t kVerticalMotionStateMask =
      (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingDown)) |
      (1ull << static_cast<std::uint32_t>(UNITSTATE_MovingUp));

    [[nodiscard]] bool IsVector3fBinaryZero(const Wm3::Vector3f& value) noexcept
    {
      static constexpr Wm3::Vector3f kZeroVector{};
      return std::memcmp(&value, &kZeroVector, sizeof(Wm3::Vector3f)) == 0;
    }

    [[nodiscard]] bool HasQueuedHeadCommand(const CUnitCommandQueue* const commandQueue) noexcept
    {
      if (!commandQueue) {
        return false;
      }

      const WeakPtr<CUnitCommand>* const begin = commandQueue->mCommandVec.begin();
      const WeakPtr<CUnitCommand>* const end = commandQueue->mCommandVec.end();
      return begin != nullptr && begin != end && begin->HasValue();
    }
  } // namespace

  /**
   * Address: 0x006B8460 (FUN_006B8460)
   * Mangled: ?Stop@CUnitMotion@Moho@@QAEXPBV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Arms stop mode, optionally retargets to a hold position, and clears active
   * path waypoint pointers/state.
   */
  void CUnitMotion::Stop(const Wm3::Vector3f* const holdPosition)
  {
    Unit* const unit = mUnit;
    mStopRequested = 1;

    if (unit->mIsAir && !unit->IsUnitState(UNITSTATE_TransportUnloading) &&
        !unit->IsUnitState(UNITSTATE_TransportLoading) && !unit->IsUnitState(UNITSTATE_Ferrying)) {
      mLayer = LAYER_Air;
    }

    if (holdPosition) {
      mTargetPosition = *holdPosition;
    } else if (mAlwaysUseTopSpeed == 0u) {
      mTargetPosition = unit->GetPosition();
    } else {
      Wm3::Vector3f normalizedVelocity{};
      Wm3::Vector3f::NormalizeInto(mVelocity, &normalizedVelocity);
      mTargetPosition = unit->GetPosition() + (normalizedVelocity * kStopLookAheadDistance);
    }

    mStateWordB0 = 0;
    mNextWaypoint = nullptr;
    mFollowingWaypoint = nullptr;
  }

  /**
   * Address: 0x006B88F0 (FUN_006B88F0)
   * Mangled: ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@@Z
   *
   * What it does:
   * Sets target position with a zero steering vector and no forced layer.
   */
  void CUnitMotion::SetTarget(const Wm3::Vector3f& target)
  {
    const Wm3::Vector3f zeroSteeringVector{};
    SetTarget(target, zeroSteeringVector, LAYER_None);
  }

  /**
   * Address: 0x006B85E0 (FUN_006B85E0)
   * Mangled: ?SetTarget@CUnitMotion@Moho@@QAEXABV?$Vector3@M@Wm3@@0W4ELayer@2@@Z
   *
   * What it does:
   * Writes target/steering state, clamps target inside map bounds, clears
   * vertical transition unit-state bits for air blueprints, and resets local
   * reservation rect ownership.
   */
  void CUnitMotion::SetTarget(
    const Wm3::Vector3f& target,
    const Wm3::Vector3f& steeringVector,
    const ELayer layer
  )
  {
    mStopRequested = 0;
    mTargetPosition = target;

    Unit* const unit = mUnit;
    Sim* const sim = unit->SimulationRef;
    STIMap* const mapData = sim ? sim->mMapData : nullptr;

    std::int32_t minX = 0;
    std::int32_t minZ = 0;
    std::int32_t maxX = 0;
    std::int32_t maxZ = 0;
    if (unit->ArmyRef && unit->ArmyRef->UseWholeMap()) {
      const CHeightField* const heightField = mapData ? mapData->GetHeightField() : nullptr;
      maxX = heightField ? (heightField->width - 1) : 0;
      maxZ = heightField ? (heightField->height - 1) : 0;
    } else if (mapData) {
      minX = mapData->mPlayableRect.x0;
      minZ = mapData->mPlayableRect.z0;
      maxX = mapData->mPlayableRect.x1;
      maxZ = mapData->mPlayableRect.z1;
    }

    mTargetPosition.x = std::clamp(mTargetPosition.x, static_cast<float>(minX), static_cast<float>(maxX));
    mTargetPosition.z = std::clamp(mTargetPosition.z, static_cast<float>(minZ), static_cast<float>(maxZ));

    if (layer != LAYER_None) {
      mLayer = layer;
    }

    if (!HasQueuedHeadCommand(unit->CommandQueue) && sim) {
      mPreparationTick = static_cast<std::int32_t>(sim->mCurTick);
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (blueprint && blueprint->Air.CanFly != 0u) {
      unit->UnitStateMask &= ~kVerticalMotionStateMask;
    }

    Wm3::Vector3f normalizedSteeringVector = steeringVector;
    if (IsVector3fBinaryZero(normalizedSteeringVector) || Wm3::Vector3f::Normalize(&normalizedSteeringVector) == 0.0f) {
      if (blueprint && blueprint->Air.CanFly != 0u) {
        const Wm3::Vector3f currentPosition = unit->GetPosition();
        const float deltaX = target.x - currentPosition.x;
        const float deltaZ = target.z - currentPosition.z;
        const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));
        if (planarDistance > blueprint->Air.StartTurnDistance) {
          if (planarDistance == 0.0f) {
            const float maxFloat = std::numeric_limits<float>::max();
            mFormationVec.x = maxFloat;
            mFormationVec.y = maxFloat;
            mFormationVec.z = maxFloat;
          } else {
            const float inverseDistance = 1.0f / planarDistance;
            mFormationVec.x = deltaX * inverseDistance;
            mFormationVec.y = 0.0f;
            mFormationVec.z = deltaZ * inverseDistance;
          }
        }
      } else {
        mFormationVec = steeringVector;
      }
    } else {
      mFormationVec = normalizedSteeringVector;
    }

    if (unit->ReservedOgridRectMinX == mReservationMinX && unit->ReservedOgridRectMinZ == mReservationMinZ &&
        unit->ReservedOgridRectMaxX == mReservationMaxX && unit->ReservedOgridRectMaxZ == mReservationMaxZ) {
      unit->FreeOgridRect();
    }

    mReservationMinX = 0;
    mReservationMinZ = 0;
    mReservationMaxX = 0;
    mReservationMaxZ = 0;
  }

  /**
   * Address: 0x006B9730 (FUN_006B9730)
   * Mangled: ?AtTarget@CUnitMotion@Moho@@QBE_NXZ
   *
   * What it does:
   * Returns true when target-layer criteria and planar-distance tolerance checks
   * report that this motion already reached its target.
   */
  bool CUnitMotion::AtTarget() const
  {
    const Unit* const unit = mUnit;
    if (mLayer != LAYER_None && unit->mCurrentLayer != mLayer) {
      return false;
    }

    const Wm3::Vector3f currentPosition = unit->GetPosition();
    const float deltaX = mTargetPosition.x - currentPosition.x;
    const float deltaZ = mTargetPosition.z - currentPosition.z;
    const float planarDistance = std::sqrt((deltaX * deltaX) + (deltaZ * deltaZ));

    float targetTolerance = kAtTargetBaseTolerance;
    if (mAlwaysUseTopSpeed != 0u) {
      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (blueprint) {
        const float speedMult = unit->GetAttributes().moveSpeedMult;
        float speedTolerance = 0.0f;
        if (blueprint->Air.CanFly != 0u) {
          speedTolerance = blueprint->Air.MaxAirspeed * speedMult;
          if (blueprint->Air.Winged == 0u) {
            speedTolerance *= kNonWingedSpeedScale;
          }
        } else {
          speedTolerance = blueprint->Physics.MaxSpeed * speedMult;
          speedTolerance *= kNonWingedSpeedScale;
        }

        if (speedTolerance > kAtTargetBaseTolerance) {
          targetTolerance = speedTolerance;
        }
      }
    }

    if (targetTolerance < planarDistance) {
      if (mVertEvent != UMVE_Hover &&
          (mVertEvent != UMVE_Top || mHeight == std::numeric_limits<float>::infinity())) {
        return false;
      }
    }

    return true;
  }
} // namespace moho

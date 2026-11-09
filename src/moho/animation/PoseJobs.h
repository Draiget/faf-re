#pragma once

#include <cstdint>

#include "moho/render/camera/VTransform.h"

namespace moho
{
  class CAimManipulator;
  class CAniActor;
  class Unit;

  /**
   * Engine addition, not in the binary: sim_ParallelPose. A unit's per-tick pose update
   * (`CAniActor::UpdateManipulators`, from `Unit::MotionTick` in task stage A) runs on a sim worker
   * while the sim thread goes on with the next units, when every enabled manipulator of the unit
   * touches only its own pose and inputs copied at the moment the serial code would have run it.
   * Aim and builder arm manipulators qualify on ticks they have no target and start or stop no
   * tracking script (`IsPoseJobQuiet`). User-side like `sim_Workers`; matters only while
   * `sim_Workers > 0`.
   */
  extern bool sim_ParallelPose;

  /// One aim manipulator of a queued unit: its weapon target's type test, copied at queue time.
  struct SPoseJobAim
  {
    const CAimManipulator* mManipulator = nullptr;
    bool mTargetSet = false; // weapon->mTarget.targetType != AITARGET_None
  };

  /// Aim manipulators a queued unit may have; a unit with more updates on the sim thread.
  constexpr std::uint32_t kPoseJobMaxAims = 8;

  /**
   * What a queued pose update reads that other units can change later in task stage A, copied
   * when the update is queued. The manipulators read these instead of the live values while they
   * run inside that unit's job (`POSE_JobInputsFor`).
   */
  struct SPoseJobInputs
  {
    const Unit* mUnit = nullptr;
    Wm3::Quatf mTransformOrient{};    // GetTransform().orient_
    Wm3::Vec3f mVelocity{};           // GetVelocity()
    Wm3::Quatf mCurOrient{};          // mVarDat.mCurTransform.orient_
    Wm3::Quatf mLastOrient{};         // mVarDat.mLastTransform.orient_
    bool mBeingBuilt = false;         // IsBeingBuilt()
    bool mDead = false;               // IsDead()
    bool mStunned = false;            // mUnitVarDat.mStunTicks != 0
    bool mHasEconomy = false;         // ArmyRef and its economy exist
    double mMaxStorageEnergy = 0.0;   // economy.MaxStorageOf(ECON_ENERGY)
    double mMaxStorageMass = 0.0;     // economy.MaxStorageOf(ECON_MASS)
    float mStoredEnergy = 0.0f;       // economy.mStored.ENERGY
    float mStoredMass = 0.0f;         // economy.mStored.MASS
    std::uint32_t mAimCount = 0;
    SPoseJobAim mAims[kPoseJobMaxAims]{};
  };

  /// The copied inputs of `unit`'s pose job while the calling thread runs it; null otherwise.
  [[nodiscard]] const SPoseJobInputs* POSE_JobInputsFor(const Unit* unit) noexcept;

  /// The copied inputs of `aim` in the pose job the calling thread runs; null outside a job.
  [[nodiscard]] const SPoseJobAim* POSE_JobAimFor(const CAimManipulator* aim) noexcept;

  /// Whether the calling thread is running a pose job (where no Lua may be called).
  [[nodiscard]] bool POSE_InJob() noexcept;

  /**
   * `Unit::MotionTick`'s pose update: queues it on the sim workers when sim_ParallelPose allows it
   * for this unit, otherwise runs `AniActor->UpdateManipulators(mPendingTransform)` here.
   */
  void POSE_UpdateManipulators(Unit& unit);

  /**
   * Called by a sim-thread reader before it reads `actor`'s pose: finishes that actor's queued
   * update (runs it here if no worker took it yet). Nothing inside a pose job, on a worker or on
   * the sim thread: a job reading its own pose must not wait for itself.
   */
  void POSE_WaitFor(const CAniActor* actor);

  /// End of task stage A: finishes every queued pose update and releases the workers.
  void POSE_FinishStage();
} // namespace moho

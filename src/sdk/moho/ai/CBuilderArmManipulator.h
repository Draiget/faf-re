#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/animation/IAniManipulator.h"
#include "moho/misc/WeakPtr.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CAniPoseBone;
  class Unit;

  /**
   * Recovered builder-arm manipulator runtime state.
   *
   * Ownership evidence:
   * - `FUN_006359F0` sets reflected size to `0xB8`.
   * - `FUN_00635BB0`/`FUN_00635CA0` initialize lanes at `+0x80..+0xB0`.
   */
  class CBuilderArmManipulator : public IAniManipulator
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00635BB0 (FUN_00635BB0, ??0CBuilderArmManipulator@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes one builder-arm manipulator lane with default heading/pitch
     * tracking parameters and cleared weak-target state.
     */
    CBuilderArmManipulator();

    /**
     * Address: 0x00635FA0 (FUN_00635FA0, ??1CBuilderArmManipulator@Moho@@UAE@XZ)
     *
     * What it does:
     * Tears down builder-arm specific weak-target state, then runs
     * `IAniManipulator` base destruction.
     */
    ~CBuilderArmManipulator() override;

    /**
     * Address: 0x00636490 (FUN_00636490, Moho::CBuilderArmManipulator::SetAimingArc)
     *
     * What it does:
     * Updates heading/pitch arc-center, half-arc, and max-slew lanes from
     * one Lua-facing aiming-arc payload (radians).
     */
    void SetAimingArc(
      float minHeading,
      float maxHeading,
      float headingMaxSlew,
      float minPitch,
      float maxPitch,
      float pitchMaxSlew
    );

    /**
     * Address: 0x00636590 (FUN_00636590, Moho::CBuilderArmManipulator::MoveManipulator)
     *
     * What it does:
     * Advances builder-arm tracking from builder aim target, updates on-target
     * state in `IAiBuilder`, and toggles task-event signaled state.
     */
    bool ManipulatorUpdate() override;

  private:
    /**
     * Address: 0x00636220 (FUN_00636220, sub_636220)
     *
     * What it does:
     * Updates one heading/pitch tracking lane against one watched bone and
     * returns tracking-state bits (`outside-tolerance`, `heading-moving`).
     */
    std::uint8_t UpdateTrackingAxis(
      const Wm3::Vector3f& targetDirection,
      CAniPoseBone* watchBone,
      float angleCenter,
      float angleHalfArc,
      float maxSlew,
      std::uint8_t trackingModeFlags
    );

    /**
     * Address: 0x00635FE0 (FUN_00635FE0, sub_635FE0)
     *
     * What it does:
     * Runs heading/pitch track steps, rotates watched bones, triggers
     * builder-tracking script callbacks, and returns on-target state.
     */
    bool TrackAimDirection(const Wm3::Vector3f& targetDirection, std::uint8_t trackingModeFlags, bool reducedSlew);

    /**
     * Address: 0x006366F0 (FUN_006366F0, sub_6366F0)
     *
     * What it does:
     * Builds normalized direction from configured reference bone position to
     * builder aim target.
     */
    Wm3::Vector3f* ComputeDirectionToReferenceBone(Wm3::Vector3f* outDirection, const Wm3::Vector3f& targetPoint) const;

  public:
    WeakPtr<Unit> mGoalUnit;        // +0x80
    float mHeading;                 // +0x88
    float mPitch;                   // +0x8C
    std::int32_t mReferenceBoneIdx; // +0x90
    bool mTrackingScriptActive;     // +0x94
    std::uint8_t mPad95_97[0x03]{};
    float mHeadingCenter;   // +0x98
    float mHeadingHalfArc;  // +0x9C
    float mHeadingMaxSlew;  // +0xA0
    float mPitchCenter;     // +0xA4
    float mPitchHalfArc;    // +0xA8
    float mPitchMaxSlew;    // +0xAC
    bool mOnTarget;         // +0xB0
    std::uint8_t mPadB1_B7[0x07]{};
  };

  static_assert(offsetof(CBuilderArmManipulator, mGoalUnit) == 0x80, "CBuilderArmManipulator::mGoalUnit offset must be 0x80");
  static_assert(offsetof(CBuilderArmManipulator, mHeading) == 0x88, "CBuilderArmManipulator::mHeading offset must be 0x88");
  static_assert(offsetof(CBuilderArmManipulator, mPitch) == 0x8C, "CBuilderArmManipulator::mPitch offset must be 0x8C");
  static_assert(
    offsetof(CBuilderArmManipulator, mReferenceBoneIdx) == 0x90,
    "CBuilderArmManipulator::mReferenceBoneIdx offset must be 0x90"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mTrackingScriptActive) == 0x94,
    "CBuilderArmManipulator::mTrackingScriptActive offset must be 0x94"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mHeadingCenter) == 0x98,
    "CBuilderArmManipulator::mHeadingCenter offset must be 0x98"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mHeadingHalfArc) == 0x9C,
    "CBuilderArmManipulator::mHeadingHalfArc offset must be 0x9C"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mHeadingMaxSlew) == 0xA0,
    "CBuilderArmManipulator::mHeadingMaxSlew offset must be 0xA0"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mPitchCenter) == 0xA4,
    "CBuilderArmManipulator::mPitchCenter offset must be 0xA4"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mPitchHalfArc) == 0xA8,
    "CBuilderArmManipulator::mPitchHalfArc offset must be 0xA8"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mPitchMaxSlew) == 0xAC,
    "CBuilderArmManipulator::mPitchMaxSlew offset must be 0xAC"
  );
  static_assert(
    offsetof(CBuilderArmManipulator, mOnTarget) == 0xB0,
    "CBuilderArmManipulator::mOnTarget offset must be 0xB0"
  );
  static_assert(sizeof(CBuilderArmManipulator) == 0xB8, "CBuilderArmManipulator size must be 0xB8");
} // namespace moho

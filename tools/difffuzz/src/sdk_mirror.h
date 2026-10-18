#pragma once

// Mirrored engine functions whose home TUs cannot compile standalone (see
// sdk_mirror.cpp). State structs stand in for the owning class's lanes.

#include <cstdint>

#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"

namespace mirror
{
  struct AimFiringArc // moho::CAimFiringArc
  {
    float mMinHeading;
    float mMaxHeading;
    float mHeadingMaxSlew;
    float mMinPitch;
    float mMaxPitch;
    float mPitchMaxSlew;
  };

  struct AimArcLanes // CAimManipulator +0xC8..+0xDC
  {
    float mMinHeading;     // +0xC8 (centre)
    float mMaxHeading;     // +0xCC (half range)
    float mHeadingMaxSlew; // +0xD0
    float mMinPitch;       // +0xD4
    float mMaxPitch;       // +0xD8
    float mPitchMaxSlew;   // +0xDC
  };

  struct BuilderArmArcLanes // CBuilderArmManipulator +0x98..+0xAC
  {
    float mHeadingCenter;  // +0x98
    float mHeadingHalfArc; // +0x9C
    float mHeadingMaxSlew; // +0xA0
    float mPitchCenter;    // +0xA4
    float mPitchHalfArc;   // +0xA8
    float mPitchMaxSlew;   // +0xAC
  };

  struct TrackLanes
  {
    float mHeading;
    float mPitch;
    float mHeadingOffset; // CAimManipulator only
  };

  float COORDS_Pitch(const Wm3::Vector3f& velocity) noexcept;
  void AimSetFiringArc(AimArcLanes& self, AimFiringArc arc);
  void BuilderArmSetAimingArc(
    BuilderArmArcLanes& self, float minHeading, float maxHeading, float headingMaxSlew, float minPitch, float maxPitch,
    float pitchMaxSlew
  );
  std::uint8_t BuilderArmUpdateTrackingAxis(
    TrackLanes& self, const Wm3::Vector3f& targetDirection, float angleCenter, float angleHalfArc, float maxSlew,
    std::uint8_t trackingModeFlags
  );
  std::uint8_t AimCheckTracking(
    TrackLanes& self, const Wm3::Vector3f& targetDirection, float minAngleCenter, float maxAngleHalfRange,
    float maxAngleSlew, float tolerance, std::uint8_t trackingModeFlags
  );
  float WrapPositiveModulo(float value, float range) noexcept;
} // namespace mirror

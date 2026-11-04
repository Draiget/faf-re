#pragma once

// Mirrored engine functions whose home TUs cannot compile standalone (see
// sdk_mirror.cpp). State structs stand in for the owning class's lanes.

#include <cstdint>

#include "moho/math/QuaternionMath.h"
#include "moho/math/Vector3f.h"
#include "Wm3Box3.h"

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

  // Fourth wave: the standalone build's copies of engine functions in TUs it
  // does not compile. faf_math_dump calls the engine's own definitions instead
  // (DIFFFUZZ_ENGINE_LINKED in targets_math.cpp), except RATE_GameRateToSpeed
  // and ProjectBoxOntoAxis, which the engine keeps in anonymous namespaces.
  int RATE_GameRateToSpeed(float rate);
  float QuantizeEdgeCost(float a, float b);
  /// moho::COORDS_ToGridRect with the rectangle as x0, z0, x1, z1.
  void COORDS_ToGridRect(int* outRect, float centerX, float centerZ, int sizeX, int sizeZ);
  /// box: Center[3], Axis[3][3], Extent[3] (Wm3::Box3f's layout).
  void ProjectBoxOntoAxis(const float* box, const float* axis, float* outMin, float* outMax) noexcept;
  /// moho::VAxes3::VAxes3(quat) into vX, vY, vZ (9 floats).
  void VAxes3FromQuat(float* outAxes, const Wm3::Quaternionf& orientation);
  /// moho::VMatrix4::Set(quat, vec) into r[4] (16 floats).
  void VMatrix4Set(float* outRows, const Wm3::Quaternionf& quat, const Wm3::Vector3f& vec);
  /// moho::AxisAlignedBoundsFromBox with Wm3::ContAlignedBox inlined.
  void AxisAlignedBoundsFromBox(const Wm3::Box3f& box, float* outMin, float* outMax);

  // Sixth wave (faf_math_dump calls the engine's own definitions).
  /// moho::CHeightField::GetElevation on the field's data, width and height.
  float HeightFieldElevation(const std::uint16_t* data, int width, int height, float x, float z);
  /// moho::CRandomStream::FRand(lower, upper) on a CMersenneTwister's state and k.
  float RandomStreamFRand(std::uint32_t* state, std::uint32_t& k, float lower, float upper);
  /// moho::VTransform::Inverse with a transform as orient[4] (w, x, y, z), pos[3].
  void VTransformInverse(const float* transform, float* outTransform);
} // namespace mirror

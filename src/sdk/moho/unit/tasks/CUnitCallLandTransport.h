#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/render/camera/VTransform.h"
#include "moho/task/CCommandTask.h"

namespace moho
{
  class Unit;

  class CUnitCallLandTransport : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00600250 (FUN_00600250)
     *
     * What it does:
     * Initializes detached land-transport-call task state with identity
     * transforms and cleared weak-pointer/flag lanes.
     */
    CUnitCallLandTransport();

    /**
     * Address: 0x00603AB0 (FUN_00603AB0)
     *
     * What it does:
     * Loads base command-task state plus land-transport serialization fields.
     */
    static void
    MemberDeserialize(gpg::ReadArchive* archive, CUnitCallLandTransport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00603BC0 (FUN_00603BC0)
     *
     * What it does:
     * Saves base command-task state plus land-transport serialization fields.
     */
    static void
    MemberSerialize(gpg::WriteArchive* archive, const CUnitCallLandTransport* task, int version, gpg::RRef* ownerRef);

    int Execute() override;

  public:
    WeakPtr<Unit> mTargetTransportUnit; // 0x30
    float mBeamupTime;                  // 0x38
    VTransform mSourceTransform;        // 0x3C
    VTransform mDestinationTransform;   // 0x58
    bool mHasBeamupDestination;         // 0x74
    bool mIsOccupying;                  // 0x75
    std::uint8_t mPadding76[2];         // 0x76
  };

  static_assert(sizeof(CUnitCallLandTransport) == 0x78, "CUnitCallLandTransport size must be 0x78");
  static_assert(
    offsetof(CUnitCallLandTransport, mTargetTransportUnit) == 0x30,
    "CUnitCallLandTransport::mTargetTransportUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallLandTransport, mBeamupTime) == 0x38,
    "CUnitCallLandTransport::mBeamupTime offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitCallLandTransport, mSourceTransform) == 0x3C,
    "CUnitCallLandTransport::mSourceTransform offset must be 0x3C"
  );
  static_assert(
    offsetof(CUnitCallLandTransport, mDestinationTransform) == 0x58,
    "CUnitCallLandTransport::mDestinationTransform offset must be 0x58"
  );
  static_assert(
    offsetof(CUnitCallLandTransport, mHasBeamupDestination) == 0x74,
    "CUnitCallLandTransport::mHasBeamupDestination offset must be 0x74"
  );
  static_assert(
    offsetof(CUnitCallLandTransport, mIsOccupying) == 0x75,
    "CUnitCallLandTransport::mIsOccupying offset must be 0x75"
  );
} // namespace moho

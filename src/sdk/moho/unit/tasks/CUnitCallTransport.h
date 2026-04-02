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

  class CUnitCallTransport : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x005FF650 (FUN_005FF650)
     *
     * What it does:
     * Initializes detached transport-call task state with identity transforms
     * and cleared weak-pointer/flag lanes.
     */
    CUnitCallTransport();

    /**
     * Address: 0x00603890 (FUN_00603890)
     *
     * What it does:
     * Loads base command-task state, transport weak pointer, beamup flags, and
     * two transform lanes for one `CUnitCallTransport` object.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCallTransport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006039A0 (FUN_006039A0)
     *
     * What it does:
     * Saves base command-task state, transport weak pointer, beamup flags, and
     * two transform lanes for one `CUnitCallTransport` object.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, const CUnitCallTransport* task, int version, gpg::RRef* ownerRef);

    int Execute() override;

  public:
    WeakPtr<Unit> mTargetTransportUnit;  // 0x30
    bool mHasBeamupDestination;          // 0x38
    std::uint8_t mPadding39[3];          // 0x39
    float mBeamupTime;                   // 0x3C
    VTransform mSourceTransform;         // 0x40
    VTransform mDestinationTransform;    // 0x5C
    std::int32_t mArrivalTickOrSequence; // 0x78
  };

  static_assert(sizeof(CUnitCallTransport) == 0x7C, "CUnitCallTransport size must be 0x7C");
  static_assert(
    offsetof(CUnitCallTransport, mTargetTransportUnit) == 0x30,
    "CUnitCallTransport::mTargetTransportUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallTransport, mHasBeamupDestination) == 0x38,
    "CUnitCallTransport::mHasBeamupDestination offset must be 0x38"
  );
  static_assert(offsetof(CUnitCallTransport, mBeamupTime) == 0x3C, "CUnitCallTransport::mBeamupTime offset must be 0x3C");
  static_assert(
    offsetof(CUnitCallTransport, mSourceTransform) == 0x40,
    "CUnitCallTransport::mSourceTransform offset must be 0x40"
  );
  static_assert(
    offsetof(CUnitCallTransport, mDestinationTransform) == 0x5C,
    "CUnitCallTransport::mDestinationTransform offset must be 0x5C"
  );
  static_assert(
    offsetof(CUnitCallTransport, mArrivalTickOrSequence) == 0x78,
    "CUnitCallTransport::mArrivalTickOrSequence offset must be 0x78"
  );
} // namespace moho

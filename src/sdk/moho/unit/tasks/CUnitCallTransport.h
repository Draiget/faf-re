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
     * Address: 0x005FF6D0 (FUN_005FF6D0, Moho::CUnitCallTransport::CUnitCallTransport)
     *
     * What it does:
     * Initializes one transport-call task bound to `parentTask`, stores the
     * requested transport weak pointer, snapshots source/destination transform
     * lanes from transport position, and sets call-transport state flags.
     */
    CUnitCallTransport(CCommandTask* parentTask, Unit* transportUnit);

    /**
     * Address: 0x005FF7F0 (FUN_005FF7F0, Moho::CUnitCallTransport::~CUnitCallTransport)
     *
     * What it does:
     * Tears down transport-call state, clears owner-unit transport flags,
     * finalizes dispatch result, and unlinks the target transport weak pointer.
     */
    ~CUnitCallTransport() override;

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

    /**
     * Address: 0x005FFC70 (FUN_005FFC70, Moho::CUnitCallTransport::TaskTick)
     *
     * What it does:
     * Runs transport-call state transitions from pickup staging through beamup
     * interpolation and final transport attach handoff.
     */
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

  /**
   * Address: 0x005FFBB0 (FUN_005FFBB0, Moho::NewCallTransportCommand)
   *
   * What it does:
   * Validates one candidate transport unit and allocates a
   * `CUnitCallTransport` task for `parentTask`; emits a warning when the
   * candidate cannot serve as transport.
   */
  void NewCallTransportCommand(CCommandTask* parentTask, Unit* transportUnit);
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006031D0 (FUN_006031D0, gpg::RRef_CUnitCallTransport)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallTransport*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallTransport(gpg::RRef* outRef, moho::CUnitCallTransport* value);
} // namespace gpg

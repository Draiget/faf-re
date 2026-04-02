#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"

namespace moho
{
  class Unit;

  class CUnitCallTeleport : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x00603CD0 (FUN_00603CD0)
     *
     * What it does:
     * Loads base command-task state plus teleport-task weak-unit and status
     * flags from archive data.
     */
    static void MemberDeserialize(gpg::ReadArchive* archive, CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00603D60 (FUN_00603D60)
     *
     * What it does:
     * Saves base command-task state plus teleport-task weak-unit and status
     * flags into archive data.
     */
    static void MemberSerialize(gpg::WriteArchive* archive, const CUnitCallTeleport* task, int version, gpg::RRef* ownerRef);

    int Execute() override;

  public:
    WeakPtr<Unit> mTargetTransportUnit; // 0x30
    bool mCompletedSuccessfully;         // 0x38
    bool mIsOccupying;                  // 0x39
    std::uint8_t mPadding3A[2];         // 0x3A
  };

  static_assert(sizeof(CUnitCallTeleport) == 0x3C, "CUnitCallTeleport size must be 0x3C");
  static_assert(
    offsetof(CUnitCallTeleport, mTargetTransportUnit) == 0x30,
    "CUnitCallTeleport::mTargetTransportUnit offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mCompletedSuccessfully) == 0x38,
    "CUnitCallTeleport::mCompletedSuccessfully offset must be 0x38"
  );
  static_assert(
    offsetof(CUnitCallTeleport, mIsOccupying) == 0x39,
    "CUnitCallTeleport::mIsOccupying offset must be 0x39"
  );
} // namespace moho

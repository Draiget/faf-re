#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"
#include "moho/task/CCommandTask.h"

namespace moho
{
  class Unit;

  class CUnitCallAirStagingPlatform : public CCommandTask
  {
  public:
    static gpg::RType* sType;

    CUnitCallAirStagingPlatform() = default;

    /**
     * Address: 0x006018E0 (FUN_006018E0, ??0CUnitCallAirStagingPlatform@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes an air-staging-call task using parent dispatch context,
     * binds the platform weak-pointer lane, clears completion state, and sets
     * unit-state bits required by the call-lane.
     */
    CUnitCallAirStagingPlatform(CCommandTask* parentTask, Unit* platformUnit);

    /**
     * Address: 0x00603DF0 (FUN_00603DF0)
     *
     * What it does:
     * Loads base command-task state plus air-staging platform weak pointer and
     * completion flag from archive data.
     */
    static void
    MemberDeserialize(gpg::ReadArchive* archive, CUnitCallAirStagingPlatform* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00603E80 (FUN_00603E80)
     *
     * What it does:
     * Saves base command-task state plus air-staging platform weak pointer and
     * completion flag into archive data.
     */
    static void
    MemberSerialize(gpg::WriteArchive* archive, const CUnitCallAirStagingPlatform* task, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00601E00 (FUN_00601E00, Moho::CUnitCallAirStagingPlatform::TaskTick)
     *
     * What it does:
     * Runs the air-staging call state machine: validates unit/platform state,
     * steers to pickup/attach goals, and finalizes attach completion flags.
     */
    int Execute() override;

  public:
    WeakPtr<Unit> mPlatform;    // 0x30
    bool mDone;                 // 0x38
    std::uint8_t mPadding39[3]; // 0x39
  };

  static_assert(sizeof(CUnitCallAirStagingPlatform) == 0x3C, "CUnitCallAirStagingPlatform size must be 0x3C");
  static_assert(
    offsetof(CUnitCallAirStagingPlatform, mPlatform) == 0x30,
    "CUnitCallAirStagingPlatform::mPlatform offset must be 0x30"
  );
  static_assert(
    offsetof(CUnitCallAirStagingPlatform, mDone) == 0x38,
    "CUnitCallAirStagingPlatform::mDone offset must be 0x38"
  );
} // namespace moho

namespace gpg
{
  /**
   * Address: 0x006036E0 (FUN_006036E0, gpg::RRef_CUnitCallAirStagingPlatform)
   *
   * What it does:
   * Builds one typed reflection reference for `moho::CUnitCallAirStagingPlatform*`,
   * preserving dynamic-derived ownership and base-offset adjustment.
   */
  gpg::RRef* RRef_CUnitCallAirStagingPlatform(gpg::RRef* outRef, moho::CUnitCallAirStagingPlatform* value);
} // namespace gpg

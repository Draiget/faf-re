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

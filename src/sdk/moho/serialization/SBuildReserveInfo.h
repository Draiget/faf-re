#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class CUnitCommand;
  class Unit;

  /**
   * Address family:
   * - 0x00579990 (`SBuildReserveInfoTypeInfo::Init`, size = 0x10)
   * - 0x00581730 (`SBuildReserveInfo::MemberDeserialize`)
   * - 0x005817B0 (`SBuildReserveInfo::MemberSerialize`)
   *
   * What it is:
   * One reserved-build entry containing a weak unit lane and a weak command lane.
   */
  struct SBuildReserveInfo
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00581730 (FUN_00581730, Moho::SBuildReserveInfo::MemberDeserialize)
     *
     * What it does:
     * Loads weak `Unit` and weak `CUnitCommand` payload lanes from archive storage.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005817B0 (FUN_005817B0, Moho::SBuildReserveInfo::MemberSerialize)
     *
     * What it does:
     * Saves weak `Unit` and weak `CUnitCommand` payload lanes to archive storage.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    WeakPtr<Unit> mUnit;         // +0x00
    WeakPtr<CUnitCommand> mCom;  // +0x08
  };

  static_assert(sizeof(SBuildReserveInfo) == 0x10, "SBuildReserveInfo size must be 0x10");
  static_assert(offsetof(SBuildReserveInfo, mUnit) == 0x00, "SBuildReserveInfo::mUnit offset must be 0x00");
  static_assert(offsetof(SBuildReserveInfo, mCom) == 0x08, "SBuildReserveInfo::mCom offset must be 0x08");
} // namespace moho


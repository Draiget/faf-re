#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/serialization/SBuildReserveInfo.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E199D8
   * COL:  0x00E6E814
   */
  class SBuildReserveInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x005799C0 (FUN_005799C0, scalar deleting dtor lane)
     */
    ~SBuildReserveInfoTypeInfo() override;

    /**
     * Address: 0x005799B0 (FUN_005799B0, Moho::SBuildReserveInfoTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00579990 (FUN_00579990, Moho::SBuildReserveInfoTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SBuildReserveInfoTypeInfo) == 0x64, "SBuildReserveInfoTypeInfo size must be 0x64");

  /**
   * Address: 0x00579930 (FUN_00579930, preregister_SBuildReserveInfoTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `SBuildReserveInfoTypeInfo` storage and preregisters RTTI.
   */
  [[nodiscard]] gpg::RType* preregister_SBuildReserveInfoTypeInfo();

  /**
   * Address: 0x00BF61D0 (FUN_00BF61D0, cleanup_SBuildReserveInfoTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `SBuildReserveInfoTypeInfo` storage at process exit.
   */
  void cleanup_SBuildReserveInfoTypeInfo();

  /**
   * Address: 0x00BCB370 (FUN_00BCB370, register_SBuildReserveInfoTypeInfoStartup)
   *
   * What it does:
   * Runs preregistration for `SBuildReserveInfoTypeInfo` and installs exit cleanup.
   */
  int register_SBuildReserveInfoTypeInfoStartup();
} // namespace moho


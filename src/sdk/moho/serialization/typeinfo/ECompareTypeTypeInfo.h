#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/ECompareType.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E19964
   * COL:  0x00E6E8CC
   */
  class ECompareTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005798A0 (FUN_005798A0, scalar deleting dtor lane)
     */
    ~ECompareTypeTypeInfo() override;

    /**
     * Address: 0x00579890 (FUN_00579890, Moho::ECompareTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00579870 (FUN_00579870, Moho::ECompareTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x005798D0 (FUN_005798D0, Moho::ECompareTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ECompareTypeTypeInfo) == 0x78, "ECompareTypeTypeInfo size must be 0x78");

  /**
   * Address: 0x00579810 (FUN_00579810, preregister_ECompareTypeTypeInfo)
   *
   * What it does:
   * Constructs startup-owned `ECompareTypeTypeInfo` storage and preregisters RTTI.
   */
  [[nodiscard]] gpg::REnumType* preregister_ECompareTypeTypeInfo();

  /**
   * Address: 0x00BF61C0 (FUN_00BF61C0, cleanup_ECompareTypeTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `ECompareTypeTypeInfo` storage at process exit.
   */
  void cleanup_ECompareTypeTypeInfo();

  /**
   * Address: 0x00BCB350 (FUN_00BCB350, register_ECompareTypeTypeInfoStartup)
   *
   * What it does:
   * Runs preregistration for `ECompareTypeTypeInfo` and installs exit cleanup.
   */
  int register_ECompareTypeTypeInfoStartup();
} // namespace moho


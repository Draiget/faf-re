#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  /**
   * VFTABLE: 0x00D48CD0
   * COL: 0x00E5DAE4
   */
  class ArchiveTokenTypeInfo final : public gpg::REnumType
  {
  public:
    /**
       * Address: 0x00952AB0 (FUN_00952AB0)
     */
    ArchiveTokenTypeInfo();

    /**
     * Address: 0x00C0A210 (FUN_00C0A210, ArchiveTokenTypeInfo::~ArchiveTokenTypeInfo)
     */
    ~ArchiveTokenTypeInfo() override;

    /**
     * Address: 0x00952B10 (FUN_00952B10, ArchiveTokenTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00952B20 (FUN_00952B20, ArchiveTokenTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x0094E990 (FUN_0094E990, ArchiveTokenTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(ArchiveTokenTypeInfo) == 0x78, "ArchiveTokenTypeInfo size must be 0x78");

  /**
   * Address: 0x00C0A210 (FUN_00C0A210, ArchiveTokenTypeInfo::~ArchiveTokenTypeInfo)
   *
   * What it does:
   * Tears down startup-owned `ArchiveTokenTypeInfo` storage at process exit.
   */
  void cleanup_ArchiveTokenTypeInfo();

  /**
   * Address: 0x00BEAAB0 (FUN_00BEAAB0, register_ArchiveTokenTypeInfo)
   *
   * What it does:
   * Runs preregistration for `ArchiveTokenTypeInfo` and installs exit cleanup.
   */
  int register_ArchiveTokenTypeInfoStartup();
} // namespace gpg

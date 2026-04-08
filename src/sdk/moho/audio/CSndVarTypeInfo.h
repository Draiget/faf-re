#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CSndVarTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004E0170 (FUN_004E0170, Moho::CSndVarTypeInfo::CSndVarTypeInfo)
     *
     * What it does:
     * Constructs and preregisters `CSndVar` reflection type metadata.
     */
    CSndVarTypeInfo();

    /**
     * Address: 0x004E0200 (FUN_004E0200, Moho::CSndVarTypeInfo::dtr)
     */
    ~CSndVarTypeInfo() override;

    /**
     * Address: 0x004E01F0 (FUN_004E01F0, Moho::CSndVarTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004E01D0 (FUN_004E01D0, Moho::CSndVarTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BF0EA0 (FUN_00BF0EA0, cleanup_CSndVarTypeInfo)
   */
  void cleanup_CSndVarTypeInfo();

  /**
   * Address: 0x00BC6910 (FUN_00BC6910, register_CSndVarTypeInfo)
   */
  void register_CSndVarTypeInfo();

  static_assert(sizeof(CSndVarTypeInfo) == 0x64, "CSndVarTypeInfo size must be 0x64");
} // namespace moho

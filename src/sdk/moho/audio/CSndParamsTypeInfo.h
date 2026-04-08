#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CSndParamsTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004E0600 (FUN_004E0600)
     *
     * What it does:
     * Constructs and preregisters `CSndParams` reflection type metadata.
     */
    CSndParamsTypeInfo();

    /**
     * Address: 0x004E0690 (FUN_004E0690, Moho::CSndParamsTypeInfo::dtr)
     */
    ~CSndParamsTypeInfo() override;

    /**
     * Address: 0x004E0680 (FUN_004E0680, Moho::CSndParamsTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004E0660 (FUN_004E0660, Moho::CSndParamsTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BF0F60 (FUN_00BF0F60, cleanup_CSndParamsTypeInfo)
   */
  void cleanup_CSndParamsTypeInfo();

  /**
   * Address: 0x00BC69A0 (FUN_00BC69A0, register_CSndParamsTypeInfo)
   */
  void register_CSndParamsTypeInfo();

  static_assert(sizeof(CSndParamsTypeInfo) == 0x64, "CSndParamsTypeInfo size must be 0x64");
} // namespace moho

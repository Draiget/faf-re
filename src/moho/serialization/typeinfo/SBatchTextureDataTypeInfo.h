#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SBatchTextureData;

  /**
   * VFTABLE: 0x00E02AC4
   * COL: 0x00E5F9BC
   */
  class SBatchTextureDataTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00447BC0 (FUN_00447BC0, Moho::SBatchTextureDataTypeInfo::SBatchTextureDataTypeInfo)
     *
     * What it does:
     * Constructs and preregisters reflection metadata for `SBatchTextureData`.
     */
    SBatchTextureDataTypeInfo();

    /**
     * Address: 0x00447C50 (FUN_00447C50, Moho::SBatchTextureDataTypeInfo::dtr)
     */
    ~SBatchTextureDataTypeInfo() override;

    /**
     * Address: 0x00447C40 (FUN_00447C40, Moho::SBatchTextureDataTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00447C20 (FUN_00447C20, Moho::SBatchTextureDataTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SBatchTextureDataTypeInfo) == 0x64, "SBatchTextureDataTypeInfo size must be 0x64");

  /**
   * Address: 0x00BC4400 (FUN_00BC4400, register_SBatchTextureDataTypeInfo)
   *
   * What it does:
   * Forces `SBatchTextureData` reflection preregistration bootstrap.
   */
  void register_SBatchTextureDataTypeInfo();
} // namespace moho

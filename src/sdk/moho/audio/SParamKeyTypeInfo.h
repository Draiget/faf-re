#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SParamKeyTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004DEE90 (FUN_004DEE90)
     *
     * What it does:
     * Constructs and preregisters `SParamKey` reflection type metadata.
     */
    SParamKeyTypeInfo();

    /**
     * Address: 0x004DEF20 (FUN_004DEF20, Moho::SParamKeyTypeInfo::dtr)
     */
    ~SParamKeyTypeInfo() override;

    /**
     * Address: 0x004DEF10 (FUN_004DEF10, Moho::SParamKeyTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004DEEF0 (FUN_004DEEF0, Moho::SParamKeyTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BF0DF0 (FUN_00BF0DF0, cleanup_SParamKeyTypeInfo)
   */
  void cleanup_SParamKeyTypeInfo();

  /**
   * Address: 0x00BC6840 (FUN_00BC6840, register_SParamKeyTypeInfo)
   */
  int register_SParamKeyTypeInfo();

  static_assert(sizeof(SParamKeyTypeInfo) == 0x64, "SParamKeyTypeInfo size must be 0x64");
} // namespace moho
